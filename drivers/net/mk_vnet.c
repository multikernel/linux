// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * virtio-net backend for multikernel app-kernels. Each net entry in an
 * instance's device table becomes a host netdev peered with the spawn's
 * eth0 the way a veth pair is: host transmit writes into the spawn's RX
 * ring, the spawn's transmits arrive through NAPI.
 */
#include <linux/bpf.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/xdp.h>
#include <linux/virtio_net.h>
#include <linux/multikernel.h>
#include <linux/multikernel_vring.h>
#include <uapi/linux/multikernel_virtio.h>

#define MK_VNET_RXQ	0	/* the spawn's receive queue, host writes */
#define MK_VNET_TXQ	1	/* the spawn's transmit queue, host reads */
#define MK_VNET_HDR_LEN	sizeof(struct virtio_net_hdr_mrg_rxbuf)

/* Bytes of a received frame kept in the skb head; the rest goes to page frags */
#define MK_VNET_HEADLEN	256
/* Largest frame that fits one page frag with XDP headroom, and so can run XDP */
#define MK_VNET_FRAG_MAX (PAGE_SIZE - XDP_PACKET_HEADROOM - \
			  SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

/* The spawn's transmit offloads: what an XDP program on this netdev cannot take */
#define MK_VNET_TX_OFFLOADS (BIT_ULL(VIRTIO_NET_F_CSUM) |		\
			     BIT_ULL(VIRTIO_NET_F_HOST_TSO4) |		\
			     BIT_ULL(VIRTIO_NET_F_HOST_TSO6))

#define MK_VNET_FEATURES (BIT_ULL(VIRTIO_F_VERSION_1) |		\
			  BIT_ULL(VIRTIO_RING_F_INDIRECT_DESC) |	\
			  BIT_ULL(VIRTIO_RING_F_EVENT_IDX) |		\
			  BIT_ULL(VIRTIO_NET_F_MAC) |			\
			  BIT_ULL(VIRTIO_NET_F_MRG_RXBUF) |		\
			  BIT_ULL(VIRTIO_NET_F_GUEST_CSUM) |		\
			  BIT_ULL(VIRTIO_NET_F_GUEST_TSO4) |		\
			  BIT_ULL(VIRTIO_NET_F_GUEST_TSO6) |		\
			  MK_VNET_TX_OFFLOADS)

struct mk_vnet {
	struct net_device *ndev;
	struct mk_virtio_hdev *hdev;
	struct napi_struct napi;
	struct mk_vring rx;		/* MK_VNET_RXQ: host writes */
	struct mk_vring tx;		/* MK_VNET_TXQ: host reads */
	spinlock_t rx_lock;		/* host transmit into the spawn's RX ring */
	u32 max_frame;			/* longest frame the spawn may transmit */
	struct bpf_prog __rcu *xdp_prog;
	struct xdp_rxq_info xdp_rxq;
};

static u64 mk_vnet_negotiated(struct mk_vnet *vn)
{
	return READ_ONCE(vn->hdev->entry->driver_features);
}

typedef void (*mk_vnet_copy_t)(void *ctx, u32 off, void *dst, u32 len);

static void mk_vnet_copy_skb(void *ctx, u32 off, void *dst, u32 len)
{
	skb_copy_bits(ctx, off, dst, len);
}

static void mk_vnet_copy_buf(void *ctx, u32 off, void *dst, u32 len)
{
	memcpy(dst, ctx + off, len);
}

static u32 mk_vnet_fill(const struct mk_vring_chain *c, u32 off, void *ctx,
			u32 done, u32 len, mk_vnet_copy_t copy)
{
	u32 i, start = done;

	for (i = c->nread; i < c->nsegs && done < len; i++) {
		const struct mk_vring_seg *s = &c->segs[i];
		u32 n;

		if (off >= s->len) {
			off -= s->len;
			continue;
		}
		n = min(s->len - off, len - done);
		copy(ctx, done, s->va + off, n);
		done += n;
		off = 0;
	}
	return done - start;
}

/*
 * Write one frame into the buffers the driver posted, as many as it
 * takes: mergeable receive buffers. The caller holds rx_lock. -ENOSPC
 * leaves the ring as it was so the frame can be retried after a refill.
 */
static int mk_vnet_push(struct mk_vnet *vn, const struct virtio_net_hdr *h,
			void *ctx, u32 len, mk_vnet_copy_t copy)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr = NULL;
	struct mk_vring_chain c;
	u32 done = 0, nbufs = 0;
	int ret;

	do {
		u32 off = 0, n;

		ret = mk_vring_next(&vn->rx, &c);
		if (ret <= 0) {
			ret = ret ? ret : -ENOSPC;
			goto unget;
		}
		nbufs++;
		if (!hdr) {
			if (c.nread == c.nsegs || c.segs[c.nread].len < MK_VNET_HDR_LEN) {
				mk_vring_add_used(&vn->rx, c.head, 0);
				ret = -EINVAL;
				goto unget;
			}
			hdr = c.segs[c.nread].va;
			hdr->hdr = *h;
			off = MK_VNET_HDR_LEN;
		}
		n = mk_vnet_fill(&c, off, ctx, done, len, copy);
		mk_vring_add_used(&vn->rx, c.head, off + n);
		/* A buffer that holds nothing would loop forever on a driver's bad chain */
		if (!n && done < len && off != MK_VNET_HDR_LEN) {
			ret = -EINVAL;
			goto unget;
		}
		done += n;
	} while (done < len);

	hdr->num_buffers = cpu_to_le16(nbufs);
	return 0;
unget:
	mk_vring_unget(&vn->rx, nbufs);
	return ret;
}

static void mk_vnet_rx_done(struct mk_vnet *vn)
{
	mk_vring_publish_used(&vn->rx);
	if (mk_vring_need_call(&vn->rx))
		mk_virtio_hdev_call(vn->hdev, MK_VNET_RXQ);
}

static netdev_tx_t mk_vnet_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct mk_vnet *vn = netdev_priv(ndev);
	struct virtio_net_hdr hdr;
	int ret;

	if (virtio_net_hdr_from_skb(skb, &hdr, true, false, 0))
		goto drop;

	spin_lock(&vn->rx_lock);
	ret = mk_vnet_push(vn, &hdr, skb, skb->len, mk_vnet_copy_skb);
	if (ret == -ENOSPC) {
		/* Out of buffers: wait for the driver's refill kick, unless it beat us */
		netif_stop_queue(ndev);
		if (!mk_vring_enable_kick(&vn->rx)) {
			spin_unlock(&vn->rx_lock);
			return NETDEV_TX_BUSY;
		}
		netif_start_queue(ndev);
		ret = mk_vnet_push(vn, &hdr, skb, skb->len, mk_vnet_copy_skb);
	}
	mk_vnet_rx_done(vn);
	spin_unlock(&vn->rx_lock);
	if (ret)
		goto drop;

	dev_sw_netstats_tx_add(ndev, 1, skb->len);
	dev_consume_skb_any(skb);
	return NETDEV_TX_OK;
drop:
	ndev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/* Frames redirected here by an XDP program on another device, no skb involved */
static int mk_vnet_xdp_xmit(struct net_device *ndev, int n, struct xdp_frame **frames,
			    u32 flags)
{
	struct mk_vnet *vn = netdev_priv(ndev);
	struct virtio_net_hdr hdr = {};
	int i, sent = 0;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;
	if (!netif_carrier_ok(ndev))
		return -ENETDOWN;

	spin_lock(&vn->rx_lock);
	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];

		if (xdp_frame_has_frags(xdpf))
			break;
		if (mk_vnet_push(vn, &hdr, xdpf->data, xdpf->len, mk_vnet_copy_buf))
			break;
		dev_sw_netstats_tx_add(ndev, 1, xdpf->len);
		xdp_return_frame_rx_napi(xdpf);
		sent++;
	}
	mk_vnet_rx_done(vn);
	spin_unlock(&vn->rx_lock);
	return sent;
}

static void mk_vnet_receive(struct mk_vnet *vn, struct sk_buff *skb,
			    const struct virtio_net_hdr *hdr)
{
	skb->protocol = eth_type_trans(skb, vn->ndev);
	if (virtio_net_hdr_to_skb(skb, hdr, true)) {
		vn->ndev->stats.rx_frame_errors++;
		kfree_skb(skb);
		return;
	}
	napi_gro_receive(&vn->napi, skb);
}

/* A frame too long for one page frag: headers in the skb head, payload in pages */
static struct sk_buff *mk_vnet_pull_skb(struct mk_vnet *vn, const struct mk_vring_chain *c,
					u32 len)
{
	u32 headlen = min(len, MK_VNET_HEADLEN);
	u32 off = MK_VNET_HDR_LEN + headlen, done = headlen;
	struct sk_buff *skb;

	if (DIV_ROUND_UP(len - headlen, PAGE_SIZE) > MAX_SKB_FRAGS)
		return NULL;
	skb = napi_alloc_skb(&vn->napi, headlen);
	if (!skb)
		return NULL;
	mk_vring_copy_from(c, MK_VNET_HDR_LEN, skb_put(skb, headlen), headlen);

	while (done < len) {
		u32 n = min(len - done, (u32)PAGE_SIZE);
		void *buf = napi_alloc_frag(n);

		if (!buf) {
			kfree_skb(skb);
			return NULL;
		}
		mk_vring_copy_from(c, off, buf, n);
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, virt_to_head_page(buf),
				buf - page_address(virt_to_head_page(buf)), n, n);
		off += n;
		done += n;
	}
	return skb;
}

/*
 * One frame from the spawn's TX ring, as a page fragment with XDP headroom
 * so an attached program can redirect it without a copy. Returns the
 * fragment or NULL with the descriptor already completed.
 */
static void *mk_vnet_pull_frag(struct mk_vnet *vn, const struct mk_vring_chain *c,
			       u32 len, size_t *truesizep)
{
	size_t truesize = SKB_DATA_ALIGN(XDP_PACKET_HEADROOM + len) +
			  SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	void *buf = napi_alloc_frag(truesize);

	if (!buf)
		return NULL;
	mk_vring_copy_from(c, MK_VNET_HDR_LEN, buf + XDP_PACKET_HEADROOM, len);
	*truesizep = truesize;
	return buf;
}

static bool mk_vnet_poll_one(struct mk_vnet *vn, struct bpf_prog *prog,
			     const struct mk_vring_chain *c, bool *redirected)
{
	struct net_device *ndev = vn->ndev;
	struct virtio_net_hdr_mrg_rxbuf hdr;
	struct sk_buff *skb;
	struct xdp_buff xdp;
	size_t truesize;
	void *buf;
	u32 len, act;

	if (c->len < MK_VNET_HDR_LEN + ETH_HLEN || c->len > MK_VNET_HDR_LEN + vn->max_frame) {
		ndev->stats.rx_length_errors++;
		return false;
	}
	len = c->len - MK_VNET_HDR_LEN;
	mk_vring_copy_from(c, 0, &hdr, MK_VNET_HDR_LEN);
	dev_sw_netstats_rx_add(ndev, len);

	if (len > MK_VNET_FRAG_MAX) {
		skb = mk_vnet_pull_skb(vn, c, len);
		if (!skb)
			goto dropped;
		mk_vnet_receive(vn, skb, &hdr.hdr);
		return true;
	}

	buf = mk_vnet_pull_frag(vn, c, len, &truesize);
	if (!buf)
		goto dropped;
	xdp_init_buff(&xdp, truesize, &vn->xdp_rxq);
	xdp_prepare_buff(&xdp, buf, XDP_PACKET_HEADROOM, len, false);
	act = prog ? bpf_prog_run_xdp(prog, &xdp) : XDP_PASS;
	switch (act) {
	case XDP_PASS:
		skb = napi_build_skb(buf, truesize);
		if (!skb) {
			skb_free_frag(buf);
			goto dropped;
		}
		skb_reserve(skb, xdp.data - buf);
		skb_put(skb, xdp.data_end - xdp.data);
		mk_vnet_receive(vn, skb, &hdr.hdr);
		return true;
	case XDP_REDIRECT:
		if (xdp_do_redirect(ndev, &xdp, prog)) {
			skb_free_frag(buf);
			goto dropped;
		}
		*redirected = true;
		return true;
	default:
		bpf_warn_invalid_xdp_action(ndev, prog, act);
		fallthrough;
	case XDP_ABORTED:
	case XDP_TX:
	case XDP_DROP:
		skb_free_frag(buf);
		goto dropped;
	}
dropped:
	ndev->stats.rx_dropped++;
	return true;
}

static int mk_vnet_poll(struct napi_struct *napi, int budget)
{
	struct mk_vnet *vn = container_of(napi, struct mk_vnet, napi);
	struct bpf_prog *prog;
	bool redirected = false;
	int done = 0;

	rcu_read_lock();
	prog = rcu_dereference(vn->xdp_prog);
	while (done < budget) {
		struct mk_vring_chain c;

		if (mk_vring_next(&vn->tx, &c) <= 0)
			break;
		mk_vring_add_used(&vn->tx, c.head, 0);
		if (mk_vnet_poll_one(vn, prog, &c, &redirected))
			done++;
	}
	rcu_read_unlock();
	if (redirected)
		xdp_do_flush();

	mk_vring_publish_used(&vn->tx);
	if (mk_vring_need_call(&vn->tx))
		mk_virtio_hdev_call(vn->hdev, MK_VNET_TXQ);

	if (done < budget && napi_complete_done(napi, done)) {
		if (mk_vring_enable_kick(&vn->tx))
			napi_schedule(napi);
	}
	return done;
}

/*
 * A program sees raw frames, so the spawn must not hand us partial
 * checksums or TSO. Like virtio_net, withdraw those offloads while a
 * program is attached; a spawn that already negotiated them keeps them
 * until it reboots.
 */
static int mk_vnet_bpf(struct net_device *ndev, struct netdev_bpf *bpf)
{
	struct mk_vnet *vn = netdev_priv(ndev);
	struct mk_virtio_entry *e = vn->hdev->entry;
	struct bpf_prog *old;

	if (bpf->command != XDP_SETUP_PROG)
		return -EINVAL;
	if (bpf->prog && READ_ONCE(vn->hdev->started) &&
	    (mk_vnet_negotiated(vn) & MK_VNET_TX_OFFLOADS)) {
		NL_SET_ERR_MSG_MOD(bpf->extack,
				   "app-kernel negotiated transmit offloads; attach before it boots");
		return -EBUSY;
	}
	WRITE_ONCE(e->device_features,
		   bpf->prog ? MK_VNET_FEATURES & ~MK_VNET_TX_OFFLOADS : MK_VNET_FEATURES);

	old = rcu_replace_pointer(vn->xdp_prog, bpf->prog, lockdep_rtnl_is_held());
	if (old) {
		synchronize_net();
		bpf_prog_put(old);
	}
	return 0;
}

/* The host stack may only hand us what the spawn agreed to receive */
static netdev_features_t mk_vnet_fix_features(struct net_device *ndev,
					      netdev_features_t features)
{
	u64 negotiated = mk_vnet_negotiated(netdev_priv(ndev));

	if (!(negotiated & BIT_ULL(VIRTIO_NET_F_GUEST_CSUM)))
		features &= ~NETIF_F_HW_CSUM;
	if (!(negotiated & BIT_ULL(VIRTIO_NET_F_GUEST_TSO4)))
		features &= ~NETIF_F_TSO;
	if (!(negotiated & BIT_ULL(VIRTIO_NET_F_GUEST_TSO6)))
		features &= ~NETIF_F_TSO6;
	return features;
}

static const struct net_device_ops mk_vnet_ops = {
	.ndo_start_xmit = mk_vnet_xmit,
	.ndo_get_stats64 = dev_get_tstats64,
	.ndo_fix_features = mk_vnet_fix_features,
	.ndo_bpf = mk_vnet_bpf,
	.ndo_xdp_xmit = mk_vnet_xdp_xmit,
};

static int mk_vnet_bind(struct mk_virtio_hdev *hdev)
{
	struct net_device *ndev;
	struct mk_vnet *vn;
	int ret;

	ndev = alloc_etherdev(sizeof(*vn));
	if (!ndev)
		return -ENOMEM;

	snprintf(ndev->name, IFNAMSIZ, "mk-%.9s-%u", hdev->instance->name, hdev->index);
	ndev->netdev_ops = &mk_vnet_ops;
	ndev->max_mtu = ETH_DATA_LEN;
	ndev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	ndev->hw_features = NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_TSO | NETIF_F_TSO6;
	ndev->features = ndev->hw_features;
	eth_hw_addr_random(ndev);
	memcpy(hdev->entry->config, ndev->dev_addr, ETH_ALEN);

	vn = netdev_priv(ndev);
	vn->ndev = ndev;
	vn->hdev = hdev;
	spin_lock_init(&vn->rx_lock);
	netif_napi_add(ndev, &vn->napi, mk_vnet_poll);
	netif_carrier_off(ndev);
	xdp_set_features_flag(ndev, NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_REDIRECT |
				    NETDEV_XDP_ACT_NDO_XMIT);

	ret = xdp_rxq_info_reg(&vn->xdp_rxq, ndev, 0, vn->napi.napi_id);
	if (!ret)
		ret = xdp_rxq_info_reg_mem_model(&vn->xdp_rxq, MEM_TYPE_PAGE_SHARED, NULL);
	if (!ret)
		ret = register_netdev(ndev);
	if (ret) {
		xdp_rxq_info_unreg(&vn->xdp_rxq);
		free_netdev(ndev);
		return ret;
	}
	hdev->priv = vn;
	netdev_info(ndev, "serving instance %d (%s)\n", hdev->instance->id,
		    hdev->instance->name);
	return 0;
}

static void mk_vnet_unbind(struct mk_virtio_hdev *hdev)
{
	struct mk_vnet *vn = hdev->priv;

	unregister_netdev(vn->ndev);
	xdp_rxq_info_unreg(&vn->xdp_rxq);
	free_netdev(vn->ndev);
	hdev->priv = NULL;
}

static int mk_vnet_start(struct mk_virtio_hdev *hdev)
{
	struct mk_vnet *vn = hdev->priv;
	int ret;

	ret = mk_vring_init(&vn->rx, hdev, MK_VNET_RXQ);
	if (ret)
		return ret;
	ret = mk_vring_init(&vn->tx, hdev, MK_VNET_TXQ);
	if (ret) {
		mk_vring_cleanup(&vn->rx);
		return ret;
	}

	vn->max_frame = mk_vnet_negotiated(vn) & (BIT_ULL(VIRTIO_NET_F_HOST_TSO4) |
						  BIT_ULL(VIRTIO_NET_F_HOST_TSO6)) ?
			GSO_LEGACY_MAX_SIZE + ETH_HLEN : ETH_FRAME_LEN;
	rtnl_lock();
	netdev_update_features(vn->ndev);
	rtnl_unlock();
	napi_enable(&vn->napi);
	netif_carrier_on(vn->ndev);
	netif_wake_queue(vn->ndev);
	/* Level-triggered: the driver may have queued before we started */
	napi_schedule(&vn->napi);
	return 0;
}

static void mk_vnet_stop(struct mk_virtio_hdev *hdev)
{
	struct mk_vnet *vn = hdev->priv;

	netif_carrier_off(vn->ndev);
	netif_stop_queue(vn->ndev);
	napi_disable(&vn->napi);
	spin_lock_bh(&vn->rx_lock);
	mk_vring_cleanup(&vn->rx);
	spin_unlock_bh(&vn->rx_lock);
	mk_vring_cleanup(&vn->tx);
}

/* Hardirq */
static void mk_vnet_kick(struct mk_virtio_hdev *hdev, unsigned int queue)
{
	struct mk_vnet *vn = hdev->priv;

	if (queue == MK_VNET_TXQ)
		napi_schedule(&vn->napi);
	else
		netif_wake_queue(vn->ndev);
}

static struct mk_virtio_backend mk_vnet_backend = {
	.device_id = VIRTIO_ID_NET,
	.name = "mk_vnet",
	.features = MK_VNET_FEATURES,
	.bind = mk_vnet_bind,
	.unbind = mk_vnet_unbind,
	.start = mk_vnet_start,
	.stop = mk_vnet_stop,
	.kick = mk_vnet_kick,
};

static int __init mk_vnet_init(void)
{
	return mk_virtio_register_backend(&mk_vnet_backend);
}
module_init(mk_vnet_init);

static void __exit mk_vnet_exit(void)
{
	mk_virtio_unregister_backend(&mk_vnet_backend);
}
module_exit(mk_vnet_exit);

MODULE_DESCRIPTION("virtio-net backend for multikernel app-kernels");
MODULE_LICENSE("GPL");

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

#define MK_VNET_FEATURES (BIT_ULL(VIRTIO_F_VERSION_1) |		\
			  BIT_ULL(VIRTIO_RING_F_INDIRECT_DESC) |	\
			  BIT_ULL(VIRTIO_RING_F_EVENT_IDX) |		\
			  BIT_ULL(VIRTIO_NET_F_MAC) |			\
			  BIT_ULL(VIRTIO_NET_F_MRG_RXBUF))

struct mk_vnet {
	struct net_device *ndev;
	struct mk_virtio_hdev *hdev;
	struct napi_struct napi;
	struct mk_vring rx;		/* MK_VNET_RXQ: host writes */
	struct mk_vring tx;		/* MK_VNET_TXQ: host reads */
	spinlock_t rx_lock;		/* host transmit into the spawn's RX ring */
	struct bpf_prog __rcu *xdp_prog;
	struct xdp_rxq_info xdp_rxq;
};

/*
 * Write one frame into the buffer the driver posted as @c. The caller
 * holds rx_lock and has taken the chain.
 */
static int mk_vnet_push(struct mk_vnet *vn, struct mk_vring_chain *c,
			const void *data, size_t len)
{
	struct virtio_net_hdr_mrg_rxbuf hdr = { .num_buffers = cpu_to_le16(1) };

	if (mk_vring_chain_writable(c) < MK_VNET_HDR_LEN + len) {
		mk_vring_add_used(&vn->rx, c->head, 0);
		return -EMSGSIZE;
	}
	mk_vring_copy_to(c, 0, &hdr, MK_VNET_HDR_LEN);
	mk_vring_copy_to(c, MK_VNET_HDR_LEN, data, len);
	mk_vring_add_used(&vn->rx, c->head, MK_VNET_HDR_LEN + len);
	return 0;
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
	struct mk_vring_chain c;
	int ret;

	if (skb_linearize(skb))
		goto drop;

	spin_lock(&vn->rx_lock);
	ret = mk_vring_next(&vn->rx, &c);
	if (!ret) {
		/* Ring empty: wait for the driver's refill kick, unless it beat us */
		netif_stop_queue(ndev);
		if (!mk_vring_enable_kick(&vn->rx)) {
			spin_unlock(&vn->rx_lock);
			return NETDEV_TX_BUSY;
		}
		netif_start_queue(ndev);
		ret = mk_vring_next(&vn->rx, &c);
	}
	if (ret <= 0 || mk_vnet_push(vn, &c, skb->data, skb->len)) {
		mk_vnet_rx_done(vn);
		spin_unlock(&vn->rx_lock);
		goto drop;
	}
	mk_vnet_rx_done(vn);
	spin_unlock(&vn->rx_lock);

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
	int i, sent = 0;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;
	if (!netif_carrier_ok(ndev))
		return -ENETDOWN;

	spin_lock(&vn->rx_lock);
	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];
		struct mk_vring_chain c;

		if (xdp_frame_has_frags(xdpf))
			break;
		if (mk_vring_next(&vn->rx, &c) <= 0)
			break;
		if (mk_vnet_push(vn, &c, xdpf->data, xdpf->len))
			break;
		dev_sw_netstats_tx_add(ndev, 1, xdpf->len);
		xdp_return_frame_rx_napi(xdpf);
		sent++;
	}
	mk_vnet_rx_done(vn);
	spin_unlock(&vn->rx_lock);
	return sent;
}

/*
 * One frame from the spawn's TX ring, as a page fragment with XDP headroom
 * so an attached program can redirect it without a copy. Returns the
 * fragment or NULL with the descriptor already completed.
 */
static void *mk_vnet_pull(struct mk_vnet *vn, struct mk_vring_chain *c,
			  size_t *lenp, size_t *truesizep)
{
	size_t len = c->len;
	size_t truesize;
	void *buf;

	mk_vring_add_used(&vn->tx, c->head, 0);
	if (len < MK_VNET_HDR_LEN + ETH_HLEN) {
		vn->ndev->stats.rx_length_errors++;
		return NULL;
	}
	len -= MK_VNET_HDR_LEN;
	truesize = SKB_DATA_ALIGN(XDP_PACKET_HEADROOM + len) +
		   SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	buf = napi_alloc_frag(truesize);
	if (!buf) {
		vn->ndev->stats.rx_dropped++;
		return NULL;
	}
	mk_vring_copy_from(c, MK_VNET_HDR_LEN, buf + XDP_PACKET_HEADROOM, len);
	*lenp = len;
	*truesizep = truesize;
	return buf;
}

static int mk_vnet_poll(struct napi_struct *napi, int budget)
{
	struct mk_vnet *vn = container_of(napi, struct mk_vnet, napi);
	struct net_device *ndev = vn->ndev;
	struct bpf_prog *prog;
	bool redirected = false;
	int done = 0;

	rcu_read_lock();
	prog = rcu_dereference(vn->xdp_prog);
	while (done < budget) {
		struct mk_vring_chain c;
		struct sk_buff *skb;
		struct xdp_buff xdp;
		size_t len, truesize;
		void *buf;
		u32 act;

		if (mk_vring_next(&vn->tx, &c) <= 0)
			break;
		buf = mk_vnet_pull(vn, &c, &len, &truesize);
		if (!buf)
			continue;
		dev_sw_netstats_rx_add(ndev, len);
		done++;

		xdp_init_buff(&xdp, truesize, &vn->xdp_rxq);
		xdp_prepare_buff(&xdp, buf, XDP_PACKET_HEADROOM, len, false);
		act = prog ? bpf_prog_run_xdp(prog, &xdp) : XDP_PASS;
		switch (act) {
		case XDP_PASS:
			skb = napi_build_skb(buf, truesize);
			if (!skb) {
				ndev->stats.rx_dropped++;
				skb_free_frag(buf);
				break;
			}
			skb_reserve(skb, xdp.data - buf);
			skb_put(skb, xdp.data_end - xdp.data);
			skb->protocol = eth_type_trans(skb, ndev);
			napi_gro_receive(napi, skb);
			break;
		case XDP_REDIRECT:
			if (xdp_do_redirect(ndev, &xdp, prog)) {
				ndev->stats.rx_dropped++;
				skb_free_frag(buf);
			} else {
				redirected = true;
			}
			break;
		default:
			bpf_warn_invalid_xdp_action(ndev, prog, act);
			fallthrough;
		case XDP_ABORTED:
		case XDP_TX:
		case XDP_DROP:
			ndev->stats.rx_dropped++;
			skb_free_frag(buf);
			break;
		}
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

static int mk_vnet_bpf(struct net_device *ndev, struct netdev_bpf *bpf)
{
	struct mk_vnet *vn = netdev_priv(ndev);
	struct bpf_prog *old;

	if (bpf->command != XDP_SETUP_PROG)
		return -EINVAL;
	old = rcu_replace_pointer(vn->xdp_prog, bpf->prog, lockdep_rtnl_is_held());
	if (old) {
		synchronize_net();
		bpf_prog_put(old);
	}
	return 0;
}

static const struct net_device_ops mk_vnet_ops = {
	.ndo_start_xmit = mk_vnet_xmit,
	.ndo_get_stats64 = dev_get_tstats64,
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

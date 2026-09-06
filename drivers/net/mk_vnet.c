// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * virtio-net backend for multikernel app-kernels. Each net entry in an
 * instance's device table becomes a host netdev peered with the spawn's
 * eth0 the way a veth pair is: host transmit writes into the spawn's RX
 * ring, the spawn's transmits arrive through NAPI.
 */
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/vhost_iotlb.h>
#include <linux/virtio_net.h>
#include <linux/virtio_ring.h>
#include <linux/vringh.h>
#include <linux/multikernel.h>
#include <uapi/linux/multikernel_virtio.h>

#define MK_VNET_RXQ	0	/* the spawn's receive queue, host writes */
#define MK_VNET_TXQ	1	/* the spawn's transmit queue, host reads */
#define MK_VNET_HDR_LEN	sizeof(struct virtio_net_hdr_mrg_rxbuf)

#define MK_VNET_FEATURES (BIT_ULL(VIRTIO_F_VERSION_1) |		\
			  BIT_ULL(VIRTIO_RING_F_INDIRECT_DESC) |	\
			  BIT_ULL(VIRTIO_RING_F_EVENT_IDX) |		\
			  BIT_ULL(VIRTIO_NET_F_MAC) |			\
			  BIT_ULL(VIRTIO_NET_F_MRG_RXBUF))

struct mk_vnet_ring {
	struct vringh vrh;
	struct vringh_kiov iov;
	__le16 *avail_idx;		/* mapped for kick control */
	__le16 *avail_event;
};

struct mk_vnet {
	struct net_device *ndev;
	struct mk_virtio_hdev *hdev;
	struct napi_struct napi;
	struct mk_vnet_ring rx;		/* MK_VNET_RXQ: host writes */
	struct mk_vnet_ring tx;		/* MK_VNET_TXQ: host reads */
	struct vhost_iotlb *iotlb;
	spinlock_t iotlb_lock;		/* vringh needs one; the map is fixed after start */
	spinlock_t rx_lock;		/* host transmit into the spawn's RX ring */
};

/* The ring lives in instance memory the host also maps; refuse anything else */
static void *mk_vnet_ring_va(struct mk_vnet *vn, u64 phys, size_t len)
{
	struct vhost_iotlb_map *map = vhost_iotlb_itree_first(vn->iotlb, phys,
							      phys + len - 1);

	if (!map || map->start > phys || map->last < phys + len - 1)
		return NULL;
	return phys_to_virt(phys);
}

static int mk_vnet_ring_init(struct mk_vnet *vn, struct mk_vnet_ring *ring,
			     unsigned int queue)
{
	struct mk_virtio_queue *q = &vn->hdev->entry->queues[queue];
	u64 features = READ_ONCE(vn->hdev->entry->driver_features);
	size_t used_len = sizeof(struct vring_used) +
			  q->num * sizeof(struct vring_used_elem) + 2;
	struct vring_avail *avail;
	struct vring_used *used;
	int ret;

	if (!READ_ONCE(q->enable) || !q->num)
		return -ENXIO;
	ret = vringh_init_iotlb(&ring->vrh, features, q->num, true,
				(struct vring_desc *)(uintptr_t)q->desc,
				(struct vring_avail *)(uintptr_t)q->avail,
				(struct vring_used *)(uintptr_t)q->used);
	if (ret)
		return ret;
	vringh_set_iotlb(&ring->vrh, vn->iotlb, &vn->iotlb_lock);

	avail = mk_vnet_ring_va(vn, q->avail, sizeof(*avail) + q->num * 2 + 2);
	used = mk_vnet_ring_va(vn, q->used, used_len);
	if (!avail || !used)
		return -EINVAL;
	ring->avail_idx = (__le16 *)&avail->idx;
	ring->avail_event = (__le16 *)&used->ring[q->num];
	return 0;
}

/*
 * Ask the driver to kick again from its current avail index. Returns
 * false when it already queued more, so the caller keeps going.
 */
static bool mk_vnet_notify_enable(struct mk_vnet_ring *ring)
{
	u16 last = ring->vrh.last_avail_idx;

	if (!ring->vrh.event_indices)
		return true;
	WRITE_ONCE(*ring->avail_event, cpu_to_le16(last));
	/* The event must be visible before we look for buffers it would announce */
	smp_mb();
	return le16_to_cpu(READ_ONCE(*ring->avail_idx)) == last;
}

static netdev_tx_t mk_vnet_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct mk_vnet *vn = netdev_priv(ndev);
	struct virtio_net_hdr_mrg_rxbuf hdr = { .num_buffers = cpu_to_le16(1) };
	u16 head;
	int ret;

	if (skb_linearize(skb))
		goto drop;

	spin_lock(&vn->rx_lock);
	ret = vringh_getdesc_iotlb(&vn->rx.vrh, NULL, &vn->rx.iov, &head, GFP_ATOMIC);
	if (!ret) {
		/* Ring empty: wait for the driver's refill kick, unless it beat us */
		netif_stop_queue(ndev);
		if (mk_vnet_notify_enable(&vn->rx)) {
			spin_unlock(&vn->rx_lock);
			return NETDEV_TX_BUSY;
		}
		netif_start_queue(ndev);
		ret = vringh_getdesc_iotlb(&vn->rx.vrh, NULL, &vn->rx.iov, &head,
					   GFP_ATOMIC);
	}
	if (ret <= 0 || vringh_kiov_length(&vn->rx.iov) < MK_VNET_HDR_LEN + skb->len) {
		spin_unlock(&vn->rx_lock);
		goto drop;
	}
	vringh_iov_push_iotlb(&vn->rx.vrh, &vn->rx.iov, &hdr, MK_VNET_HDR_LEN);
	vringh_iov_push_iotlb(&vn->rx.vrh, &vn->rx.iov, skb->data, skb->len);
	vringh_complete_iotlb(&vn->rx.vrh, head, MK_VNET_HDR_LEN + skb->len);
	if (vringh_need_notify_iotlb(&vn->rx.vrh) > 0)
		mk_virtio_hdev_call(vn->hdev, MK_VNET_RXQ);
	spin_unlock(&vn->rx_lock);

	dev_sw_netstats_tx_add(ndev, 1, skb->len);
	dev_consume_skb_any(skb);
	return NETDEV_TX_OK;
drop:
	ndev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int mk_vnet_poll(struct napi_struct *napi, int budget)
{
	struct mk_vnet *vn = container_of(napi, struct mk_vnet, napi);
	struct net_device *ndev = vn->ndev;
	int done = 0;

	while (done < budget) {
		struct virtio_net_hdr_mrg_rxbuf hdr;
		struct sk_buff *skb;
		size_t len;
		u16 head;
		int ret;

		ret = vringh_getdesc_iotlb(&vn->tx.vrh, &vn->tx.iov, NULL, &head,
					   GFP_ATOMIC);
		if (ret <= 0)
			break;

		len = vringh_kiov_length(&vn->tx.iov);
		if (len < MK_VNET_HDR_LEN + ETH_HLEN) {
			ndev->stats.rx_length_errors++;
			vringh_complete_iotlb(&vn->tx.vrh, head, 0);
			continue;
		}
		len -= MK_VNET_HDR_LEN;

		skb = napi_alloc_skb(napi, len);
		if (!skb) {
			ndev->stats.rx_dropped++;
			vringh_complete_iotlb(&vn->tx.vrh, head, 0);
			continue;
		}
		vringh_iov_pull_iotlb(&vn->tx.vrh, &vn->tx.iov, &hdr, MK_VNET_HDR_LEN);
		vringh_iov_pull_iotlb(&vn->tx.vrh, &vn->tx.iov, skb_put(skb, len), len);
		vringh_complete_iotlb(&vn->tx.vrh, head, 0);

		skb->protocol = eth_type_trans(skb, ndev);
		dev_sw_netstats_rx_add(ndev, len);
		napi_gro_receive(napi, skb);
		done++;
	}

	if (vringh_need_notify_iotlb(&vn->tx.vrh) > 0)
		mk_virtio_hdev_call(vn->hdev, MK_VNET_TXQ);

	if (done < budget && napi_complete_done(napi, done)) {
		if (!mk_vnet_notify_enable(&vn->tx))
			napi_schedule(napi);
	}
	return done;
}

static const struct net_device_ops mk_vnet_ops = {
	.ndo_start_xmit = mk_vnet_xmit,
	.ndo_get_stats64 = dev_get_tstats64,
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
	spin_lock_init(&vn->iotlb_lock);
	spin_lock_init(&vn->rx_lock);
	vringh_kiov_init(&vn->rx.iov, NULL, 0);
	vringh_kiov_init(&vn->tx.iov, NULL, 0);
	netif_napi_add(ndev, &vn->napi, mk_vnet_poll);
	netif_carrier_off(ndev);

	ret = register_netdev(ndev);
	if (ret) {
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
	free_netdev(vn->ndev);
	hdev->priv = NULL;
}

static int mk_vnet_start(struct mk_virtio_hdev *hdev)
{
	struct mk_vnet *vn = hdev->priv;
	int ret;

	vn->iotlb = mk_virtio_hdev_iotlb(hdev);
	if (IS_ERR(vn->iotlb))
		return PTR_ERR(vn->iotlb);

	ret = mk_vnet_ring_init(vn, &vn->rx, MK_VNET_RXQ);
	if (!ret)
		ret = mk_vnet_ring_init(vn, &vn->tx, MK_VNET_TXQ);
	if (ret) {
		vhost_iotlb_free(vn->iotlb);
		vn->iotlb = NULL;
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
	vringh_kiov_cleanup(&vn->rx.iov);
	vringh_kiov_cleanup(&vn->tx.iov);
	vringh_kiov_init(&vn->rx.iov, NULL, 0);
	vringh_kiov_init(&vn->tx.iov, NULL, 0);
	spin_unlock_bh(&vn->rx_lock);
	vhost_iotlb_free(vn->iotlb);
	vn->iotlb = NULL;
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

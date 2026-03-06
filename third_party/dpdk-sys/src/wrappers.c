#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_net.h>
#include <string.h>

uint16_t rust_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t rust_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

uint16_t rust_rte_eth_tx_prepare(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
    return rte_eth_tx_prepare(port_id, queue_id, tx_pkts, nb_pkts);
}

struct rte_mbuf * rust_rte_pktmbuf_alloc(struct rte_mempool *mp)
{
    return rte_pktmbuf_alloc(mp);
}

char * rust_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len)
{
    return rte_pktmbuf_append(m, len);
}

void rust_rte_pktmbuf_free(struct rte_mbuf *m)
{
    rte_pktmbuf_free(m);
}

uint32_t rust_rte_pktmbuf_pkt_len(const struct rte_mbuf *m)
{
    return rte_pktmbuf_pkt_len(m);
}

uint16_t rust_rte_pktmbuf_data_len(const struct rte_mbuf *m)
{
    return rte_pktmbuf_data_len(m);
}

uint16_t rust_rte_pktmbuf_nb_segs(const struct rte_mbuf *m)
{
    return m->nb_segs;
}

void * rust_rte_pktmbuf_mtod(struct rte_mbuf *m)
{
    return rte_pktmbuf_mtod(m, void *);
}

void * rust_rte_pktmbuf_mtod_offset(struct rte_mbuf *m, uint16_t o)
{
    return rte_pktmbuf_mtod_offset(m, void *, o);
}

uint16_t rust_rte_pktmbuf_headroom(const struct rte_mbuf *m)
{
    return rte_pktmbuf_headroom(m);
}

const void * rust_rte_pktmbuf_read(const struct rte_mbuf *m, uint32_t off, uint32_t len, void *buf)
{
    return rte_pktmbuf_read(m, off, len, buf);
}

int rust_rte_errno(void)
{
    return rte_errno;
}

void rust_rte_reset_errno(void)
{
    rte_errno = 0;
}

void rust_rte_mbuf_prefetch_part1(struct rte_mbuf *m)
{
    rte_mbuf_prefetch_part1(m);
}

void rust_rte_mbuf_prefetch_part2(struct rte_mbuf *m)
{
    rte_mbuf_prefetch_part2(m);
}

uint16_t rust_rte_ipv4_phdr_cksum(const struct rte_ipv4_hdr *ipv4_hdr, uint64_t ol_flags)
{
    return rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
}

int rust_rte_prepare_ipv4_l4_checksum_offload(
    struct rte_mbuf *m,
    uint64_t ol_flags,
    uint16_t l2_len,
    uint16_t l3_len)
{
    int ret;

    if (m == NULL)
        return -EINVAL;

    m->ol_flags = ol_flags;
    m->l2_len = l2_len;
    m->l3_len = l3_len;
    m->l4_len = 0;
    m->tso_segsz = 0;
    m->outer_l2_len = 0;
    m->outer_l3_len = 0;

    ret = rte_validate_tx_offload(m);
    if (ret != 0)
        return ret;

    return rte_net_intel_cksum_flags_prepare(m, ol_flags);
}

int rust_rte_eth_dev_info_caps_get(
    uint16_t port_id,
    uint16_t *max_rx_queues,
    uint16_t *max_tx_queues,
    uint16_t *reta_size,
    uint64_t *flow_type_rss_offloads,
    uint64_t *tx_offload_capa,
    uint64_t *rx_offload_capa,
    uint32_t *max_rx_pktlen,
    const char **driver_name)
{
    struct rte_eth_dev_info info;
    memset(&info, 0, sizeof(info));
    rte_eth_dev_info_get(port_id, &info);

    if (max_rx_queues != NULL) {
        *max_rx_queues = info.max_rx_queues;
    }
    if (max_tx_queues != NULL) {
        *max_tx_queues = info.max_tx_queues;
    }
    if (reta_size != NULL) {
        *reta_size = info.reta_size;
    }
    if (flow_type_rss_offloads != NULL) {
        *flow_type_rss_offloads = info.flow_type_rss_offloads;
    }
    if (tx_offload_capa != NULL) {
        *tx_offload_capa = info.tx_offload_capa;
    }
    if (rx_offload_capa != NULL) {
        *rx_offload_capa = info.rx_offload_capa;
    }
    if (max_rx_pktlen != NULL) {
        *max_rx_pktlen = info.max_rx_pktlen;
    }
    if (driver_name != NULL) {
        *driver_name = info.driver_name;
    }
    return 0;
}

int rust_rte_eth_dev_configure_basic(
    uint16_t port_id,
    uint16_t rx_queues,
    uint16_t tx_queues,
    int enable_rss,
    uint64_t rss_hf,
    uint64_t tx_offloads)
{
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));

    if (enable_rss != 0) {
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
        conf.rx_adv_conf.rss_conf.rss_key = NULL;
        conf.rx_adv_conf.rss_conf.rss_key_len = 0;
    }

    conf.txmode.offloads = tx_offloads;
    return rte_eth_dev_configure(port_id, rx_queues, tx_queues, &conf);
}

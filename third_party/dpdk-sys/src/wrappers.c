#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_errno.h>

uint16_t rust_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t rust_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
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

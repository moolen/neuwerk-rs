use super::Packet;

pub trait FrameIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String>;
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String>;
    fn send_borrowed_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.send_frame(frame)
    }
    fn recv_packet(&mut self, pkt: &mut Packet) -> Result<usize, String> {
        pkt.prepare_for_rx(65536);
        let n = self.recv_frame(pkt.buffer_mut())?;
        pkt.truncate(n);
        Ok(n)
    }
    fn finish_rx_packet(&mut self) {}
    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn mac(&self) -> Option<[u8; 6]> {
        None
    }
}

pub struct UnwiredDpdkIo;

impl UnwiredDpdkIo {
    pub fn new(_iface: &str, _metrics: Option<crate::metrics::Metrics>) -> Result<Self, String> {
        Err(
            "dpdk io backend not available (build with --features dpdk and install DPDK)"
                .to_string(),
        )
    }

    pub fn new_with_queue(
        _iface: &str,
        _queue_id: u16,
        _queue_count: u16,
        _metrics: Option<crate::metrics::Metrics>,
    ) -> Result<Self, String> {
        Err(
            "dpdk io backend not available (build with --features dpdk and install DPDK)"
                .to_string(),
        )
    }

    pub fn effective_queue_count(_iface: &str, _queue_count: u16) -> Result<u16, String> {
        Err(
            "dpdk io backend not available (build with --features dpdk and install DPDK)"
                .to_string(),
        )
    }
}

impl FrameIo for UnwiredDpdkIo {
    fn recv_frame(&mut self, _buf: &mut [u8]) -> Result<usize, String> {
        Err("dpdk io backend not implemented".to_string())
    }

    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), String> {
        Err("dpdk io backend not implemented".to_string())
    }
}

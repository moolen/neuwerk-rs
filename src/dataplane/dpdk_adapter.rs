use crate::dataplane::engine::EngineState;

#[derive(Debug)]
pub struct DpdkAdapter {
    data_iface: String,
}

impl DpdkAdapter {
    pub fn new(data_iface: String) -> Result<Self, String> {
        if data_iface.trim().is_empty() {
            return Err("data-plane-interface cannot be empty".to_string());
        }
        Ok(Self {
            data_iface: data_iface.trim().to_string(),
        })
    }

    pub fn run(&mut self, _state: &mut EngineState) -> Result<(), String> {
        println!(
            "dataplane started (no-op), data-plane-interface={}",
            self.data_iface
        );
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

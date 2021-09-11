use env_logger::*;

pub struct Logs;

impl Logs {
    pub fn new(){
        env_logger::init();
        info!("Starting Logging")
    }
}


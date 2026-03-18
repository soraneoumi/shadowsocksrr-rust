use anyhow::Result;
use std::collections::HashMap;

pub mod auth_akarin;
pub mod auth_chain;
pub mod udp;

#[derive(Clone)]
pub struct ProtocolConfigRuntime {
    pub method: String,
    pub key: Vec<u8>,
    pub recv_iv: Vec<u8>,
    pub protocol_param: String,
    pub users: HashMap<u32, Vec<u8>>,
    pub overhead: u16,
    pub tcp_mss: u16,
}

pub trait ProtocolCodec: Send {
    fn decode_from_client(&mut self, input: &[u8]) -> Result<(Vec<u8>, bool)>;
    fn decode_from_client_into(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        let (decoded, sendback) = self.decode_from_client(input)?;
        out.clear();
        out.extend_from_slice(&decoded);
        Ok(sendback)
    }
    fn encode_to_client(&mut self, input: &[u8]) -> Result<Vec<u8>>;
    fn encode_to_client_into(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let encoded = self.encode_to_client(input)?;
        out.clear();
        out.extend_from_slice(&encoded);
        Ok(())
    }
    fn on_encode_to_client_flushed(&mut self, _delivered: bool) -> Result<()> {
        Ok(())
    }
    fn update_tcp_mss(&mut self, _tcp_mss: u16) {}
    fn dispose(&mut self);
}

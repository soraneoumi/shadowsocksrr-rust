use crate::crypto::{ChaCha20Stream, Rc4Stream, hmac_md5};
use crate::protocol::ProtocolConfigRuntime;
use crate::protocol::auth_akarin::AuthAkarinVariant;
use crate::protocol::auth_chain::AuthChainVariant;
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::{RngExt, rng};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpCipherKind {
    ChainRc4,
    AkarinChaCha20,
}

#[derive(Clone, Default)]
struct XorShift128Plus {
    v0: u64,
    v1: u64,
}

impl XorShift128Plus {
    const MOV_MASK: u64 = (1_u64 << (64 - 23)) - 1;

    fn next(&mut self) -> u64 {
        let mut x = self.v0;
        let y = self.v1;
        self.v0 = y;
        x ^= (x & Self::MOV_MASK) << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.v1 = x;
        x.wrapping_add(y)
    }

    fn init_from_bin(&mut self, input: &[u8]) {
        let mut data = [0_u8; 16];
        let n = input.len().min(16);
        data[..n].copy_from_slice(&input[..n]);
        self.v0 = u64::from_le_bytes(data[0..8].try_into().unwrap());
        self.v1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
    }
}

#[derive(Clone)]
pub struct UdpProtocolCodec {
    method: String,
    kind: UdpCipherKind,
    key: Vec<u8>,
    users: HashMap<u32, Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UdpSessionRef {
    LegacyUid(Option<u32>),
}

#[derive(Debug)]
pub enum UdpClientPacket {
    Data {
        plain: Vec<u8>,
        session: UdpSessionRef,
    },
}

#[derive(Debug)]
pub struct UdpSendPlan {
    packet: Vec<u8>,
}

impl UdpSendPlan {
    fn new(packet: Vec<u8>) -> Self {
        Self { packet }
    }

    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    pub fn complete(self, _delivered: bool) {}
}

impl UdpProtocolCodec {
    #[cfg(test)]
    pub fn new(cfg: ProtocolConfigRuntime) -> Result<Self> {
        Self::new_with_replay_capacity(cfg, 1)
    }

    pub fn new_with_replay_capacity(
        cfg: ProtocolConfigRuntime,
        _replay_max_entries: usize,
    ) -> Result<Self> {
        let kind = if AuthChainVariant::from_method(&cfg.method).is_some() {
            UdpCipherKind::ChainRc4
        } else if AuthAkarinVariant::from_method(&cfg.method).is_some() {
            UdpCipherKind::AkarinChaCha20
        } else {
            bail!("unsupported protocol method for UDP: {}", cfg.method);
        };

        Ok(Self {
            method: cfg.method,
            kind,
            key: cfg.key,
            users: cfg.users,
        })
    }

    pub fn decode_from_client(&self, input: &[u8]) -> Result<UdpClientPacket> {
        if input.len() <= 8 {
            bail!("udp packet too short");
        }

        let seed_data = &input[input.len() - 8..input.len() - 5];
        let md5_seed = hmac_md5(&self.key, seed_data);

        let uid_enc = u32::from_le_bytes(
            input[input.len() - 5..input.len() - 1]
                .try_into()
                .map_err(|_| anyhow!("invalid udp uid bytes"))?,
        );
        let uid = uid_enc ^ u32::from_le_bytes(md5_seed[0..4].try_into().unwrap());

        let (user_key, user_id) = self.select_user_key_for_decode(uid)?;
        let check = hmac_md5(&user_key, &input[..input.len() - 1])[0];
        if check != input[input.len() - 1] {
            bail!("udp checksum mismatch for {}", self.method);
        }

        let rand_len = Self::udp_rnd_data_len(&md5_seed);
        if input.len() < 8 + rand_len {
            bail!("udp packet malformed random length");
        }
        let encrypted_len = input.len() - 8 - rand_len;
        let plain = self.apply_stream_cipher(&user_key, &md5_seed, &input[..encrypted_len])?;
        Ok(UdpClientPacket::Data {
            plain,
            session: UdpSessionRef::LegacyUid(user_id),
        })
    }

    pub fn encode_to_client(&self, input: &[u8], session: UdpSessionRef) -> Result<UdpSendPlan> {
        let user_key = match session {
            UdpSessionRef::LegacyUid(uid) => self.select_user_key_for_encode(uid)?,
        };

        let mut auth_data = [0_u8; 7];
        rng().fill(&mut auth_data);
        let md5_seed = hmac_md5(&self.key, &auth_data);
        let rand_len = Self::udp_rnd_data_len(&md5_seed);

        let encrypted = self.apply_stream_cipher(&user_key, &md5_seed, input)?;
        let mut out = Vec::with_capacity(encrypted.len() + rand_len + auth_data.len() + 1);
        out.extend_from_slice(&encrypted);

        if rand_len > 0 {
            let mut pad = vec![0_u8; rand_len];
            rng().fill(&mut pad);
            out.extend_from_slice(&pad);
        }

        out.extend_from_slice(&auth_data);
        let check = hmac_md5(&user_key, &out)[0];
        out.push(check);
        Ok(UdpSendPlan::new(out))
    }

    fn select_user_key_for_decode(&self, uid: u32) -> Result<(Vec<u8>, Option<u32>)> {
        if let Some(user_key) = self.users.get(&uid) {
            return Ok((user_key.clone(), Some(uid)));
        }
        if self.users.is_empty() {
            return Ok((self.key.clone(), None));
        }
        bail!("unknown udp uid {} for {}", uid, self.method)
    }

    fn select_user_key_for_encode(&self, uid: Option<u32>) -> Result<Vec<u8>> {
        if let Some(id) = uid {
            if let Some(user_key) = self.users.get(&id) {
                return Ok(user_key.clone());
            }
            bail!("unknown udp response uid {} for {}", id, self.method);
        }
        if self.users.is_empty() {
            return Ok(self.key.clone());
        }
        bail!("missing udp response uid for {}", self.method)
    }

    fn udp_rnd_data_len(seed: &[u8; 16]) -> usize {
        let mut random = XorShift128Plus::default();
        random.init_from_bin(seed);
        (random.next() % 127) as usize
    }

    fn apply_stream_cipher(
        &self,
        user_key: &[u8],
        md5_seed: &[u8; 16],
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut password = B64.encode(user_key).into_bytes();
        password.extend_from_slice(B64.encode(md5_seed).as_bytes());

        match self.kind {
            UdpCipherKind::ChainRc4 => {
                let mut stream = Rc4Stream::new_from_password(&password)?;
                Ok(stream.process(data))
            }
            UdpCipherKind::AkarinChaCha20 => {
                let nonce = Self::nonce_from_key(&self.key);
                let mut stream = ChaCha20Stream::new_from_password(&password, &nonce)?;
                Ok(stream.process(data))
            }
        }
    }

    fn nonce_from_key(key: &[u8]) -> [u8; 8] {
        let mut nonce = [0_u8; 8];
        let n = key.len().min(8);
        nonce[..n].copy_from_slice(&key[..n]);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cfg(method: &str) -> ProtocolConfigRuntime {
        ProtocolConfigRuntime {
            method: method.to_string(),
            key: b"demo-key-0123456".to_vec(),
            recv_iv: Vec::new(),
            protocol_param: "64".to_string(),
            users: HashMap::new(),
            overhead: 4,
            tcp_mss: 1460,
        }
    }

    fn make_client_udp_packet(codec: &UdpProtocolCodec, plain: &[u8], uid: u32) -> Vec<u8> {
        let auth_data = [1_u8, 2_u8, 3_u8];
        let md5_seed = hmac_md5(&codec.key, &auth_data);
        let (user_key, _) = codec.select_user_key_for_decode(uid).expect("user key");
        let encrypted = codec
            .apply_stream_cipher(&user_key, &md5_seed, plain)
            .expect("encrypt");

        let rand_len = UdpProtocolCodec::udp_rnd_data_len(&md5_seed);
        let mut out = Vec::with_capacity(encrypted.len() + rand_len + 8 + 1);
        out.extend_from_slice(&encrypted);
        out.extend(std::iter::repeat_n(0_u8, rand_len));
        out.extend_from_slice(&auth_data);

        let uid_enc = uid ^ u32::from_le_bytes(md5_seed[0..4].try_into().unwrap());
        out.extend_from_slice(&uid_enc.to_le_bytes());
        let check = hmac_md5(&user_key, &out)[0];
        out.push(check);
        out
    }

    fn decode_server_udp_packet(
        codec: &UdpProtocolCodec,
        packet: &[u8],
        session: UdpSessionRef,
    ) -> Vec<u8> {
        assert!(packet.len() > 8);
        let uid = match session {
            UdpSessionRef::LegacyUid(uid) => uid,
        };
        let user_key = codec.select_user_key_for_encode(uid).expect("user key");
        let check = hmac_md5(&user_key, &packet[..packet.len() - 1])[0];
        assert_eq!(
            check,
            packet[packet.len() - 1],
            "server udp packet checksum"
        );

        let md5_seed = hmac_md5(&codec.key, &packet[packet.len() - 8..packet.len() - 1]);
        let rand_len = UdpProtocolCodec::udp_rnd_data_len(&md5_seed);
        let encrypted = &packet[..packet.len() - 8 - rand_len];
        codec
            .apply_stream_cipher(&user_key, &md5_seed, encrypted)
            .expect("decrypt")
    }

    #[test]
    fn udp_decode_chain_request_roundtrip() {
        let codec = UdpProtocolCodec::new(build_cfg("auth_chain_d")).expect("codec");
        let plain = b"\x01\x08\x08\x08\x08\x00\x35hello";
        let packet = make_client_udp_packet(&codec, plain, 1001);

        let decoded = codec.decode_from_client(&packet).expect("decode");
        match decoded {
            UdpClientPacket::Data {
                plain: decoded,
                session,
            } => {
                assert_eq!(decoded, plain);
                assert_eq!(
                    session,
                    UdpSessionRef::LegacyUid(None),
                    "without configured users uid should not be retained"
                );
            }
        }
    }

    #[test]
    fn udp_decode_akarin_request_with_user() {
        let mut cfg = build_cfg("auth_akarin_spec_a");
        cfg.users.insert(1001, b"user-key-1001".to_vec());
        let codec = UdpProtocolCodec::new(cfg).expect("codec");
        let plain = b"\x01\x08\x08\x04\x04\x00\x35payload";
        let packet = make_client_udp_packet(&codec, plain, 1001);

        let decoded = codec.decode_from_client(&packet).expect("decode");
        match decoded {
            UdpClientPacket::Data {
                plain: decoded,
                session,
            } => {
                assert_eq!(decoded, plain);
                assert_eq!(session, UdpSessionRef::LegacyUid(Some(1001)));
            }
        }
    }

    #[test]
    fn udp_rejects_unknown_uid_when_users_are_configured() {
        let mut cfg = build_cfg("auth_akarin_spec_a");
        cfg.users.insert(1001, b"user-key-1001".to_vec());
        let codec = UdpProtocolCodec::new(cfg).expect("codec");
        let auth_data = [1_u8, 2_u8, 3_u8];
        let md5_seed = hmac_md5(&codec.key, &auth_data);
        let uid_enc = 2002_u32 ^ u32::from_le_bytes(md5_seed[0..4].try_into().unwrap());
        let mut packet = vec![0xaa];
        packet.extend_from_slice(&auth_data);
        packet.extend_from_slice(&uid_enc.to_le_bytes());
        packet.push(0);

        let err = codec
            .decode_from_client(&packet)
            .expect_err("unknown uid should be rejected");
        assert!(
            err.to_string().contains("unknown udp uid"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn udp_encode_chain_response_roundtrip() {
        let codec = UdpProtocolCodec::new(build_cfg("auth_chain_f")).expect("codec");
        let plain = b"\x01\x01\x01\x01\x01\x13\x88hello";
        let packet = codec
            .encode_to_client(plain, UdpSessionRef::LegacyUid(None))
            .expect("encode");
        let decoded =
            decode_server_udp_packet(&codec, packet.packet(), UdpSessionRef::LegacyUid(None));
        packet.complete(true);
        assert_eq!(decoded, plain);
    }

    #[test]
    fn udp_encode_akarin_response_roundtrip() {
        let mut cfg = build_cfg("auth_akarin_spec_a");
        cfg.users.insert(1001, b"user-key-1001".to_vec());
        let codec = UdpProtocolCodec::new(cfg).expect("codec");
        let plain = b"\x03\x0bexample.org\x13\x88hello";
        let packet = codec
            .encode_to_client(plain, UdpSessionRef::LegacyUid(Some(1001)))
            .expect("encode");
        let decoded = decode_server_udp_packet(
            &codec,
            packet.packet(),
            UdpSessionRef::LegacyUid(Some(1001)),
        );
        packet.complete(true);
        assert_eq!(decoded, plain);
    }
}

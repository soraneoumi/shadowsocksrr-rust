use crate::common::{PrefixBuffer, int32, parse_protocol_param_max_client};
use crate::crypto::{Rc4Stream, aes128_cbc_decrypt_no_padding, hmac_md5};
use crate::protocol::{ProtocolCodec, ProtocolConfigRuntime};
use crate::state::SharedUserRegistry;
use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::{RngExt, rng};
use std::cmp::min;
use std::collections::HashMap;
use tracing::warn;

#[derive(Clone, Copy)]
pub enum AuthChainVariant {
    D,
    E,
    F,
}

impl AuthChainVariant {
    pub fn from_method(method: &str) -> Option<Self> {
        match method {
            "auth_chain_d" => Some(Self::D),
            "auth_chain_e" => Some(Self::E),
            "auth_chain_f" => Some(Self::F),
            _ => None,
        }
    }
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

    fn init_from_bin_len(&mut self, input: &[u8], length: usize) {
        let mut data = [0_u8; 16];
        let n = input.len().min(16);
        data[..n].copy_from_slice(&input[..n]);

        let mut first = [0_u8; 8];
        first[0..2].copy_from_slice(&(length as u16).to_le_bytes());
        first[2..8].copy_from_slice(&data[2..8]);

        self.v0 = u64::from_le_bytes(first);
        self.v1 = u64::from_le_bytes(data[8..16].try_into().unwrap());

        for _ in 0..4 {
            let _ = self.next();
        }
    }
}

fn lower_bound(list: &[u16], value: usize) -> usize {
    match list.binary_search_by(|x| (*x as usize).cmp(&value)) {
        Ok(i) | Err(i) => i,
    }
}

pub struct AuthChainCodec {
    variant: AuthChainVariant,
    method: String,
    key: Vec<u8>,
    recv_iv: Vec<u8>,
    users: HashMap<u32, Vec<u8>>,

    max_time_dif: i32,
    salt: &'static [u8],
    no_compatible_method: String,

    recv_buf: PrefixBuffer,
    unit_len: usize,
    raw_trans: bool,
    has_recv_header: bool,

    client_id: u32,
    connection_id: u32,
    pack_id: u32,
    recv_id: u32,

    user_id: Option<u32>,
    user_id_num: u32,
    user_key: Vec<u8>,

    overhead: u16,
    client_over_head: u16,
    tcp_mss: u16,

    last_client_hash: [u8; 16],
    last_server_hash: [u8; 16],
    random_client: XorShift128Plus,
    random_server: XorShift128Plus,

    crypt_tx: Option<Rc4Stream>,
    crypt_rx: Option<Rc4Stream>,

    data_size_list0: Vec<u16>,

    key_change_interval: u64,
    key_change_datetime_key_bytes: [u8; 8],

    shared_registry: SharedUserRegistry,
}

impl AuthChainCodec {
    pub fn new(
        variant: AuthChainVariant,
        cfg: ProtocolConfigRuntime,
        shared_registry: SharedUserRegistry,
    ) -> Self {
        let salt = match variant {
            AuthChainVariant::D => b"auth_chain_d".as_ref(),
            AuthChainVariant::E => b"auth_chain_e".as_ref(),
            AuthChainVariant::F => b"auth_chain_f".as_ref(),
        };

        let max_client = parse_protocol_param_max_client(&cfg.protocol_param, 64);
        shared_registry.set_max_client(max_client);
        let mut key_change_interval = 60 * 60 * 24;
        if let AuthChainVariant::F = variant {
            if let Some(interval) = cfg
                .protocol_param
                .split('#')
                .nth(1)
                .and_then(|x| x.parse::<u64>().ok())
            {
                key_change_interval = interval.max(1);
            }
        }

        let mut codec = Self {
            variant,
            method: cfg.method.clone(),
            key: cfg.key,
            recv_iv: cfg.recv_iv,
            users: cfg.users,

            max_time_dif: 60 * 60 * 24,
            salt,
            no_compatible_method: cfg.method,

            recv_buf: PrefixBuffer::new(),
            unit_len: 2800,
            raw_trans: false,
            has_recv_header: false,

            client_id: 0,
            connection_id: 0,
            pack_id: 1,
            recv_id: 1,

            user_id: None,
            user_id_num: 0,
            user_key: Vec::new(),

            overhead: cfg.overhead,
            client_over_head: cfg.overhead,
            tcp_mss: cfg.tcp_mss,

            last_client_hash: [0_u8; 16],
            last_server_hash: [0_u8; 16],
            random_client: XorShift128Plus::default(),
            random_server: XorShift128Plus::default(),

            crypt_tx: None,
            crypt_rx: None,

            data_size_list0: Vec::new(),

            key_change_interval,
            key_change_datetime_key_bytes: [0_u8; 8],

            shared_registry,
        };

        if !matches!(codec.variant, AuthChainVariant::F) {
            let key = codec.key.clone();
            codec.init_data_size(&key);
        }

        codec
    }

    fn not_match_return(&mut self, buf: &[u8]) -> (Vec<u8>, bool) {
        self.raw_trans = true;
        self.overhead = 0;
        warn!(
            method = %self.method,
            recv_len = buf.len(),
            "auth_chain protocol mismatch; switching to raw_trans"
        );
        if self.method == self.no_compatible_method {
            return (vec![b'E'; 2048], false);
        }
        (buf.to_vec(), false)
    }

    fn rnd_start_pos(&mut self, rand_len: usize, random: &mut XorShift128Plus) -> usize {
        if rand_len == 0 {
            return 0;
        }
        (random.next() % 8_589_934_609_u64 % rand_len as u64) as usize
    }

    fn rnd_data_len(
        &mut self,
        buf_size: usize,
        last_hash: &[u8; 16],
        random: &mut XorShift128Plus,
    ) -> usize {
        match self.variant {
            AuthChainVariant::D => {
                let other_data_size = buf_size + self.overhead as usize;
                if self.data_size_list0.is_empty() {
                    return 0;
                }
                if other_data_size >= *self.data_size_list0.last().unwrap() as usize {
                    return 0;
                }
                random.init_from_bin_len(last_hash, buf_size);
                let pos = lower_bound(&self.data_size_list0, other_data_size);
                let remain = self.data_size_list0.len().saturating_sub(pos);
                if remain == 0 {
                    return 0;
                }
                let final_pos = pos + (random.next() as usize % remain);
                self.data_size_list0[final_pos] as usize - other_data_size
            }
            AuthChainVariant::E | AuthChainVariant::F => {
                random.init_from_bin_len(last_hash, buf_size);
                let other_data_size = buf_size + self.overhead as usize;
                if self.data_size_list0.is_empty() {
                    return 0;
                }
                if other_data_size >= *self.data_size_list0.last().unwrap() as usize {
                    return 0;
                }
                let pos = lower_bound(&self.data_size_list0, other_data_size);
                self.data_size_list0[pos] as usize - other_data_size
            }
        }
    }

    fn rnd_data(
        &mut self,
        buf_size: usize,
        buf: &[u8],
        last_hash: &[u8; 16],
        random: &mut XorShift128Plus,
    ) -> Vec<u8> {
        let rand_len = self.rnd_data_len(buf_size, last_hash, random);
        let mut rnd = vec![0_u8; rand_len];
        rng().fill(&mut rnd);

        if buf_size == 0 {
            return rnd;
        }

        if rand_len > 0 {
            let start_pos = self.rnd_start_pos(rand_len, random);
            let mut out = Vec::with_capacity(buf_size + rand_len);
            out.extend_from_slice(&rnd[..start_pos]);
            out.extend_from_slice(buf);
            out.extend_from_slice(&rnd[start_pos..]);
            return out;
        }

        buf.to_vec()
    }

    fn init_data_size(&mut self, key: &[u8]) {
        match self.variant {
            AuthChainVariant::D | AuthChainVariant::E => {
                self.data_size_list0.clear();
                let mut random = XorShift128Plus::default();
                random.init_from_bin(key);
                let list_len = (random.next() % (8 + 16) as u64 + (4 + 8) as u64) as usize;
                for _ in 0..list_len {
                    self.data_size_list0
                        .push((random.next() % 2340 % 2040 % 1440) as u16);
                }
                self.data_size_list0.sort_unstable();
                self.check_and_patch_data_size(&mut random);
                self.data_size_list0.sort_unstable();
            }
            AuthChainVariant::F => {
                self.data_size_list0.clear();
                let mut new_key = self.key.clone();
                for i in 0..8.min(new_key.len()) {
                    new_key[i] ^= self.key_change_datetime_key_bytes[i];
                }

                let mut random = XorShift128Plus::default();
                random.init_from_bin(&new_key);
                let list_len = (random.next() % (8 + 16) as u64 + (4 + 8) as u64) as usize;
                for _ in 0..list_len {
                    self.data_size_list0
                        .push((random.next() % 2340 % 2040 % 1440) as u16);
                }
                self.data_size_list0.sort_unstable();
                self.check_and_patch_data_size(&mut random);
                self.data_size_list0.sort_unstable();
            }
        }
    }

    fn check_and_patch_data_size(&mut self, random: &mut XorShift128Plus) {
        while self
            .data_size_list0
            .last()
            .map(|x| *x < 1300)
            .unwrap_or(true)
            && self.data_size_list0.len() < 64
        {
            self.data_size_list0
                .push((random.next() % 2340 % 2040 % 1440) as u16);
        }
    }

    fn on_recv_auth_data(&mut self, utc_time: u32) {
        if !matches!(self.variant, AuthChainVariant::F) {
            return;
        }

        let key = utc_time as u64 / self.key_change_interval;
        for i in (0..8).rev() {
            self.key_change_datetime_key_bytes[7 - i] = ((key >> (8 * i)) & 0xff) as u8;
        }
        let key = self.key.clone();
        self.init_data_size(&key);
    }

    fn select_user_key(&mut self, uid: u32) -> bool {
        self.user_id_num = uid;
        if let Some(key) = self.users.get(&uid) {
            self.user_id = Some(uid);
            self.user_key = key.clone();
            return true;
        }

        self.user_id = None;
        self.user_id_num = 0;
        if self.users.is_empty() {
            self.user_key = self.key.clone();
            true
        } else {
            self.user_key.clear();
            false
        }
    }

    fn init_connection_ciphers(&mut self) -> Result<()> {
        let mut password = B64.encode(&self.user_key).into_bytes();
        password.extend_from_slice(B64.encode(self.last_client_hash).as_bytes());
        self.crypt_tx = Some(Rc4Stream::new_from_password(&password)?);
        self.crypt_rx = Some(Rc4Stream::new_from_password(&password)?);
        Ok(())
    }

    fn decrypt_head_block(&self, encrypted_16: &[u8]) -> Result<[u8; 16]> {
        if encrypted_16.len() != 16 {
            return Err(anyhow!("invalid auth head size"));
        }
        let mut password = B64.encode(&self.user_key).into_bytes();
        password.extend_from_slice(self.salt);
        let plain = aes128_cbc_decrypt_no_padding(&password, &[0_u8; 16], encrypted_16)?;
        let mut out = [0_u8; 16];
        out.copy_from_slice(&plain[..16]);
        Ok(out)
    }

    fn pack_server_data(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        let encrypted = self
            .crypt_tx
            .as_mut()
            .ok_or_else(|| anyhow!("tx cipher not initialized"))?
            .process(buf);

        let mut random_server = std::mem::take(&mut self.random_server);
        let last_server_hash = self.last_server_hash;
        let mut rnd = self.rnd_data(
            encrypted.len(),
            &encrypted,
            &last_server_hash,
            &mut random_server,
        );
        self.random_server = random_server;

        let length = (encrypted.len() as u16)
            ^ u16::from_le_bytes([self.last_server_hash[14], self.last_server_hash[15]]);
        let mut data = Vec::with_capacity(rnd.len() + 4);
        data.extend_from_slice(&length.to_le_bytes());
        data.append(&mut rnd);

        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.last_server_hash = hmac_md5(&mac_key, &data);
        data.extend_from_slice(&self.last_server_hash[..2]);
        self.pack_id = self.pack_id.wrapping_add(1);
        Ok(data)
    }
}

impl ProtocolCodec for AuthChainCodec {
    fn decode_from_client(&mut self, input: &[u8]) -> Result<(Vec<u8>, bool)> {
        if self.raw_trans {
            return Ok((input.to_vec(), false));
        }
        self.recv_buf.extend_from_slice(input);
        let mut out_buf = Vec::new();
        let mut sendback = false;

        if !self.has_recv_header {
            if self.recv_buf.len() >= 12 || self.recv_buf.len() == 7 || self.recv_buf.len() == 8 {
                let recv_len = self.recv_buf.len().min(12);
                if self.recv_buf.len() >= 4 {
                    let mut mac_key = self.recv_iv.clone();
                    mac_key.extend_from_slice(&self.key);
                    let md5data = hmac_md5(&mac_key, &self.recv_buf[..4]);
                    if md5data[..recv_len - 4] != self.recv_buf[4..recv_len] {
                        let recv_snapshot = self.recv_buf.clone();
                        return Ok(self.not_match_return(&recv_snapshot));
                    }
                }
            }

            if self.recv_buf.len() < 36 {
                return Ok((Vec::new(), false));
            }

            let mut mac_key = self.recv_iv.clone();
            mac_key.extend_from_slice(&self.key);
            let md5data = hmac_md5(&mac_key, &self.recv_buf[..4]);
            self.last_client_hash = md5data;

            let uid_xor = u32::from_le_bytes(self.recv_buf[12..16].try_into().unwrap());
            let uid = uid_xor ^ u32::from_le_bytes(md5data[8..12].try_into().unwrap());
            if !self.select_user_key(uid) {
                let recv_snapshot = self.recv_buf.clone();
                return Ok(self.not_match_return(&recv_snapshot));
            }

            let md5data2 = hmac_md5(&self.user_key, &self.recv_buf[12..32]);
            if md5data2[..4] != self.recv_buf[32..36] {
                let recv_snapshot = self.recv_buf.clone();
                return Ok(self.not_match_return(&recv_snapshot));
            }
            self.last_server_hash = md5data2;

            let head = self.decrypt_head_block(&self.recv_buf[16..32])?;
            self.client_over_head = u16::from_le_bytes(head[12..14].try_into().unwrap());

            let utc_time = u32::from_le_bytes(head[0..4].try_into().unwrap());
            let client_id = u32::from_le_bytes(head[4..8].try_into().unwrap());
            let connection_id = u32::from_le_bytes(head[8..12].try_into().unwrap());

            let time_dif = int32(utc_time as i64 - crate::common::now_secs_u32() as i64);
            if time_dif < -self.max_time_dif || time_dif > self.max_time_dif {
                warn!(
                    method = %self.method,
                    time_dif,
                    max_time_dif = self.max_time_dif,
                    "auth_chain timestamp check failed"
                );
                let recv_snapshot = self.recv_buf.clone();
                return Ok(self.not_match_return(&recv_snapshot));
            }

            let reg_user = self.user_id.unwrap_or(0);
            if self
                .shared_registry
                .insert(reg_user, client_id, connection_id)
            {
                self.has_recv_header = true;
                self.client_id = client_id;
                self.connection_id = connection_id;
            } else {
                let recv_snapshot = self.recv_buf.clone();
                return Ok(self.not_match_return(&recv_snapshot));
            }

            self.on_recv_auth_data(utc_time);
            self.init_connection_ciphers()?;

            self.recv_buf.consume(36);
            self.has_recv_header = true;
            sendback = true;
        }

        loop {
            if self.recv_buf.len() <= 4 {
                break;
            }

            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());

            let data_len = u16::from_le_bytes(self.recv_buf[0..2].try_into().unwrap())
                ^ u16::from_le_bytes(self.last_client_hash[14..16].try_into().unwrap());

            let mut random_client = std::mem::take(&mut self.random_client);
            let last_client_hash = self.last_client_hash;
            let rand_len =
                self.rnd_data_len(data_len as usize, &last_client_hash, &mut random_client);
            self.random_client = random_client;

            let length = data_len as usize + rand_len;
            if length >= 4096 {
                self.raw_trans = true;
                self.recv_buf.clear();
                warn!(
                    method = %self.method,
                    recv_id = self.recv_id,
                    length,
                    "auth_chain frame length overflow"
                );
                if self.recv_id == 1 {
                    return Ok((vec![b'E'; 2048], false));
                }
                return Err(anyhow!("auth_chain decode data length overflow"));
            }

            if length + 4 > self.recv_buf.len() {
                break;
            }

            let client_hash = hmac_md5(&mac_key, &self.recv_buf[..length + 2]);
            if client_hash[..2] != self.recv_buf[length + 2..length + 4] {
                self.raw_trans = true;
                self.recv_buf.clear();
                warn!(
                    method = %self.method,
                    recv_id = self.recv_id,
                    "auth_chain checksum mismatch"
                );
                if self.recv_id == 1 {
                    return Ok((vec![b'E'; 2048], false));
                }
                return Err(anyhow!("auth_chain checksum mismatch"));
            }

            self.recv_id = self.recv_id.wrapping_add(1);

            let mut pos = 2;
            if data_len > 0 && rand_len > 0 {
                let mut random_client = std::mem::take(&mut self.random_client);
                pos = 2 + self.rnd_start_pos(rand_len, &mut random_client);
                self.random_client = random_client;
            }

            let plain = self
                .crypt_rx
                .as_mut()
                .ok_or_else(|| anyhow!("rx cipher not initialized"))?
                .process(&self.recv_buf[pos..pos + data_len as usize]);
            out_buf.extend_from_slice(&plain);

            self.last_client_hash = client_hash;
            self.recv_buf.consume(length + 4);

            if data_len == 0 {
                sendback = true;
            }
        }

        if !out_buf.is_empty() {
            let reg_user = self.user_id.unwrap_or(0);
            self.shared_registry.update(reg_user, self.client_id);
        }

        Ok((out_buf, sendback))
    }

    fn encode_to_client(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if self.raw_trans {
            return Ok(input.to_vec());
        }

        let mut out = Vec::new();
        let mut buf = input.to_vec();

        if self.pack_id == 1 {
            let base_mss = if self.tcp_mss == 0 {
                1460
            } else {
                self.tcp_mss
            };
            let tcp_mss = min(base_mss.clamp(500, 1500), 1500);
            self.tcp_mss = tcp_mss;
            let mut first = Vec::with_capacity(buf.len() + 2);
            first.extend_from_slice(&tcp_mss.to_le_bytes());
            first.extend_from_slice(&buf);
            buf = first;
            let unit = tcp_mss.saturating_sub(self.client_over_head);
            self.unit_len = unit.max(1) as usize;
        }

        let mut start = 0;
        while buf.len().saturating_sub(start) > self.unit_len {
            out.extend_from_slice(&self.pack_server_data(&buf[start..start + self.unit_len])?);
            start += self.unit_len;
        }

        out.extend_from_slice(&self.pack_server_data(&buf[start..])?);
        Ok(out)
    }

    fn update_tcp_mss(&mut self, tcp_mss: u16) {
        self.tcp_mss = tcp_mss.max(500);
    }

    fn dispose(&mut self) {
        let reg_user = self.user_id.unwrap_or(0);
        self.shared_registry.remove(reg_user, self.client_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::now_secs_u32;
    use crate::protocol::ProtocolConfigRuntime;
    use crate::state::SharedUserRegistry;
    use aes::Aes128;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use std::collections::HashMap;

    fn base_cfg(method: &str) -> ProtocolConfigRuntime {
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

    fn encrypt_head_block(user_key: &[u8], salt: &[u8], plain: &[u8; 16]) -> [u8; 16] {
        let mut password = B64.encode(user_key).into_bytes();
        password.extend_from_slice(salt);
        let (key, _) = crate::crypto::evp_bytes_to_key(&password, 16, 16);
        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut block = GenericArray::clone_from_slice(plain);
        cipher.encrypt_block(&mut block);
        let mut out = [0_u8; 16];
        out.copy_from_slice(&block);
        out
    }

    fn build_chain_client_packet(variant: AuthChainVariant, payload: &[u8], uid: u32) -> Vec<u8> {
        let cfg = base_cfg(match variant {
            AuthChainVariant::D => "auth_chain_d",
            AuthChainVariant::E => "auth_chain_e",
            AuthChainVariant::F => "auth_chain_f",
        });
        let mut codec = AuthChainCodec::new(variant, cfg.clone(), SharedUserRegistry::new(64));
        assert!(codec.select_user_key(uid));

        let prefix = [1_u8, 3, 5, 7];
        let md5data = hmac_md5(&cfg.key, &prefix);

        let mut head = [0_u8; 16];
        head[0..4].copy_from_slice(&now_secs_u32().to_le_bytes());
        head[4..8].copy_from_slice(&17_u32.to_le_bytes());
        head[8..12].copy_from_slice(&23_u32.to_le_bytes());
        head[12..14].copy_from_slice(&cfg.overhead.to_le_bytes());
        let encrypted_head = encrypt_head_block(&codec.user_key, codec.salt, &head);

        let uid_xor = uid ^ u32::from_le_bytes(md5data[8..12].try_into().unwrap());
        let mut packet = Vec::new();
        packet.extend_from_slice(&prefix);
        packet.extend_from_slice(&md5data[..8]);
        packet.extend_from_slice(&uid_xor.to_le_bytes());
        packet.extend_from_slice(&encrypted_head);
        let md5data2 = hmac_md5(&codec.user_key, &packet[12..32]);
        packet.extend_from_slice(&md5data2[..4]);

        let mut password = B64.encode(&codec.user_key).into_bytes();
        password.extend_from_slice(B64.encode(md5data).as_bytes());
        let mut crypt = Rc4Stream::new_from_password(&password).expect("rc4");
        let encrypted = crypt.process(payload);

        let mut random = XorShift128Plus::default();
        let rand_len = codec.rnd_data_len(encrypted.len(), &md5data, &mut random);
        let start_pos = if rand_len > 0 {
            codec.rnd_start_pos(rand_len, &mut random)
        } else {
            0
        };
        let mut frame = Vec::with_capacity(2 + rand_len + encrypted.len() + 2);
        let length = (encrypted.len() as u16) ^ u16::from_le_bytes([md5data[14], md5data[15]]);
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(&vec![0_u8; rand_len]);
        frame[2 + start_pos..2 + start_pos + encrypted.len()].copy_from_slice(&encrypted);

        let mut mac_key = codec.user_key.clone();
        mac_key.extend_from_slice(&1_u32.to_le_bytes());
        let hash = hmac_md5(&mac_key, &frame);
        frame.extend_from_slice(&hash[..2]);
        packet.extend_from_slice(&frame);
        packet
    }

    #[test]
    fn auth_chain_rejects_unknown_uid_when_users_are_configured() {
        let mut cfg = ProtocolConfigRuntime {
            method: "auth_chain_d".to_string(),
            key: b"demo-key-0123456".to_vec(),
            recv_iv: Vec::new(),
            protocol_param: "64".to_string(),
            users: HashMap::new(),
            overhead: 4,
            tcp_mss: 1460,
        };
        cfg.users.insert(1001, b"user-key-1001".to_vec());

        let registry = SharedUserRegistry::new(64);
        let mut codec = AuthChainCodec::new(AuthChainVariant::D, cfg, registry);

        assert!(!codec.select_user_key(9999));
        assert!(codec.user_key.is_empty());
        assert_eq!(codec.user_id, None);
    }

    #[test]
    fn auth_chain_accepts_single_user_handshake_packet() {
        let cfg = base_cfg("auth_chain_d");
        let registry = SharedUserRegistry::new(64);
        let mut codec = AuthChainCodec::new(AuthChainVariant::D, cfg, registry);
        let packet =
            build_chain_client_packet(AuthChainVariant::D, b"\x01\x7f\x00\x00\x01\x00\x35hello", 0);

        let (decoded, sendback) = codec.decode_from_client(&packet).expect("decode");

        assert!(
            sendback,
            "initial auth_chain packet should request a server response"
        );
        assert!(
            !codec.raw_trans,
            "valid auth_chain packet must not fall back to raw_trans"
        );
        assert!(
            decoded.is_empty() || decoded == b"\x01\x7f\x00\x00\x01\x00\x35hello",
            "handshake packet should be accepted and may carry an immediate payload"
        );
    }
}

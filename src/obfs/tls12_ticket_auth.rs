use crate::common::{PrefixBuffer, int32, now_secs_u32};
use crate::crypto::hmac_sha1;
use crate::obfs::ObfsCodec;
use crate::state::TimedReplaySet;
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use rand::{Rng, RngExt, rng};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum FirstPacketError {
    #[error("plain tls client hello detected")]
    PlainTlsClientHello,
    #[error("invalid first packet")]
    DropConnection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlsClientHelloState {
    Incomplete,
    Valid,
    Invalid,
}

fn classify_tls_client_hello_record(data: &[u8]) -> TlsClientHelloState {
    if data.len() < 5 {
        return TlsClientHelloState::Incomplete;
    }
    if data[0] != 0x16 || data[1] != 0x03 || data[2] > 0x04 {
        return TlsClientHelloState::Invalid;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if record_len == 0 || record_len > 16 * 1024 {
        return TlsClientHelloState::Invalid;
    }
    if data.len() < record_len + 5 {
        return TlsClientHelloState::Incomplete;
    }

    let record = &data[5..5 + record_len];
    if record.len() < 4 || record[0] != 0x01 {
        return TlsClientHelloState::Invalid;
    }

    let hello_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    if hello_len + 4 != record.len() {
        return TlsClientHelloState::Invalid;
    }

    let body = &record[4..];
    let mut p = 0;
    if body.len() < 2 + 32 + 1 {
        return TlsClientHelloState::Invalid;
    }
    p += 2 + 32;

    let session_id_len = body[p] as usize;
    p += 1;
    if session_id_len > 32 || body.len() < p + session_id_len + 2 {
        return TlsClientHelloState::Invalid;
    }
    p += session_id_len;

    let cipher_suites_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if cipher_suites_len == 0
        || !cipher_suites_len.is_multiple_of(2)
        || body.len() < p + cipher_suites_len + 1
    {
        return TlsClientHelloState::Invalid;
    }
    p += cipher_suites_len;

    let compression_methods_len = body[p] as usize;
    p += 1;
    if compression_methods_len == 0 || body.len() < p + compression_methods_len {
        return TlsClientHelloState::Invalid;
    }
    p += compression_methods_len;

    if body.len() == p {
        return TlsClientHelloState::Valid;
    }
    if body.len() < p + 2 {
        return TlsClientHelloState::Invalid;
    }

    let extensions_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if body.len() != p + extensions_len {
        return TlsClientHelloState::Invalid;
    }

    TlsClientHelloState::Valid
}

#[derive(Clone)]
pub struct TlsTicketAuthShared {
    replay: Arc<Mutex<TimedReplaySet>>,
    pub startup_time: u32,
}

impl TlsTicketAuthShared {
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            replay: Arc::new(Mutex::new(TimedReplaySet::with_capacity(
                Duration::from_secs(60 * 5),
                max_entries,
            ))),
            startup_time: now_secs_u32().saturating_sub(60 * 30),
        }
    }

    pub fn insert_verify_id_unique(&self, key: &[u8]) -> bool {
        self.replay.lock().insert_unique(key)
    }
}

pub struct TlsTicketAuth {
    method: String,
    key: Vec<u8>,
    obfs_param: String,
    handshake_status: i32,
    recv_buffer: PrefixBuffer,
    client_id: Vec<u8>,
    max_time_dif: i32,
    tls_version: [u8; 2],
    shared: TlsTicketAuthShared,
}

impl TlsTicketAuth {
    pub fn new(
        method: &str,
        key: Vec<u8>,
        obfs_param: String,
        shared: TlsTicketAuthShared,
    ) -> Self {
        Self {
            method: method.to_string(),
            key,
            obfs_param,
            handshake_status: 0,
            recv_buffer: PrefixBuffer::new(),
            client_id: Vec::new(),
            max_time_dif: 60 * 60 * 24,
            tls_version: [0x03, 0x03],
            shared,
        }
    }

    fn match_begin(data: &[u8], prefix: &[u8]) -> bool {
        data.len() >= prefix.len() && &data[..prefix.len()] == prefix
    }

    fn pack_auth_data(&self, client_id: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(32);
        let utc = now_secs_u32();
        data.extend_from_slice(&utc.to_be_bytes());
        let mut rand = [0_u8; 18];
        rng().fill(&mut rand);
        data.extend_from_slice(&rand);

        let mut mac_key = self.key.clone();
        mac_key.extend_from_slice(client_id);
        let h = hmac_sha1(&mac_key, &data);
        data.extend_from_slice(&h[..10]);
        data
    }

    fn encode_app_data_records_into(&self, mut buf: &[u8], out: &mut Vec<u8>) {
        out.clear();
        let mut rng = rng();
        while buf.len() > 2048 {
            let r = (rng.next_u32() as usize % 4096) + 100;
            let size = r.min(buf.len());
            out.push(0x17);
            out.extend_from_slice(&self.tls_version);
            out.extend_from_slice(&(size as u16).to_be_bytes());
            out.extend_from_slice(&buf[..size]);
            buf = &buf[size..];
        }
        if !buf.is_empty() {
            out.push(0x17);
            out.extend_from_slice(&self.tls_version);
            out.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            out.extend_from_slice(buf);
        }
    }

    fn server_hello_extensions(send_ticket: bool) -> Vec<u8> {
        let mut extensions = Vec::with_capacity(if send_ticket { 13 } else { 9 });
        extensions.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        if send_ticket {
            extensions.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);
        }
        extensions
    }

    fn encode_new_session_ticket_record(&self, ticket: &[u8], lifetime_hint: u32) -> Vec<u8> {
        let body_len = 4 + 2 + ticket.len();
        let mut out = Vec::with_capacity(5 + 4 + body_len);
        out.push(0x16);
        out.extend_from_slice(&self.tls_version);
        out.extend_from_slice(&((4 + body_len) as u16).to_be_bytes());
        out.push(0x04);
        out.push(((body_len >> 16) & 0xff) as u8);
        out.push(((body_len >> 8) & 0xff) as u8);
        out.push((body_len & 0xff) as u8);
        out.extend_from_slice(&lifetime_hint.to_be_bytes());
        out.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        out.extend_from_slice(ticket);
        out
    }
}

impl ObfsCodec for TlsTicketAuth {
    fn decode_from_client(&mut self, input: &[u8]) -> Result<(Vec<u8>, bool, bool)> {
        let mut out = Vec::new();
        let (need_decrypt, sendback) = self.decode_from_client_into(input, &mut out)?;
        Ok((out, need_decrypt, sendback))
    }

    fn decode_from_client_into(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(bool, bool)> {
        if self.handshake_status == -1 {
            out.clear();
            out.extend_from_slice(input);
            return Ok((true, false));
        }

        if (self.handshake_status & 4) == 4 {
            self.recv_buffer.extend_from_slice(input);
            out.clear();
            loop {
                if self.recv_buffer.len() <= 5 {
                    break;
                }
                if self.recv_buffer[0] != 0x17
                    || self.recv_buffer[1] != 0x03
                    || self.recv_buffer[2] != 0x03
                {
                    return Err(anyhow!("tls appdata decode error"));
                }
                let size = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;
                if self.recv_buffer.len() < size + 5 {
                    break;
                }
                out.extend_from_slice(&self.recv_buffer[5..5 + size]);
                self.recv_buffer.consume(size + 5);
            }
            return Ok((true, false));
        }

        if (self.handshake_status & 1) == 1 {
            self.recv_buffer.extend_from_slice(input);
            let verify = self.recv_buffer.clone();
            if verify.len() < 11 {
                out.clear();
                return Ok((false, false));
            }

            let ccs = [
                0x14,
                self.tls_version[0],
                self.tls_version[1],
                0x00,
                0x01,
                0x01,
            ];
            if !Self::match_begin(&verify, &ccs) {
                warn!("tls ticket auth missing ChangeCipherSpec");
                return Err(anyhow!("tls missing ChangeCipherSpec"));
            }
            let rest = &verify[6..];
            let finished_head = [0x16, self.tls_version[0], self.tls_version[1], 0x00];
            if !Self::match_begin(rest, &finished_head) {
                warn!("tls ticket auth missing Finished record");
                return Err(anyhow!("tls missing Finished"));
            }
            if rest.len() < 5 {
                out.clear();
                return Ok((false, false));
            }
            let verify_len = u16::from_be_bytes([rest[3], rest[4]]) as usize + 1;
            if verify.len() < verify_len + 10 {
                out.clear();
                return Ok((false, false));
            }

            let mut mac_key = self.key.clone();
            mac_key.extend_from_slice(&self.client_id);
            let h = hmac_sha1(&mac_key, &verify[..verify_len]);
            if h[..10] != verify[verify_len..verify_len + 10] {
                warn!("tls ticket auth Finished HMAC mismatch");
                return Err(anyhow!("tls finished hmac mismatch"));
            }

            self.recv_buffer = verify[verify_len + 10..].to_vec().into();
            self.handshake_status |= 4;
            return self.decode_from_client_into(&[], out);
        }

        self.recv_buffer.extend_from_slice(input);
        let first_packet = self.recv_buffer.clone();
        match classify_tls_client_hello_record(&self.recv_buffer) {
            TlsClientHelloState::Incomplete => {
                out.clear();
                return Ok((false, false));
            }
            TlsClientHelloState::Invalid => {
                warn!(
                    method = %self.method,
                    frame_len = first_packet.len(),
                    "dropping invalid non-TLS first packet"
                );
                return Err(FirstPacketError::DropConnection.into());
            }
            TlsClientHelloState::Valid => {}
        }

        if !Self::match_begin(&self.recv_buffer, &[0x16, 0x03, 0x01]) {
            warn!(
                method = %self.method,
                frame_len = first_packet.len(),
                "plain TLS ClientHello detected on SSR port"
            );
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }

        let header_len = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;

        let frame = self.recv_buffer[5..5 + header_len].to_vec();
        self.recv_buffer.consume(5 + header_len);
        self.handshake_status = 1;

        if frame.len() < 2 || !Self::match_begin(&frame, &[0x01, 0x00]) {
            warn!("plain TLS ClientHello failed SSR handshake-type check");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }
        if frame.len() < 4 {
            out.clear();
            return Ok((false, false));
        }
        let total_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        if total_len != frame.len().saturating_sub(4) {
            warn!("plain TLS ClientHello failed SSR length check");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }
        let mut p = 4;
        if frame.len() < p + 2 || !Self::match_begin(&frame[p..], &self.tls_version) {
            warn!("plain TLS ClientHello failed SSR version check");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }
        p += 2;

        if frame.len() < p + 32 {
            warn!("plain TLS ClientHello failed SSR verifyid length check");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }
        let verifyid = &frame[p..p + 32];
        p += 32;

        if frame.len() < p + 1 {
            warn!("plain TLS ClientHello failed SSR session id length check");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }
        let session_id_len = frame[p] as usize;
        p += 1;
        if session_id_len < 32 || frame.len() < p + session_id_len {
            warn!("plain TLS ClientHello failed SSR session id bounds check");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }

        let sessionid = &frame[p..p + session_id_len];
        self.client_id = sessionid.to_vec();

        let mut mac_key = self.key.clone();
        mac_key.extend_from_slice(sessionid);
        let sha1 = hmac_sha1(&mac_key, &verifyid[..22]);
        if sha1[..10] != verifyid[22..32] {
            warn!("plain TLS ClientHello failed SSR verifyid HMAC check");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }

        let utc_time = u32::from_be_bytes([verifyid[0], verifyid[1], verifyid[2], verifyid[3]]);
        if !self.obfs_param.trim().is_empty() {
            if let Ok(v) = self.obfs_param.trim().parse::<i32>() {
                self.max_time_dif = v;
            }
        }
        let now = now_secs_u32();
        let time_dif = int32(now as i64 - utc_time as i64);
        let startup_dif = int32(utc_time as i64 - self.shared.startup_time as i64);
        if self.max_time_dif > 0
            && (time_dif < -self.max_time_dif
                || time_dif > self.max_time_dif
                || startup_dif < -(self.max_time_dif / 2))
        {
            warn!(
                time_dif,
                startup_dif,
                max_time_dif = self.max_time_dif,
                "tls ticket auth timestamp check failed"
            );
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }

        if !self.shared.insert_verify_id_unique(&verifyid[..22]) {
            warn!("tls ticket auth replay check failed");
            return Err(FirstPacketError::PlainTlsClientHello.into());
        }

        if self.recv_buffer.len() >= 11 {
            let (need_decrypt, sendback) = self.decode_from_client_into(&[], out)?;
            debug_assert!(need_decrypt);
            debug_assert!(!sendback);
            return Ok((true, true));
        }

        out.clear();
        Ok((false, true))
    }

    fn encode_to_client(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_to_client_into(input, &mut out)?;
        Ok(out)
    }

    fn encode_to_client_into(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.handshake_status == -1 {
            out.clear();
            out.extend_from_slice(input);
            return Ok(());
        }
        if (self.handshake_status & 8) == 8 {
            self.encode_app_data_records_into(input, out);
            return Ok(());
        }

        self.handshake_status |= 8;
        let mut rng = rng();
        let send_ticket = rng.next_u32().is_multiple_of(9);
        let (cipher_suite, finish_len) = if rng.next_u32() & 1 == 0 {
            ([0xc0, 0x2f], 40_u16)
        } else {
            ([0xcc, 0xa8], 32_u16)
        };
        let hello_extensions = Self::server_hello_extensions(send_ticket);

        let mut data = Vec::new();
        data.extend_from_slice(&self.tls_version);
        data.extend_from_slice(&self.pack_auth_data(&self.client_id));
        data.push(0x20);
        data.extend_from_slice(&self.client_id);
        data.extend_from_slice(&cipher_suite);
        data.push(0x00);
        data.extend_from_slice(&(hello_extensions.len() as u16).to_be_bytes());
        data.extend_from_slice(&hello_extensions);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x02, 0x00]);
        hello.extend_from_slice(&(data.len() as u16).to_be_bytes());
        hello.extend_from_slice(&data);

        out.clear();
        out.push(0x16);
        out.extend_from_slice(&self.tls_version);
        out.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        out.extend_from_slice(&hello);

        if send_ticket {
            let ticket_len = ((rng.next_u32() as usize % 164) * 2) + 64;
            let mut ticket = vec![0_u8; ticket_len];
            rng.fill_bytes(&mut ticket);
            out.extend_from_slice(&self.encode_new_session_ticket_record(&ticket, 12 * 60 * 60));
        }

        out.extend_from_slice(&[
            0x14,
            self.tls_version[0],
            self.tls_version[1],
            0x00,
            0x01,
            0x01,
        ]);
        out.push(0x16);
        out.extend_from_slice(&self.tls_version);
        out.extend_from_slice(&finish_len.to_be_bytes());

        let mut finish = vec![0_u8; finish_len as usize - 10];
        rng.fill_bytes(&mut finish);
        out.extend_from_slice(&finish);

        let mut mac_key = self.key.clone();
        mac_key.extend_from_slice(&self.client_id);
        let h = hmac_sha1(&mac_key, &out);
        out.extend_from_slice(&h[..10]);

        if !input.is_empty() {
            let mut records = Vec::new();
            self.encode_app_data_records_into(input, &mut records);
            out.extend_from_slice(&records);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        TlsClientHelloState, TlsTicketAuth, TlsTicketAuthShared, classify_tls_client_hello_record,
    };
    use crate::crypto::hmac_sha1;
    use crate::obfs::ObfsCodec;

    #[derive(Clone, Copy)]
    struct FlightInfo {
        has_ticket: bool,
        cipher_suite: [u8; 2],
    }

    fn parse_tls_records(mut data: &[u8]) -> Vec<(u8, &[u8])> {
        let mut records = Vec::new();
        while !data.is_empty() {
            assert!(data.len() >= 5);
            let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
            assert!(data.len() >= 5 + record_len);
            records.push((data[0], &data[5..5 + record_len]));
            data = &data[5 + record_len..];
        }
        records
    }

    fn parse_handshake_message(record_payload: &[u8], expected_type: u8) -> &[u8] {
        assert!(record_payload.len() >= 4);
        assert_eq!(record_payload[0], expected_type);
        let body_len = ((record_payload[1] as usize) << 16)
            | ((record_payload[2] as usize) << 8)
            | record_payload[3] as usize;
        assert_eq!(record_payload.len(), body_len + 4);
        &record_payload[4..]
    }

    fn parse_extension_ids(mut extensions: &[u8]) -> Vec<u16> {
        let mut ids = Vec::new();
        while !extensions.is_empty() {
            assert!(extensions.len() >= 4);
            let ext_id = u16::from_be_bytes([extensions[0], extensions[1]]);
            let ext_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
            assert!(extensions.len() >= 4 + ext_len);
            ids.push(ext_id);
            extensions = &extensions[4 + ext_len..];
        }
        ids
    }

    fn inspect_server_flight(out: &[u8], client_id: &[u8]) -> FlightInfo {
        let records = parse_tls_records(out);
        assert!(records.len() >= 3);

        assert_eq!(records[0].0, 0x16);
        let hello = parse_handshake_message(records[0].1, 0x02);
        assert!(hello.len() >= 2 + 32 + 1 + client_id.len() + 2 + 1 + 2);
        assert_eq!(&hello[..2], &[0x03, 0x03]);

        let mut p = 2 + 32;
        let session_id_len = hello[p] as usize;
        p += 1;
        assert_eq!(session_id_len, client_id.len());
        assert_eq!(&hello[p..p + session_id_len], client_id);
        p += session_id_len;

        let cipher_suite = [hello[p], hello[p + 1]];
        p += 2;
        assert_eq!(hello[p], 0x00);
        p += 1;

        let extensions_len = u16::from_be_bytes([hello[p], hello[p + 1]]) as usize;
        p += 2;
        assert_eq!(hello.len(), p + extensions_len);
        let extension_ids = parse_extension_ids(&hello[p..]);
        assert!(extension_ids.contains(&0xff01));
        assert!(extension_ids.contains(&0x0017));

        let mut next_record = 1;
        let mut has_ticket = false;
        if next_record < records.len()
            && records[next_record].0 == 0x16
            && !records[next_record].1.is_empty()
            && records[next_record].1[0] == 0x04
        {
            has_ticket = true;
            let ticket = parse_handshake_message(records[next_record].1, 0x04);
            assert!(ticket.len() >= 6);
            assert_eq!(
                u32::from_be_bytes([ticket[0], ticket[1], ticket[2], ticket[3]]),
                12 * 60 * 60
            );
            let ticket_len = u16::from_be_bytes([ticket[4], ticket[5]]) as usize;
            assert_eq!(ticket.len(), 6 + ticket_len);
            assert!(extension_ids.contains(&0x0023));
            next_record += 1;
        }
        if !has_ticket {
            assert!(!extension_ids.contains(&0x0023));
        }

        assert!(records.len() > next_record + 1);
        assert_eq!(records[next_record].0, 0x14);
        assert_eq!(records[next_record].1, &[0x01]);
        next_record += 1;

        assert_eq!(records[next_record].0, 0x16);
        match cipher_suite {
            [0xc0, 0x2f] => assert_eq!(records[next_record].1.len(), 40),
            [0xcc, 0xa8] => assert_eq!(records[next_record].1.len(), 32),
            other => panic!("unexpected cipher suite: {:02x?}", other),
        }

        FlightInfo {
            has_ticket,
            cipher_suite,
        }
    }

    fn make_tls_ticket_auth(client_id: Vec<u8>) -> TlsTicketAuth {
        let mut auth = TlsTicketAuth::new(
            "tls1.2_ticket_auth",
            b"0123456789abcdef".to_vec(),
            String::new(),
            TlsTicketAuthShared::with_capacity(32),
        );
        auth.client_id = client_id;
        auth
    }

    fn minimal_tls_client_hello(record_version: [u8; 2]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x00]);

        let mut out = Vec::new();
        out.push(0x16);
        out.extend_from_slice(&record_version);
        out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        out.push(0x01);
        out.extend_from_slice(&[0x00, 0x00, body.len() as u8]);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn classifies_complete_tls_client_hello() {
        let hello = minimal_tls_client_hello([0x03, 0x03]);
        assert_eq!(
            classify_tls_client_hello_record(&hello),
            TlsClientHelloState::Valid
        );
    }

    #[test]
    fn classifies_incomplete_tls_client_hello() {
        let mut hello = minimal_tls_client_hello([0x03, 0x03]);
        hello.truncate(12);
        assert_eq!(
            classify_tls_client_hello_record(&hello),
            TlsClientHelloState::Incomplete
        );
    }

    #[test]
    fn rejects_non_tls_first_packet() {
        assert_eq!(
            classify_tls_client_hello_record(b"GET / HTTP/1.1\r\n"),
            TlsClientHelloState::Invalid
        );
    }

    #[test]
    fn tls_ticket_auth_shared_rejects_duplicate_verify_id() {
        let shared = TlsTicketAuthShared::with_capacity(8);
        let verify_id = b"verify-id";

        assert!(shared.insert_verify_id_unique(verify_id));
        assert!(!shared.insert_verify_id_unique(verify_id));
    }

    #[test]
    fn buffers_short_client_finished_fragments() {
        let client_id = vec![0x5a; 32];
        let mut auth = make_tls_ticket_auth(client_id);
        auth.handshake_status = 1;

        let partial = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00];
        let (data, consumed, need_decode) = auth
            .decode_from_client(&partial)
            .expect("partial client finished");

        assert!(data.is_empty());
        assert!(!consumed);
        assert!(!need_decode);
        assert_eq!(auth.recv_buffer.len(), partial.len());
        assert_eq!(auth.handshake_status, 1);
    }

    #[test]
    fn server_flight_is_structurally_self_consistent() {
        let client_id = vec![0x5a; 32];
        let mut saw_gcm = false;
        let mut saw_chacha = false;
        let mut saw_ticket = false;

        for _ in 0..256 {
            let mut auth = make_tls_ticket_auth(client_id.clone());
            let out = auth.encode_to_client(&[]).expect("server flight");
            let info = inspect_server_flight(&out, &client_id);

            match info.cipher_suite {
                [0xc0, 0x2f] => saw_gcm = true,
                [0xcc, 0xa8] => saw_chacha = true,
                _ => {}
            }
            if info.has_ticket {
                saw_ticket = true;
            }

            let mut mac_key = b"0123456789abcdef".to_vec();
            mac_key.extend_from_slice(&client_id);
            let h = hmac_sha1(&mac_key, &out[..out.len() - 10]);
            assert_eq!(&h[..10], &out[out.len() - 10..]);
        }

        assert!(saw_gcm);
        assert!(saw_chacha);
        assert!(saw_ticket);
    }
}

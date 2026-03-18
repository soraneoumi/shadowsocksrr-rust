use anyhow::Result;

pub mod tls12_ticket_auth;

pub trait ObfsCodec: Send {
    fn decode_from_client(&mut self, input: &[u8]) -> Result<(Vec<u8>, bool, bool)>;
    fn decode_from_client_into(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(bool, bool)> {
        let (decoded, need_decrypt, sendback) = self.decode_from_client(input)?;
        out.clear();
        out.extend_from_slice(&decoded);
        Ok((need_decrypt, sendback))
    }
    fn encode_to_client(&mut self, input: &[u8]) -> Result<Vec<u8>>;
    fn encode_to_client_into(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let encoded = self.encode_to_client(input)?;
        out.clear();
        out.extend_from_slice(&encoded);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ObfsCodec;
    use anyhow::Result;

    struct DummyObfs;

    impl ObfsCodec for DummyObfs {
        fn decode_from_client(&mut self, input: &[u8]) -> Result<(Vec<u8>, bool, bool)> {
            Ok((
                input.iter().map(|b| b.to_ascii_uppercase()).collect(),
                true,
                false,
            ))
        }

        fn encode_to_client(&mut self, input: &[u8]) -> Result<Vec<u8>> {
            Ok(input.to_vec())
        }
    }

    #[test]
    fn obfs_decode_into_overwrites_previous_output() {
        let mut codec = DummyObfs;
        let mut out = b"stale-bytes".to_vec();

        let (need_decrypt, sendback) = codec
            .decode_from_client_into(b"abc", &mut out)
            .expect("decode should succeed");

        assert!(need_decrypt);
        assert!(!sendback);
        assert_eq!(out, b"ABC");
    }
}

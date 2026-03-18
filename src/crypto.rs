use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use anyhow::{Result, anyhow};
use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rc4::consts::U16;
use rc4::{Rc4, StreamCipher as _};
use sha1::Sha1;

pub fn evp_bytes_to_key(password: &[u8], key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut blocks: Vec<u8> = Vec::new();
    let mut prev: Vec<u8> = Vec::new();

    while blocks.len() < key_len + iv_len {
        let mut hasher = Md5::new();
        if !prev.is_empty() {
            hasher.update(&prev);
        }
        hasher.update(password);
        prev = hasher.finalize().to_vec();
        blocks.extend_from_slice(&prev);
    }

    let key = blocks[..key_len].to_vec();
    let iv = blocks[key_len..key_len + iv_len].to_vec();
    (key, iv)
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    type HmacMd5 = Hmac<Md5>;
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("hmac md5 key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0_u8; 16];
    arr.copy_from_slice(&out);
    arr
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("hmac sha1 key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0_u8; 20];
    arr.copy_from_slice(&out);
    arr
}

pub fn aes128_cbc_decrypt_no_padding(
    password: &[u8],
    iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return Err(anyhow!(
            "aes128 cbc no padding input must be 16-byte aligned"
        ));
    }
    let (key, _) = evp_bytes_to_key(password, 16, 16);
    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let mut prev = *iv;
    let mut out = vec![0_u8; data.len()];
    for (in_chunk, out_chunk) in data.chunks(16).zip(out.chunks_mut(16)) {
        let mut ga = GenericArray::clone_from_slice(in_chunk);
        cipher.decrypt_block(&mut ga);
        for i in 0..16 {
            out_chunk[i] = ga[i] ^ prev[i];
        }
        prev.copy_from_slice(in_chunk);
    }
    Ok(out)
}

pub struct Rc4Stream {
    inner: Rc4<U16>,
}

impl Rc4Stream {
    pub fn new_from_password(password: &[u8]) -> Result<Self> {
        let (key, _) = evp_bytes_to_key(password, 16, 0);
        let inner = Rc4::<U16>::new_from_slice(&key).map_err(|_| anyhow!("invalid rc4 key"))?;
        Ok(Self { inner })
    }

    pub fn process(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        self.inner.apply_keystream(&mut out);
        out
    }
}

pub struct ChaCha20Stream {
    inner: ChaCha20Legacy,
}

impl ChaCha20Stream {
    pub fn new_from_password(password: &[u8], nonce: &[u8]) -> Result<Self> {
        if nonce.len() != 8 {
            return Err(anyhow!("chacha20 legacy nonce must be 8 bytes"));
        }
        let (key, _) = evp_bytes_to_key(password, 32, 8);
        let inner = ChaCha20Legacy::new_from_slices(&key, nonce)
            .map_err(|_| anyhow!("invalid chacha20 key or nonce"))?;
        Ok(Self { inner })
    }

    pub fn process(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        self.inner.apply_keystream(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{ChaCha20Stream, Rc4Stream, evp_bytes_to_key};

    #[test]
    fn evp_bytes_to_key_is_deterministic() {
        let first = evp_bytes_to_key(b"demo-password", 16, 16);
        let second = evp_bytes_to_key(b"demo-password", 16, 16);
        assert_eq!(first, second);
        assert_eq!(first.0.len(), 16);
        assert_eq!(first.1.len(), 16);
    }

    #[test]
    fn stream_cipher_chunking_matches_single_pass() {
        let plaintext = b"chunked stream cipher plaintext";

        let mut rc4_full = Rc4Stream::new_from_password(b"stream-key").expect("rc4");
        let full_rc4 = rc4_full.process(plaintext);
        let mut rc4_chunked = Rc4Stream::new_from_password(b"stream-key").expect("rc4");
        let mut chunked_rc4 = rc4_chunked.process(&plaintext[..10]);
        chunked_rc4.extend_from_slice(&rc4_chunked.process(&plaintext[10..]));
        assert_eq!(full_rc4, chunked_rc4, "rc4 stream position must be stable");

        let nonce = b"12345678";
        let mut chacha_full =
            ChaCha20Stream::new_from_password(b"stream-key", nonce).expect("chacha");
        let full_chacha = chacha_full.process(plaintext);
        let mut chacha_chunked =
            ChaCha20Stream::new_from_password(b"stream-key", nonce).expect("chacha");
        let mut chunked_chacha = chacha_chunked.process(&plaintext[..10]);
        chunked_chacha.extend_from_slice(&chacha_chunked.process(&plaintext[10..]));
        assert_eq!(
            full_chacha, chunked_chacha,
            "chacha20 stream position must be stable"
        );
    }
}

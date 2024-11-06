use std::fs;
use std::io::Read;
use std::path::Path;

use crate::cli::TextSignFormat;
use crate::utils::get_reader;
use anyhow::{Ok, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use super::process_genpass;

pub fn process_encrypt(input: &str, key: &str) -> Result<String> {
    let mut input_reader = get_reader(input)?;
    let mut buf = Vec::new();
    input_reader.read_to_end(&mut buf)?;
    let cipher = ChaCha20Poly1305Cipher::load(key)?;
    cipher.encrypt(&buf)
}

pub fn process_decrypt(input: &str, key: &str) -> Result<String> {
    let mut input_reader = get_reader(input)?;
    let mut buf = Vec::new();
    input_reader.read_to_end(&mut buf)?;
    let buf = buf.trim_ascii_end();
    let cipher = ChaCha20Poly1305Cipher::load(key)?;
    cipher.decrypt(buf)
}

pub fn process_generate_key(format: TextSignFormat) -> Result<Vec<Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> Result<String> {
    let mut input_reader = get_reader(input)?;
    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut input_reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut input_reader)?
        }
    };
    let signed = URL_SAFE_NO_PAD.encode(&signed);
    Ok(signed)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    format: TextSignFormat,
    sig: &str,
) -> Result<bool> {
    let mut input_reader: Box<dyn Read> = get_reader(input)?;
    let signed = URL_SAFE_NO_PAD.decode(sig.as_bytes())?;
    let verify_result = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.verify(&mut input_reader, &signed)?
        }
        TextSignFormat::Ed25519 => {
            let verifyer = Ed25519Verifier::load(key)?;
            verifyer.verify(&mut input_reader, &signed)?
        }
    };
    Ok(verify_result)
}

trait TextSign {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized;
}

trait TextVerify {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

struct Blake3 {
    key: [u8; 32],
}

struct Ed25519Signer {
    key: SigningKey,
}

struct Ed25519Verifier {
    key: VerifyingKey,
}

impl TextSign for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let signature = self.key.clone().sign(&data);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerify for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let sig_64: [u8; 64] = sig.try_into()?;
        let signature = Signature::from_bytes(&sig_64);
        let verify_result = self.key.verify(&data, &signature).is_ok();
        Ok(verify_result)
    }
}

impl TextSign for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        //TODO: improve by perf by reading in chunks
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let hash = blake3::keyed_hash(&self.key, &buf);
        let hash = hash.as_bytes();
        Ok(hash == sig)
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into().unwrap();
        Ok(Self::new(key))
    }
}

impl Ed25519Signer {
    pub fn new(key: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&key);
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into().unwrap();
        Ok(Self::new(key))
    }
}

impl Ed25519Verifier {
    pub fn new(key: [u8; 32]) -> Self {
        let key = VerifyingKey::from_bytes(&key).unwrap();
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into().unwrap();
        Ok(Self::new(key))
    }
}

pub trait KeyGenerator {
    fn generate() -> Result<Vec<Vec<u8>>>;
}

impl KeyGenerator for Blake3 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let key = key.as_bytes().into();
        Ok(vec![key])
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key();
        Ok(vec![sk.to_bytes().to_vec(), pk.to_bytes().to_vec()])
    }
}

struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        let key = Key::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(key);
        Self { cipher }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into().unwrap();
        Ok(Self::new(key))
    }

    pub fn encrypt(&self, input: &[u8]) -> Result<String> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);
        let cipher_result = self.cipher.encrypt(&nonce, input.as_ref());
        match cipher_result {
            std::result::Result::Ok(encrypted) => {
                let mut v = Vec::new();
                v.extend(nonce);
                v.extend(encrypted);
                let ciphertext = URL_SAFE_NO_PAD.encode(v);
                Ok(ciphertext)
            }
            Err(e) => anyhow::bail!("Error encrypting: {}", e),
        }
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<String> {
        let buf = URL_SAFE_NO_PAD.decode(input)?;
        let nonce = &buf[..12];
        let content = &buf[12..];
        let nonce = Nonce::from_slice(nonce);
        let cipher_result = self.cipher.decrypt(nonce, content.as_ref());
        match cipher_result {
            std::result::Result::Ok(decrypted) => {
                let v = String::from_utf8(decrypted)?;
                Ok(v)
            }
            Err(e) => anyhow::bail!("Error decrypting: {}", e),
        }
    }
}

impl KeyLoader for ChaCha20Poly1305Cipher {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_text_blake3_sign_verify() -> anyhow::Result<()> {
        let blake = Blake3::load("fixtures/blake3.key")?;
        let input: &[u8; 5] = b"Hello";
        let mut input = input.as_slice();
        let mut input_for_verify = input;
        let signed = blake.sign(&mut input)?;
        let verify_result = blake.verify(&mut input_for_verify, &signed)?;
        assert!(verify_result);
        Ok(())
    }

    #[test]
    fn test_text_ed25519_sign_verify() -> anyhow::Result<()> {
        let signer = Ed25519Signer::load("fixtures/ed25519.key")?;
        let verifyer = Ed25519Verifier::load("fixtures/ed25519.pub")?;
        let input: &[u8; 5] = b"Hello";
        let mut input = input.as_slice();
        let mut input_for_verify = input;
        let signed = signer.sign(&mut input)?;
        let verify_result = verifyer.verify(&mut input_for_verify, &signed)?;
        assert!(verify_result);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<()> {
        let cipher = ChaCha20Poly1305Cipher::load("fixtures/blake3.key")?;
        let encrypted = cipher.encrypt(b"Hello!")?;
        let decrypted = cipher.decrypt(encrypted.as_bytes())?;
        assert_eq!(&decrypted, "Hello!");
        Ok(())
    }
}

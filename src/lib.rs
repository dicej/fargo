#![deny(warnings)]

use {
    aes_gcm_siv::{
        aead::{Aead, NewAead},
        Aes256GcmSiv, Key, Nonce,
    },
    anyhow::{anyhow, Result},
    hmac::Hmac,
    sha2::Sha256,
};

const PBKDF2_ITERATIONS: u32 = 100_000;

const KEY_SIZE: usize = 32;

pub const NONCE_SIZE: usize = 12;

pub const SALT_SIZE: usize = 20;

fn derive_key(salt: &[u8], password: &str) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];

    pbkdf2::pbkdf2::<Hmac<Sha256>>(salt, password.as_bytes(), PBKDF2_ITERATIONS, &mut key);

    key
}

pub fn decrypt(ciphertext: &[u8], password: &str) -> Result<String> {
    let (nonce, body) = ciphertext.split_at(NONCE_SIZE);
    let (salt, body) = body.split_at(SALT_SIZE);

    Ok(String::from_utf8(
        Aes256GcmSiv::new(Key::from_slice(&derive_key(salt, password)))
            .decrypt(Nonce::from_slice(nonce), body)
            .map_err(|_| anyhow!("decryption failed"))?,
    )?)
}

pub fn encrypt(
    nonce: [u8; NONCE_SIZE],
    plaintext: &str,
    salt: [u8; SALT_SIZE],
    password: &str,
) -> Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(NONCE_SIZE + SALT_SIZE + plaintext.len());

    buffer.extend(&nonce);
    buffer.extend(&salt);
    buffer.extend(
        Aes256GcmSiv::new(Key::from_slice(&derive_key(&salt, password)))
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|_| anyhow!("encryption failed"))?,
    );

    Ok(buffer)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() -> Result<()> {
        let plaintext = r#"
"0 Oysters, come and walk with us!"
   The Walrus did beseech.
"A pleasant walk, a pleasant talk,
   Along the briny beach:
We cannot do with more than four,
   To give a hand to each."
"#;

        let password = "carpenter";

        let nonce = [42u8; NONCE_SIZE];
        let salt = [223u8; SALT_SIZE];

        assert_eq!(
            plaintext,
            &decrypt(&encrypt(nonce, plaintext, salt, password)?, password)?
        );

        Ok(())
    }
}

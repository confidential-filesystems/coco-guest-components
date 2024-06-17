use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kbs_types::{Response, TeePubKey};
use log::{error, info};
use rand::{rngs::OsRng, Rng};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde::Deserialize;
use serde_json::{json, Deserializer, Value};

//
const RSA_ALGORITHM: &str = "RSA1_5";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

//pub(crate) fn jwe(tee_pub_key: TeePubKey, payload_data: Vec<u8>) -> Result<Response> {
pub fn jwe(tee_pub_key: TeePubKey, payload_data: Vec<u8>) -> anyhow::Result<Response> {
    if tee_pub_key.alg != *RSA_ALGORITHM {
        /*raise_error!(Error::JWEFailed(format!(
            "algorithm is not {RSA_ALGORITHM} but {}",
            tee_pub_key.alg
        )));*/
        return Err(anyhow!(
            "algorithm is not {RSA_ALGORITHM} but {}",
            tee_pub_key.alg
        ));
    }

    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let encrypted_payload_data = cipher
        .encrypt(nonce, payload_data.as_slice())
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e:?}"))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_mod)
        .map_err(|e| anyhow!("base64 decode k_mod failed: {e:?}"))?;
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_exp)
        .map_err(|e| anyhow!("base64 decode k_exp failed: {e:?}"))?;
    let e = BigUint::from_bytes_be(&k_exp);

    let rsa_pub_key = RsaPublicKey::new(n, e).map_err(|e| {
        anyhow!(
            "Building RSA key from modulus and exponent failed: {e:?}"
        )
    })?;
    let sym_key: &[u8] = aes_sym_key.as_slice();
    let wrapped_sym_key = rsa_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, sym_key)
        .map_err(|e| anyhow!("RSA encrypt sym key failed: {e:?}"))?;

    let protected_header = json!(
    {
       "alg": RSA_ALGORITHM.to_string(),
       "enc": AES_GCM_256_ALGORITHM.to_string(),
    });

    let protected_json = serde_json::to_string(&protected_header)
        .map_err(|e| anyhow!("serde protected_header failed: {e}"))?;
    let protected = URL_SAFE_NO_PAD.encode(protected_json);
    Ok(Response {
        protected,
        encrypted_key: URL_SAFE_NO_PAD.encode(wrapped_sym_key),
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(encrypted_payload_data),
        tag: "".to_string(),
    })
}
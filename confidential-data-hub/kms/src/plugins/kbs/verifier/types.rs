use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{anyhow, Result};
use jwt_simple::prelude::*;
use serde::{Serialize, Deserialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertTableEntry;
use sha2::{Digest, Sha384};
use plugins::kbs::resource::{Repository, ResourceDesc};
use crate::plugins;

pub type TeeEvidenceParsedClaim = serde_json::Value;

pub const AUTHED_ECSK_RES_FOR_CONTROLLER: &str = "*/ecsk/*";
pub const AUTHED_IPK_RES_FOR_CONTROLLER: &str = "*/ipk/*";
pub const AUTHED_CERT_RES_FOR_CONTROLLER: &str = "*/certs/client";

#[derive(Debug, Serialize, Deserialize)]
pub struct CRPTPayload {
    // iat
    pub authorized_res: Vec<AuthorizedRes>,
    pub runtime_res: HashMap<String, HashMap<String, String>,>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizedRes {
    pub exp: u64,
    pub res: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttReport {
    pub attester: String,
    pub attestation_report: AttestationReport,
    pub cert_chain: Option<Vec<CertTableEntry>>,
}

// RAE
#[derive(Debug, Serialize, Deserialize)]
pub struct RAEvidence {
    pub crp_token: Option<String>,
    pub attestation_reports: Vec<AttReport>,
}

pub fn expected_hash(input: &String) -> [u8; 48] {
    let mut hasher = Sha384::new();

    hasher.update(input.as_bytes());

    let partial_hash = hasher.finalize();

    let mut hash = [0u8; 48];
    hash[..48].copy_from_slice(&partial_hash);

    hash
}

pub fn parse_crptpayload(crp_token: &String) -> Result<CRPTPayload> {
    let token_parts: Vec<&str> = crp_token.split('.').collect();
    if token_parts.len() != 3 {
        return Err(anyhow!("Invalid crp_token!"));
    }

    let payload_part_encoded = token_parts[1];
    let payload_part_decoded = &Base64UrlSafeNoPadding::decode_to_vec(payload_part_encoded.as_bytes(), None);
    return match payload_part_decoded {
        Ok(payload_decoded) => match serde_json::from_slice::<CRPTPayload>(&payload_decoded) {
            Ok(claims) => Ok(claims),
            Err(e) => Err(anyhow!("Error parsing crp_token from decoded payload:\n{}", e)),
        },
        Err(e) => Err(anyhow!("Error decoding crp_token:\n{}", e)),
    }
}

pub async fn verify_crpt(crp_token: &String, repository: &Box<dyn Repository + Send + Sync>) -> Result<CRPTPayload> {
    let metadata = Token::decode_metadata(crp_token.as_ref()).map_err(|_| anyhow!("Invalid crp_token!"))?;
    let kid = metadata.key_id().ok_or(anyhow!("Invalid crp_token! No kid"))?;
    log::info!("ccdata - crp_token: kid = {:?}", kid);
    let kid = kid.to_string().replace("kbs:///", "");
    let parts: Vec<&str> = kid.split('/').filter(|&s| !s.is_empty()).collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid crp_token! Wrong kid"));
    }
    if parts[1] != "ecsk" {
        return Err(anyhow!("Invalid crp_token! Wrong kid: {}", kid));
    }
    let user_addr = parts[0];
    // check res validity
    let crpt_payload = parse_crptpayload(crp_token)?;
    if crpt_payload.authorized_res.is_empty() {
        return Err(anyhow!("Invalid crp_token! Empty authorized res"));
    }
    for auth_res in &crpt_payload.authorized_res {
        let res = auth_res.res.replace("kbs:///", "");
        let res_parts : Vec<_> = res.split('/').filter(|&s| !s.is_empty()).collect();
        if res_parts.len() != 3 {
            return Err(anyhow!("Invalid crp_token! Wrong authorized res"));
        }
        if res_parts[0] != user_addr {
            return Err(anyhow!("Unexpected auth res: {}, should be {}'s", auth_res.res, user_addr));
        }
    }
    for (_, inner_map) in &crpt_payload.runtime_res {
        for key in inner_map.keys() {
            let res = key.replace("kbs:///", "");
            let res_parts : Vec<_> = res.split('/').filter(|&s| !s.is_empty()).collect();
            if res_parts.len() != 3 {
                return Err(anyhow!("Invalid crp_token! Wrong runtime res"));
            }
            if res_parts[0] != user_addr {
                return Err(anyhow!("Unexpected runtime res: {}, should be {}'s", key, user_addr));
            }
        }
    }

    // read user's public key
    let resource_description = ResourceDesc {
        repository_name: user_addr.to_string(),
        resource_type: "ecpk".to_string(), // get pub key
        resource_tag: parts[2].to_string(),
    };
    let pub_key_pem_bytes = repository.read_secret_resource(resource_description)
        .await
        .map_err(|e| anyhow!("Failed to read user {}'s public key: {}", user_addr, e))?;
    let pub_key_pem = std::str::from_utf8(&pub_key_pem_bytes).map_err(|_| anyhow!("Invalid user's public key"))?;
    let public_key = ES256PublicKey::from_pem(pub_key_pem).map_err(|_| anyhow!("Invalid user's public key"))?;
    let claims = public_key
        .verify_token::<CRPTPayload>(crp_token, Some(VerificationOptions::default())).map_err(|_| anyhow!("Invalid crp_token! Verify failed"))?;
    Ok(claims.custom)
}

pub fn default_authed_res_for_controller() -> Vec<AuthorizedRes> {
    return vec![AuthorizedRes {
        exp: 0,
        res: AUTHED_ECSK_RES_FOR_CONTROLLER.to_string(),
    }, AuthorizedRes {
        exp: 0,
        res: AUTHED_IPK_RES_FOR_CONTROLLER.to_string(),
    }, AuthorizedRes {
        exp: 0,
        res: AUTHED_CERT_RES_FOR_CONTROLLER.to_string(),
    }];
}

pub fn authed_res(crpt_payload: &CRPTPayload) -> Vec<String> {
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    crpt_payload.authorized_res.iter()
        .filter(|res| res.exp == 0 || res.exp > current_time)
        .map(|res| res.res.replace("kbs:///", ""))
        .collect()
}

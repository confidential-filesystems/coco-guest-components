// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use jwt_simple::claims::JWTClaims;
use jwt_simple::prelude::{Clock, coarsetime, Duration, Token};
#[allow(unused_imports)]
use jwt_simple::prelude::{
    ES256PublicKey, Ed25519PublicKey, EdDSAPublicKeyLike, ECDSAP256PublicKeyLike, NoCustomClaims, VerificationOptions,
};
use kbs_protocol::{
    client::KbsClient as KbsProtocolClient,
    token_provider::{AATokenProvider, TokenProvider},
    KbsClientCapabilities, ResourceUri,
};
use hex::*;
use jwt_simple::prelude::*;

use crate::{Error, Result};

use super::{get_init_extra_credential, Kbc, verifier};

fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct AuthorizedRes {
    // Time the claims expire at
    #[serde(
        rename = "exp",
        default,
    )]
    pub exp: u64, // Duration, // UnixTimeStamp

    // Resource - This can be set to anything application-specific
    #[serde(rename = "res", default)]
    pub res: String,
}

//#[derive(Debug, Serialize, Deserialize)]
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct CustomClaims {
    // Version - This can be set to anything application-specific
    //#[serde(rename = "svn", default)]
    //pub svn: String,

    // authorized-res
    pub authorized_res: Vec<AuthorizedRes>,

    // runtime-res
    pub runtime_res: HashMap<String, HashMap<String, HashMap<String, String>>>,
}

#[derive(Debug)]
pub struct KBSInfos {
    pub kbs_url: String,
    pub kbs_ld: String,
    pub kbs_is_emulated: bool,
}

pub struct CcKbc {
    client: KbsProtocolClient<Box<dyn TokenProvider>>,
    kbs_infos: KBSInfos,
}

impl CcKbc {
    pub async fn new(kbs_infos: &KBSInfos) -> Result<Self> {
        println!("confilesystem20 println- cdh.kms.CcKbc.new():  kbs_infos.kbs_url = {:?}", kbs_infos.kbs_url);
        println!("confilesystem20 println- cdh.kms.CcKbc.new():  kbs_infos.kbs_ld = {:?}", kbs_infos.kbs_ld);

        let token_provider = AATokenProvider::new()
            .await
            .map_err(|e| Error::KbsClientError(format!("create AA token provider failed: {e}")))?;
        let client = kbs_protocol::KbsClientBuilder::with_token_provider(
            Box::new(token_provider),
            &kbs_infos.kbs_url,
        )
        .build()
        .map_err(|e| Error::KbsClientError(format!("create kbs client failed: {e}")))?;
        Ok(Self {
            client,
            kbs_infos: KBSInfos{
                kbs_url: kbs_infos.kbs_url.clone(),
                kbs_ld: kbs_infos.kbs_ld.clone(),
                kbs_is_emulated: kbs_infos.kbs_is_emulated,
            },
        })
    }

    //
    async fn auth_resource(&mut self, rid: ResourceUri, extra_credential: &attester::extra_credential::ExtraCredential) -> anyhow::Result<attester::extra_credential::ExtraCredential> {
        let mut init_extra_credential = get_init_extra_credential().await?;
        if extra_credential.aa_attester != init_extra_credential.aa_attester {
            return Err(anyhow::anyhow!("aa_attester: {:?} should be {:?}", extra_credential.aa_attester, init_extra_credential.aa_attester));
        }

        init_extra_credential.extra_request = extra_credential.extra_request.clone();
        match extra_credential.aa_attester.as_str() {
            super::ATTESTER_SECURITY => {
                return Ok(init_extra_credential);
            },
            super::ATTESTER_CONTROLLER => {
                return Ok(init_extra_credential);
            },
            super::ATTESTER_METADATA => {},
            super::ATTESTER_WORKLOAD => {},
            _ => {
                return Err(anyhow::anyhow!("aa_attester must be set to security/controller/metadata/workload"));
            },
        }

        // 1. verify jws；
        // 2. path.res in crt.authorized_res
        // 3. path.res in crpt.authorized_res
        // 4. crpt.authorized_res.exp
        let (key_user, claims) = self.verify_crp_token(&extra_credential.controller_crp_token, &init_extra_credential)
            .await?;
        let addr_is_ok = addr_is_ok(&key_user, &rid.repository);
        if !addr_is_ok {
            return Err(anyhow::anyhow!("rid.repository {:?} not key_user {:?}", rid.repository, key_user));
        }
        let  res_id = rid.whole_uri();
        let authorized_res = claims.custom.authorized_res;
        let mut can_get = can_get_res(authorized_res, &res_id);
        if !can_get {
            return Err(anyhow::anyhow!("res_id {:?} not in req.controller_crp_token", res_id));
        }
        let init_authorized_res = parse_crptpayload(&init_extra_credential.controller_crp_token)?;
        can_get = can_get_res(init_authorized_res.authorized_res, &res_id);
        if !can_get {
            return Err(anyhow::anyhow!("res_id {:?} not in init.controller_crp_token", res_id));
        }

        Ok(init_extra_credential)
    }

    async fn verify_crp_token(&mut self, controller_crp_token: &str, extra_credential: &attester::extra_credential::ExtraCredential) -> anyhow::Result<(String, JWTClaims<CustomClaims>)> {
        let metadata = Token::decode_metadata(controller_crp_token)?;
        let kbs_key_path = match metadata.key_id() {
            Some(value) => value,
            _ => return Err(anyhow::anyhow!("no kid in token")),
        };
        println!("confilesystem21 println- verify_crp_token(): kbs_key_path = {:?}", kbs_key_path);
        let key_user = get_addr_from_res_id(kbs_key_path)?;
        let kbs_pub_key_path = kbs_key_path.replace("ecsk", "ecpk");
        println!("confilesystem21 println- verify_crp_token(): kbs_pub_key_path = {:?}", kbs_pub_key_path);

        let resource_uri = ResourceUri::try_from(kbs_pub_key_path.as_str())
            .map_err(|_| anyhow::anyhow!("illegal kbs resource uri: {kbs_pub_key_path}"))?;
        let pubkey_bytes = self
            .client
            .get_resource(resource_uri, &extra_credential)
            .await
            .map_err(|e| Error::KbsClientError(format!("get resource failed: {e}")))?;
        let pubkey_str_got = String::from_utf8_lossy(&pubkey_bytes);
        let pubkey_str = pubkey_str_got.trim_end_matches('\n');
        println!("confilesystem21 println- verify_crp_token(): pubkey_str = {:?}", pubkey_str);
        let claims = verify_token_internal(controller_crp_token, pubkey_str)
            .map_err(|e| anyhow!("confilesystem21 - verify_token_internal failed: {:?}", e))?;
        println!("confilesystem21 println- ExternalExtraData.proc(): verify_token_internal: OK -> claims = {:?}", claims);
        println!("confilesystem21 println- ExternalExtraData.proc(): verify_token_internal: OK -> claims.custom = {:?}", claims.custom);
        println!("confilesystem21 println- ExternalExtraData.proc(): verify_token_internal: OK -> claims.custom.runtime_res = {:?}", claims.custom.runtime_res);
        Ok((key_user, claims))
    }
}

#[async_trait]
impl Kbc for CcKbc {
    async fn get_resource(&mut self, rid: ResourceUri, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        let new_extra_credential = self.auth_resource(rid.clone(), extra_credential)
            .await
            .map_err(|e| Error::KbsClientError(format!("auth resource failed: {e}")))?;

        let secret = self
            .client
            .get_resource(rid, &new_extra_credential)
            .await
            .map_err(|e| Error::KbsClientError(format!("get resource failed: {e}")))?;
        Ok(secret)
    }

    async fn set_resource(&mut self, rid: ResourceUri, content: Vec<u8>) -> Result<Vec<u8>> {
        log::info!("confilesystem20 - cdh.kms.CcKbc.set_resource():  rid = {:?}, content.len() = {:?}",
            rid, content.len());
        println!("confilesystem20 println- cdh.kms.CcKbc.set_resource():  rid = {:?}, content.len() = {:?}",
            rid, content.len());
        slog::info!(sl(), "confilesystem20 slog- cdh.kms.CcKbc.set_resource():  rid = {:?}, content.len() = {:?}",
            rid, content.len());
        println!("confilesystem20 println- cdh.kms.CcKbc.set_resource():  self.kbs_infos.kbs_url = {:?}", self.kbs_infos.kbs_url);
        println!("confilesystem20 println- cdh.kms.CcKbc.set_resource():  self.kbs_infos.kbs_ld = {:?}", self.kbs_infos.kbs_ld);

        let set_rsp = set_resource(&self.kbs_infos.kbs_url, &rid.resource_path(), content, &self.kbs_infos.kbs_ld, self.kbs_infos.kbs_is_emulated)
            .await
            .map_err(|e| Error::SetResourceError(format!("set resource failed: {e}")))?;;

        println!("confilesystem20 println- cdh.kms.CcKbc.set_resource():  set_rsp = {:?}", set_rsp);
        Ok(set_rsp)
    }

    async fn delete_resource(&mut self, rid: ResourceUri, content: Vec<u8>) -> Result<Vec<u8>> {
        println!("confilesystem20 println- cdh.kms.CcKbc.delete_resource():  rid = {:?}, content.len() = {:?}",
                 rid, content.len());
        println!("confilesystem20 println- cdh.kms.CcKbc.delete_resource():  self.kbs_infos.kbs_url = {:?}", self.kbs_infos.kbs_url);
        println!("confilesystem20 println- cdh.kms.CcKbc.delete_resource():  self.kbs_infos.kbs_ld = {:?}", self.kbs_infos.kbs_ld);

        let delete_rsp = delete_resource(&self.kbs_infos.kbs_url, &rid.resource_path(), content, &self.kbs_infos.kbs_ld, self.kbs_infos.kbs_is_emulated)
            .await
            .map_err(|e| Error::DeleteResourceError(format!("delete resource failed: {e}")))?;;

        println!("confilesystem20 println- cdh.kms.CcKbc.delete_resource():  delete_rsp = {:?}", delete_rsp);
        Ok(delete_rsp)
    }
}

// util apis
pub fn parse_crptpayload(crp_token: &str) -> anyhow::Result<CustomClaims> {
    let token_parts: Vec<&str> = crp_token.split('.').collect();
    if token_parts.len() != 3 {
        return Err(anyhow!("Invalid crp_token!"));
    }

    let payload_part_encoded = token_parts[1];
    let payload_part_decoded = &Base64UrlSafeNoPadding::decode_to_vec(payload_part_encoded.as_bytes(), None);
    return match payload_part_decoded {
        Ok(payload_decoded) => match serde_json::from_slice::<CustomClaims>(&payload_decoded) {
            Ok(claims) => Ok(claims),
            Err(e) => Err(anyhow!("Error parsing crp_token from decoded payload:\n{}", e)),
        },
        Err(e) => Err(anyhow!("Error decoding crp_token:\n{}", e)),
    }
}

pub fn verify_token_internal(token: &str, user_public_key_pem: &str) -> anyhow::Result<JWTClaims<CustomClaims>, anyhow::Error> {
    println!("confilesystem20 println- verify_token_internal(): token = {:?}", token);
    println!("confilesystem20 println- verify_token_internal(): user_public_key_pem = {:?}", user_public_key_pem);
    let public_key = ES256PublicKey::from_pem(user_public_key_pem)?; // from_der, from_bytes
    //.expect("confilesystem21 - new pubkey fail");
    println!("confilesystem20 println- verify_token_internal(): public_key = {:?}", public_key);

    let claims = public_key
        .verify_token::<CustomClaims>(token, Some(VerificationOptions::default()))
        .context("confilesystem21 - verify token failed")?;

    println!("confilesystem20 println- verify_token_internal(): claims = {:?}", claims);
    Ok(claims)
}

pub fn get_addr_from_res_id(res_id: &str) -> anyhow::Result<String> {
    let mut new_res_id = res_id.to_string();
    if !res_id.starts_with("kbs://") {
        new_res_id = format!("{}{}", "kbs:///", res_id)
    }

    let path_slices: Vec<&str> = new_res_id.split('/').filter(|&s| !s.is_empty()).collect();
    println!("confilesystem20 println- get_addr_from_res_id(): res_id = {:?} -> new_res_id = {:?} -> path_slices = {:?}",
        res_id, new_res_id, path_slices);
    if path_slices.len() < 2 {
        return Err(anyhow!("confilesystem6 - res kid format error"));
    }
    let addr = path_slices[1];
    Ok(addr.to_string())
}

pub fn can_get_res(authorized_res: Vec<AuthorizedRes>, res_id: &str) -> bool {
    let now = coarsetime::Clock::now_since_epoch().as_secs();
    println!("confilesystem20 println- can_get_res(): res_id = {:?}, authorized_res = {:?}; now = {:?}",
            res_id, authorized_res, now);
    if authorized_res.len() == 0 {
        return true;
    }

    let mut new_res_id = res_id.to_string();
    if !res_id.starts_with("kbs://") {
        new_res_id = format!("{}{}", "kbs:///", res_id)
    }
    println!("confilesystem20 println- can_get_res(): res_id = {:?} -> new_res_id = {:?}", res_id, new_res_id);
    let res_id_slices: Vec<&str> = new_res_id.split('/').filter(|&s| !s.is_empty()).collect();
    if res_id_slices.len() < 4 {
        return false;
    }

    let mut can_get = false;
    for a_res in authorized_res {
        // confilesystem : check pattern *
        if a_res.res == "*"
            || a_res.res == "*/*/*"
            || a_res.res == "*:///*/*/*" {
            return true;
        }

        let a_res_slices: Vec<&str> = (&a_res.res).split('/').filter(|&s| !s.is_empty()).collect();
        if a_res_slices.len() < 4 {
            return false;
        }

        if (a_res_slices[0] == "*:" || a_res_slices[0] == res_id_slices[0]) // "*:///*/*/*"
            && (a_res_slices[1] == "*" || a_res_slices[1] == res_id_slices[1])
            && (a_res_slices[2] == "*" || a_res_slices[2] == res_id_slices[2])
            && (a_res_slices[3] == "*" || a_res_slices[3] == res_id_slices[3]) {
            if a_res.exp > 0 && a_res.exp < now {
                println!("confilesystem20 println- a_res.res = {:?}'s a_res.exp = {:?} < now = {:?}",
                        a_res.res, a_res.exp, now);
                break;
            }
            can_get = true;
            break;
        }
    }
    can_get
}

pub fn addr_is_ok(key_user: &str, addr: &str) -> bool {
    if key_user.len() == 0 || key_user.to_string() == "*".to_string() {
        return true;
    }

    if addr.to_string() != key_user.to_string() {
        println!("confilesystem20 println- addr_is_ok(): addr = {:?} != key_user = {:?}",
                addr.to_string(), key_user.to_string());
        return false;
    }
    return true;
}

// util apis
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand::SeedableRng;
use kbs_types::{Attestation, TeePubKey};
use serde::{Serialize, Deserialize};
//use slog::info;
//use image_rs::extra::token::{AuthorizedRes, CustomClaims};
use crate::plugins::kbs::resource::local_fs::{LocalFsRepoDesc, LocalFs};
//use attestation_service::{config::Config as AsConfig, AttestationService};

const KBS_URL_PREFIX: &str = "kbs/v0";

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceRsp {
    #[serde(rename = "tee-type")]
    pub tee_type: i32,
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeePubKey,
    #[serde(rename = "evidence")]
    pub evidence: Vec<u8>,
}

// let mut args: Vec<String> = vec![];
pub async fn set_resource(
    url: &str,
    path: &str,
    resource_bytes: Vec<u8>,
    kbs_ld: &str,
    kbs_is_emulated: bool,
    //challenge: &str,
    //auth_key: String,
    //kbs_root_certs_pem: Vec<String>,
) -> anyhow::Result<Vec<u8>> {
    println!("confilesystem20 println- set_resource(): url = {:?}", url);
    println!("confilesystem20 println- set_resource(): path = {:?}", path);

    let challenge = gen_challenge();//"123456";
    println!("confilesystem20 println- set_resource(): challenge = {:?}", challenge);
    let kbs_root_certs_pem = vec![];

    let http_client = build_http_client(kbs_root_certs_pem)?;

    // get evidence
    let get_evidence_url = format!("{}/{KBS_URL_PREFIX}/cfs/evidence?challenge={}", url, challenge);
    let get_evidence_response = http_client
        .get(get_evidence_url)
        .send()
        .await?;

    match get_evidence_response.status() {
        reqwest::StatusCode::OK => {

        },
        _ => {
            bail!("Request Failed, Response: {:?}", get_evidence_response.text().await?);
        }
    }

    let cookies = get_evidence_response.cookies();
    let mut last_cookie = "".to_string();
    for cookie in cookies.into_iter() {
        println!("confilesystem20 println- set_resource(): cookie = {:?}", cookie);
        println!("confilesystem20 println- set_resource(): cookie.name() = {:?}, cookie.value() = {:?}",
                 cookie.name(), cookie.value());
        //last_cookie = cookie.value().clone();
        last_cookie = format!("{}={}", cookie.name(), cookie.value());
    }
    println!("confilesystem20 println- set_resource(): last_cookie = {:?}", last_cookie);

    //let rsp = get_evidence_response.text().await?;
    let evidence = get_evidence_response.json::<EvidenceRsp>().await?;
    //println!("set_resource(): kbs_evidence() -> evidence = {:?}", evidence);
    println!("confilesystem20 println- set_resource(): evidence.tee_pubkey = {:?}", evidence.tee_pubkey);
    println!("confilesystem20 println- set_resource(): evidence.tee_type = {:?}", evidence.tee_type);
    println!("confilesystem20 println- set_resource(): kbs_types::Tee::Challenge = {:?}", kbs_types::Tee::Challenge);

    //TODO:  verify evidence
    /*
    let as_config = AsConfig::default();
    let attestation_service_native = AttestationService::new(as_config.clone())?;
    let as_evaluate_rsp = attestation_service_native.evaluate(evidence.tee_type, challenge, evidence.evidence)
        .await?;
    println!("confilesystem20 println- set_resource(): as_evaluate_rsp = {:?}", as_evaluate_rsp);
    */
    let tee_type = i32_to_tee(evidence.tee_type)?;
    let tee_verifier = verifier::to_verifier(&tee_type)?;
    //let attestation = serde_json::from_slice::<Attestation>(evidence.evidence.as_slice())
    //    .context("Failed to deserialize Attestation")?;
    let evidence_string = String::from_utf8(evidence.evidence)?;
    let attestation = Attestation {
        tee_pubkey: evidence.tee_pubkey.clone(),
        tee_evidence: evidence_string,
    };
    //let repository = LocalFs::new(&LocalFsRepoDesc::default())?;
    let repository = Box::new(LocalFs::new(&LocalFsRepoDesc::default())?) as Box<dyn crate::plugins::kbs::resource::Repository + Send + Sync>;
    let evaluate_result = tee_verifier.evaluate(challenge, &attestation, &repository)
        .await
        .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;
    println!("confilesystem20 println- set_resource(): evidence.evaluate_result = {:?}", evaluate_result);

    let jwe = kbs_protocol::jwe::jwe(evidence.tee_pubkey, resource_bytes)?;
    let resource_bytes_ciphertext = serde_json::to_vec(&jwe)?;

    //
    let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", url, path);
    println!("confilesystem20 println- set_resource(): resource_url = {:?}", resource_url);
    let response = http_client
        .post(resource_url)
        .header("Content-Type", "application/octet-stream")
        .header("Cookie", last_cookie)
        //.bearer_auth(token)
        .body(resource_bytes_ciphertext.clone())
        .send()
        .await?;
    println!("confilesystem20 println- set_resource(): response.status() = {:?}", response.status());
    match response.status() {
        reqwest::StatusCode::OK => {
            //let body_bytes = response.bytes().await?;
            Ok(response.bytes().await?.to_vec())
        },
        _ => {
            bail!("Request Failed, Response: {:?}", response.text().await?)
        }
    }
}

pub async fn delete_resource(
    url: &str,
    path: &str,
    resource_bytes: Vec<u8>,
    kbs_ld: &str,
    kbs_is_emulated: bool,
    //challenge: &str,
    //auth_key: String,
    //kbs_root_certs_pem: Vec<String>,
) -> anyhow::Result<Vec<u8>> {
    println!("confilesystem20 println- delete_resource(): url = {:?}", url);
    println!("confilesystem20 println- delete_resource(): path = {:?}", path);

    let challenge = gen_challenge();//"123456";
    println!("confilesystem20 println- delete_resource(): challenge = {:?}", challenge);
    let kbs_root_certs_pem = vec![];

    let http_client = build_http_client(kbs_root_certs_pem)?;

    // get evidence
    let get_evidence_url = format!("{}/{KBS_URL_PREFIX}/cfs/evidence?challenge={}", url, challenge);
    let get_evidence_response = http_client
        .get(get_evidence_url)
        .send()
        .await?;

    match get_evidence_response.status() {
        reqwest::StatusCode::OK => {

        },
        _ => {
            bail!("Request Failed, Response: {:?}", get_evidence_response.text().await?);
        }
    }

    let cookies = get_evidence_response.cookies();
    let mut last_cookie = "".to_string();
    for cookie in cookies.into_iter() {
        //println!("confilesystem20 println- delete_resource(): cookie = {:?}", cookie);
        //println!("confilesystem20 println- delete_resource(): cookie.name() = {:?}, cookie.value() = {:?}",
        //         cookie.name(), cookie.value());
        //last_cookie = cookie.value().clone();
        last_cookie = format!("{}={}", cookie.name(), cookie.value());
    }
    println!("confilesystem20 println- delete_resource(): last_cookie = {:?}", last_cookie);

    //let rsp = get_evidence_response.text().await?;
    let evidence = get_evidence_response.json::<EvidenceRsp>().await?;
    //println!("set_resource(): kbs_evidence() -> evidence = {:?}", evidence);
    println!("confilesystem20 println- delete_resource(): evidence.tee_pubkey = {:?}", evidence.tee_pubkey);
    println!("confilesystem20 println- delete_resource(): evidence.tee_type = {:?}", evidence.tee_type);
    println!("confilesystem20 println- delete_resource(): kbs_types::Tee::Challenge = {:?}", kbs_types::Tee::Challenge);

    //TODO:  verify evidence
    /*
    let as_config = AsConfig::default();
    let attestation_service_native = AttestationService::new(as_config.clone())?;
    let as_evaluate_rsp = attestation_service_native.evaluate(evidence.tee_type, challenge, evidence.evidence)
        .await?;
    println!("confilesystem20 println- delete_resource(): as_evaluate_rsp = {:?}", as_evaluate_rsp);
    */
    let tee_type = i32_to_tee(evidence.tee_type)?;
    let tee_verifier = verifier::to_verifier(&tee_type)?;
    //let attestation = serde_json::from_slice::<Attestation>(evidence.evidence.as_slice())
    //    .context("Failed to deserialize Attestation")?;
    let evidence_string = String::from_utf8(evidence.evidence)?;
    let attestation = Attestation {
        tee_pubkey: evidence.tee_pubkey.clone(),
        tee_evidence: evidence_string,
    };
    //let repository = LocalFs::new(&LocalFsRepoDesc::default())?;
    let repository = Box::new(LocalFs::new(&LocalFsRepoDesc::default())?) as Box<dyn crate::plugins::kbs::resource::Repository + Send + Sync>;
    let evaluate_result = tee_verifier.evaluate(challenge.to_string(), &attestation, &repository)
        .await
        .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;
    println!("confilesystem20 println- delete_resource(): evidence.evaluate_result = {:?}", evaluate_result);

    let jwe = kbs_protocol::jwe::jwe(evidence.tee_pubkey, resource_bytes)?;
    let resource_bytes_ciphertext = serde_json::to_vec(&jwe)?;

    //
    let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", url, path);
    println!("confilesystem20 println- delete_resource(): resource_url = {:?}", resource_url);
    let response = http_client
        .delete(resource_url)
        .header("Content-Type", "application/octet-stream")
        .header("Cookie", last_cookie)
        //.bearer_auth(token)
        .body(resource_bytes_ciphertext.clone())
        .send()
        .await?;
    println!("confilesystem20 println- delete_resource(): response.status() = {:?}", response.status());
    match response.status() {
        reqwest::StatusCode::OK => {
            //let body_bytes = response.bytes().await?;
            Ok(response.bytes().await?.to_vec())
        },
        _ => {
            bail!("Request Failed, Response: {:?}", response.text().await?)
        }
    }
}

fn build_http_client(kbs_root_certs_pem: Vec<String>) -> anyhow::Result<reqwest::Client> {
    let mut client_builder =
        reqwest::Client::builder().user_agent(format!("kbs-client/{}", env!("CARGO_PKG_VERSION")));

    for custom_root_cert in kbs_root_certs_pem.iter() {
        let cert = reqwest::Certificate::from_pem(custom_root_cert.as_bytes())?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    client_builder
        .build()
        .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
}

fn i32_to_tee(tee_i32: i32) -> anyhow::Result<kbs_types::Tee> {
    let tee_type = match tee_i32 {
        0 => { kbs_types::Tee::AzSnpVtpm },
        1 => { kbs_types::Tee::Sev },
        2 => { kbs_types::Tee::Sgx },
        3 => { kbs_types::Tee::Snp },
        4 => { kbs_types::Tee::Tdx },
        5 => { kbs_types::Tee::Cca },
        6 => { kbs_types::Tee::Csv },
        7 => { kbs_types::Tee::Sample },
        8 => { kbs_types::Tee::Challenge },
        _ => { return Err(bail!("tee type error: {:?}", tee_i32)); }
    };

    Ok(tee_type)
}

fn gen_challenge() -> String {
    let random_string: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(10)
        .map(char::from)
        .collect::<String>();
    random_string
}
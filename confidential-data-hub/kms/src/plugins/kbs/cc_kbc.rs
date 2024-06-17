// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use kbs_protocol::{
    client::KbsClient as KbsProtocolClient,
    token_provider::{AATokenProvider, TokenProvider},
    KbsClientCapabilities, ResourceUri,
};

use crate::{Error, Result};

use super::{Kbc};

fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

pub struct CcKbc {
    client: KbsProtocolClient<Box<dyn TokenProvider>>,
    kbs_url: String,
    kbs_ld: String,
}

impl CcKbc {
    pub async fn new(kbs_host_url: &str, kbs_ld: &str) -> Result<Self> {
        println!("confilesystem20 println- cdh.kms.CcKbc.new():  kbs_host_url = {:?}", kbs_host_url);
        println!("confilesystem20 println- cdh.kms.CcKbc.new():  kbs_ld = {:?}", kbs_ld);

        let token_provider = AATokenProvider::new()
            .await
            .map_err(|e| Error::KbsClientError(format!("create AA token provider failed: {e}")))?;
        let client = kbs_protocol::KbsClientBuilder::with_token_provider(
            Box::new(token_provider),
            kbs_host_url,
        )
        .build()
        .map_err(|e| Error::KbsClientError(format!("create kbs client failed: {e}")))?;
        Ok(Self {
            client,
            kbs_url: kbs_host_url.to_string(),
            kbs_ld: kbs_ld.to_string(),
        })
    }
}

#[async_trait]
impl Kbc for CcKbc {
    async fn get_resource(&mut self, rid: ResourceUri, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        let secret = self
            .client
            .get_resource(rid, extra_credential)
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
        println!("confilesystem20 println- cdh.kms.CcKbc.set_resource():  self.kbs_url = {:?}", self.kbs_url);
        println!("confilesystem20 println- cdh.kms.CcKbc.set_resource():  self.kbs_ld = {:?}", self.kbs_ld);

        let set_rsp = set_resource(&self.kbs_url, &rid.resource_path(), content)
            .await
            .map_err(|e| Error::SetResourceError(format!("set resource failed: {e}")))?;;

        println!("confilesystem20 println- cdh.kms.CcKbc.set_resource():  set_rsp = {:?}", set_rsp);
        Ok(set_rsp)
    }
}

// util apis
use kbs_types::{TeePubKey};
use serde::{Serialize, Deserialize};

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
    //challenge: &str,
    //auth_key: String,
    //kbs_root_certs_pem: Vec<String>,
) -> anyhow::Result<Vec<u8>> {
    println!("confilesystem20 println- set_resource(): url = {:?}", url);
    println!("confilesystem20 println- set_resource(): path = {:?}", path);

    let challenge = "123456";
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


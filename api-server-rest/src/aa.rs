// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use crate::ttrpc_proto::attestation_agent::{GetEvidenceRequest, GetTokenRequest};
use crate::ttrpc_proto::attestation_agent_ttrpc::AttestationAgentServiceClient;
use anyhow::*;
use async_trait::async_trait;
use hyper::{Body, Method, Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

use crate::{ttrpc_proto, TTRPC_TIMEOUT};

/// ROOT path for Confidential Data Hub API
pub const AA_ROOT: &str = "/aa";

/// URL for querying CDH get resource API
const AA_TOKEN_URL: &str = "/token";
const AA_EVIDENCE_URL: &str = "/evidence";

// 2024-04-01 : add by confilesystem
const AA_TOKEN_URL_EXTRA: &str = "/token_extra";
const AA_EVIDENCE_URL_EXTRA: &str = "/evidence_extra";

pub struct AAClient {
    client: AttestationAgentServiceClient,
    aa_attester: String,
    accepted_method: Vec<Method>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceAARsp {
    #[serde(rename = "tee-type")]
    pub tee_type: i32,
    #[serde(rename = "evidence")]
    pub evidence: Vec<u8>,
}

#[async_trait]
impl ApiHandler for AAClient {
    async fn handle_request(
        &self,
        remote_addr: SocketAddr,
        url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if !remote_addr.ip().is_loopback() {
            // Return 403 Forbidden response.
            return self.forbidden();
        }

        if !self.accepted_method.iter().any(|i| i.eq(&req.method())) {
            // Return 405 Method Not Allowed response.
            return self.not_allowed();
        }

        let params: HashMap<String, String> = req
            .uri()
            .query()
            .map(|v| form_urlencoded::parse(v.as_bytes()).into_owned().collect())
            .unwrap_or_default();

        if params.len() != 1 {
            return self.not_allowed();
        }

        match url_path {
            AA_TOKEN_URL => match params.get("token_type") {
                Some(token_type) => {
                    let results = self
                        .get_token(token_type)
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                None => return self.bad_request(),
            },
            AA_EVIDENCE_URL => match params.get("runtime_data") {
                Some(runtime_data) => {
                    let results = self
                        .get_evidence(&runtime_data.clone().into_bytes())
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                None => return self.bad_request(),
            },
            AA_TOKEN_URL_EXTRA => match params.get("token_type") {
                Some(token_type) => {
                    let extra_credential = match crate::utils::get_extra_credential_from_req(req).await {
                        core::result::Result::Ok(content) => {
                            println!("confilesystem10 - AAClient::handle_request(): get_extra_credential_from_req() -> content = {:?}", content);
                            content
                        },
                        Err(e) => {
                            println!("confilesystem10 - AAClient::handle_request(): get_extra_credential_from_req() -> e = {:?}", e);
                            return self.bad_request();
                        }
                    };
                    println!("confilesystem11 - AAClient::handle_request(): extra_credential = {:?}, self.aa_attester = {:?}",
                             extra_credential, self.aa_attester);
                    if self.aa_attester != extra_credential.aa_attester {
                        return self.bad_request();
                    }
                    let results = self
                        .get_token_extra(token_type, &extra_credential)
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                None => return self.bad_request(),
            },
            AA_EVIDENCE_URL_EXTRA => match params.get("runtime_data") {
                Some(runtime_data) => {
                    let extra_credential = match crate::utils::get_extra_credential_from_req(req).await {
                        core::result::Result::Ok(content) => {
                            println!("confilesystem10 - AAClient::handle_request(): get_extra_credential_from_req() -> content = {:?}", content);
                            content
                        },
                        Err(e) => {
                            println!("confilesystem10 - AAClient::handle_request(): get_extra_credential_from_req() -> e = {:?}", e);
                            return self.bad_request();
                        }
                    };
                    println!("confilesystem20 - AAClient::handle_request(): extra_credential = {:?}, self.aa_attester = {:?}",
                             extra_credential, self.aa_attester);
                    if self.aa_attester != extra_credential.aa_attester
                     /*&& extra_credential.aa_attester != "security"*/ {
                        return self.bad_request();
                    }
                    let evidence_rsp = self
                        .get_evidence_extra(runtime_data, &extra_credential)
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    println!("confilesystem20 - AAClient::handle_request() get_evidence_extra(): done");
                    return self.octet_stream_response(evidence_rsp);
                }
                None => return self.bad_request(),
            },
            _ => {
                return self.not_found();
            }
        }
    }
}

impl AAClient {
    pub fn new(aa_addr: &str, aa_attester: &str, accepted_method: Vec<Method>) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(aa_addr)?;
        let client = AttestationAgentServiceClient::new(inner);

        Ok(Self {
            client,
            aa_attester: aa_attester.to_string(),
            accepted_method,
        })
    }

    pub async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let req = GetTokenRequest {
            TokenType: token_type.to_string(),
            ..Default::default()
        };
        let res = self
            .client
            .get_token(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Token)
    }

    pub async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data.to_vec(),
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Evidence)
    }

    pub async fn get_token_extra(&self, token_type: &str, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        println!("confilesystem10 - AAClient::get_token_extra(): token_type = {:?}, extra_credential = {:?}",
                 token_type, extra_credential);

        let extra_credential_ttrpc = ttrpc_proto::attestation_agent::ExtraCredential {
            ControllerCrpToken: extra_credential.controller_crp_token.clone(),
            ControllerAttestationReport: extra_credential.controller_attestation_report.clone(),
            ControllerCertChain: extra_credential.controller_cert_chain.clone(),
            AAAttester: extra_credential.aa_attester.clone(),
            ExtraRequest: extra_credential.extra_request.clone(),
            ..Default::default()
        };

        let req = GetTokenRequest {
            TokenType: token_type.to_string(),
            ExtraCredential: protobuf::MessageField::some(extra_credential_ttrpc),
            ..Default::default()
        };
        let res = self
            .client
            .get_token(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Token)
    }

    pub async fn get_evidence_extra(&self, runtime_data: &str, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        println!("confilesystem10 - AAClient::get_evidence_extra(): runtime_data = {:?}, extra_credential = {:?}",
                 runtime_data, extra_credential);

        // see: coco-trustee api_server::http::evidence::get_runtime_data
        let runtime_data_vec = hex::decode(runtime_data.clone())?;

        let extra_credential_ttrpc = ttrpc_proto::attestation_agent::ExtraCredential {
            ControllerCrpToken: extra_credential.controller_crp_token.clone(),
            ControllerAttestationReport: extra_credential.controller_attestation_report.clone(),
            ControllerCertChain: extra_credential.controller_cert_chain.clone(),
            AAAttester: extra_credential.aa_attester.clone(),
            ExtraRequest: extra_credential.extra_request.clone(),
            ..Default::default()
        };

        let req = GetEvidenceRequest {
            RuntimeData: runtime_data_vec,
            ExtraCredential: protobuf::MessageField::some(extra_credential_ttrpc),
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        println!("confilesystem10 - AAClient::get_evidence_extra(): success");
        let evidence_aa_rsp = EvidenceAARsp{
            tee_type: res.Tee.value(),
            evidence: res.Evidence,
        };
        let evidence_vec = serde_json::to_vec(&evidence_aa_rsp)?;

        Ok(evidence_vec)
    }
}

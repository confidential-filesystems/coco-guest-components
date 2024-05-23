// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use crate::ttrpc_proto::attestation_agent::ExtraCredential;
use crate::ttrpc_proto::confidential_data_hub::GetResourceRequest;
use crate::ttrpc_proto::confidential_data_hub_ttrpc::GetResourceServiceClient;
use anyhow::*;
use async_trait::async_trait;
use hyper::{Body, Method, Request, Response};
use std::net::SocketAddr;

use crate::utils::split_nth_slash;
use crate::{ttrpc_proto, TTRPC_TIMEOUT};

/// ROOT path for Confidential Data Hub API
pub const CDH_ROOT: &str = "/cdh";

/// URL for querying CDH get resource API
pub const CDH_RESOURCE_URL: &str = "/resource";

// 2024-04-01: add by confilesystem
pub const CDH_RESOURCE_URL_EXTRA: &str = "/resource_extra";

const KBS_PREFIX: &str = "kbs://";

pub struct CDHClient {
    client: GetResourceServiceClient,
    aa_attester: String,
    accepted_method: Vec<Method>,
}

#[async_trait]
impl ApiHandler for CDHClient {
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

        //println!("confilesystem10 - CDHClient::handle_request(): url_path = {:?}, req.body() = {:?}", url_path, req.body());
        if !self.accepted_method.iter().any(|i| i.eq(&req.method())) {
            // Return 405 Method Not Allowed response.
            return self.not_allowed();
        }

        if let Some((api, resource_path)) = split_nth_slash(url_path, 2) {
            match api {
                CDH_RESOURCE_URL => {
                    let results = self
                        .get_resource(resource_path)
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                CDH_RESOURCE_URL_EXTRA => {
                    let extra_credential = match crate::utils::get_extra_credential_from_req(req).await {
                        core::result::Result::Ok(content) => {
                            println!("confilesystem10 - CDHClient::handle_request(): get_extra_credential_from_req() -> content = {:?}", content);
                            content
                        },
                        Err(e) => {
                            println!("confilesystem10 - CDHClient::handle_request(): get_extra_credential_from_req() -> e = {:?}", e);
                            return self.bad_request();
                        }
                    };
                    println!("confilesystem11 - CDHClient::handle_request(): extra_credential = {:?}, self.aa_attester = {:?}",
                             extra_credential, self.aa_attester);
                    if self.aa_attester != extra_credential.aa_attester {
                        return self.bad_request();
                    }
                    let results = self
                        .get_resource_extra(resource_path, &extra_credential)
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                _ => {
                    return self.not_found();
                }
            }
        }

        Ok(Response::builder().status(404).body(Body::empty())?)
    }
}

impl CDHClient {
    pub fn new(cdh_addr: &str, aa_attester: &str, accepted_method: Vec<Method>) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(cdh_addr)?;
        let client = GetResourceServiceClient::new(inner);

        Ok(Self {
            client,
            aa_attester: aa_attester.to_string(),
            accepted_method,
        })
    }

    // confilesystem1000: ExtraCredential -> req
    pub async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let req = GetResourceRequest {
            ResourcePath: format!("{}{}", KBS_PREFIX, resource_path),
            ..Default::default()
        };
        let res = self
            .client
            .get_resource(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Resource)
    }

    pub async fn get_resource_extra(&self, resource_path: &str, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        println!("confilesystem10 - CDHClient::get_resource_extra(): resource_path = {:?}, extra_credential = {:?}",
                 resource_path, extra_credential);

        let extra_credential_ttrpc = ttrpc_proto::attestation_agent::ExtraCredential {
            ControllerCrpToken: extra_credential.controller_crp_token.clone(),
            ControllerAttestationReport: extra_credential.controller_attestation_report.clone(),
            ControllerCertChain: extra_credential.controller_cert_chain.clone(),
            AAAttester: extra_credential.aa_attester.clone(),
            ContainerName: extra_credential.container_name.clone(),
            ..Default::default()
        };

        let req = GetResourceRequest {
            ResourcePath: format!("{}{}", KBS_PREFIX, resource_path),
            ExtraCredential: protobuf::MessageField::some(extra_credential_ttrpc),
            ..Default::default()
        };
        let res = self
            .client
            .get_resource(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Resource)
    }
}

// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Rserouce ttrpc client

use anyhow::*;
use async_trait::async_trait;
use ttrpc::context;

use super::Client;

use super::ttrpc_proto::getresource::{GetResourceRequest};
use super::ttrpc_proto::getresource_ttrpc::GetResourceServiceClient;
//use crate::kbc::extra_credential::{ExtraCredential};
use ocicrypt_rs::token::{ExtraCredential};

//use log::{info};
// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

const SOCKET_ADDR: &str = "unix:///run/confidential-containers/attestation-agent/getresource.sock";

pub struct Ttrpc {
    gtclient: GetResourceServiceClient,
}

impl Ttrpc {
    pub fn new() -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(SOCKET_ADDR)?;
        let gtclient = GetResourceServiceClient::new(inner);

        Ok(Self { gtclient })
    }
}

#[async_trait]
impl Client for Ttrpc {
    async fn get_resource(
        &mut self,
        kbc_name: &str,
        resource_path: &str,
        kbs_uri: &str,
        ie_data: &crate::extra::token::InternalExtraData,
        extra_request: &str,
    ) -> Result<Vec<u8>> {
        slog::info!(sl(), "confilesystem2 - Client - Ttrpc.get_resource(): kbc_name = {:?}, resource_path = {:?}, kbs_uri = {:?}",
            kbc_name, resource_path, kbs_uri);
        slog::info!(sl(), "confilesystem6 - Client - Ttrpc.get_resource(): ie_data.controller_crp_token.len() = {:?}, ie_data.controller_attestation_report.len() = {:?}, ie_data.controller_cert_chain.len() = {:?}",
            ie_data.controller_crp_token.len(), ie_data.controller_attestation_report.len(), ie_data.controller_cert_chain.len());
        slog::info!(sl(), "confilesystem6 - Client- Ttrpc.get_resource(): ie_data.aa_attester = {:?}, ie_data.container_name = {:?}",
            ie_data.aa_attester, ie_data.container_name);
        let extra_credential = ExtraCredential::new(
            ie_data.controller_crp_token.clone(),
            ie_data.controller_attestation_report.clone(),
            ie_data.controller_cert_chain.clone(),
            ie_data.aa_attester.clone(),
            extra_request.to_string()).to_string().expect("confilesystem7 - fail to get extra credential");
        let req = GetResourceRequest {
            KbcName: kbc_name.to_string(),
            ResourcePath: resource_path.to_string(),
            KbsUri: kbs_uri.to_string(),
            ExtraCredential: extra_credential,
            ..Default::default()
        };
        let res = self
            .gtclient
            .get_resource(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .context("ttrpc request error")?;
        Ok(res.Resource)
    }
}

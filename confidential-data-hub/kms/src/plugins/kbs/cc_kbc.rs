// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

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

        //1TODO
        Ok(content)
    }
}

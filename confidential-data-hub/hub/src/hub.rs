// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use kms::{Annotations, ProviderSettings};
use secret::secret::Secret;

use crate::{DataHub, Error, Result};

pub struct Hub {}

impl Hub {
    pub async fn new() -> Result<Self> {
        let mut hub = Self {};

        hub.init().await?;
        Ok(hub)
    }
}

#[async_trait]
impl DataHub for Hub {
    async fn unseal_secret(&self, secret: Vec<u8>, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        // TODO: verify the jws signature using the key specified by `kid`
        // in header. Here we directly get the JWS payload
        let payload = secret
            .split(|c| *c == b'.')
            .nth(1)
            .ok_or_else(|| Error::UnsealSecret("illegal input sealed secret (not a JWS)".into()))?;

        let secret_json = STANDARD.decode(payload).map_err(|e| {
            Error::UnsealSecret(format!(
                "illegal input sealed secret (JWS body is not standard base64 encoded): {e}"
            ))
        })?;
        let secret: Secret = serde_json::from_slice(&secret_json).map_err(|e| {
            Error::UnsealSecret(format!(
                "illegal input sealed secret format (json deseralization failed): {e}"
            ))
        })?;

        let res = secret
            .unseal(extra_credential)
            .await
            .map_err(|e| Error::UnsealSecret(format!("unseal failed: {e}")))?;
        Ok(res)
    }

    async fn unwrap_key(&self, _annotation: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    async fn get_resource(&self, uri: String, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        // to initialize a get_resource_provider client we do not need the ProviderSettings.
        let mut client = kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| Error::GetResource(format!("create kbs client failed: {e}")))?;

        // to get resource using a get_resource_provider client we do not need the Annotations.
        let res = client
            .get_secret(&uri, &Annotations::default(), extra_credential)
            .await
            .map_err(|e| Error::GetResource(format!("get rersource failed: {e}")))?;
        Ok(res)
    }

    async fn set_resource(&self, uri: String, resource: Vec<u8>) -> Result<Vec<u8>> {
        // to initialize a set_resource_provider client we do not need the ProviderSettings.
        let mut client = kms::new_setter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| Error::SetResource(format!("create kbs client failed: {e}")))?;

        // to set resource using a set_resource_provider client we do not need the Annotations.
        let res = client
            .set_secret(&uri, resource)
            .await
            .map_err(|e| Error::SetResource(format!("set rersource failed: {e}")))?;
        Ok(res)
    }

    async fn delete_resource(&self, uri: String, resource: Vec<u8>) -> Result<Vec<u8>> {
        // to initialize a delete_resource_provider client we do not need the ProviderSettings.
        let mut client = kms::new_deleter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| Error::DeleteResource(format!("create kbs client failed: {e}")))?;

        // to delete resource using a delete_resource_provider client we do not need the Annotations.
        let res = client
            .delete_secret(&uri, resource)
            .await
            .map_err(|e| Error::DeleteResource(format!("delete rersource failed: {e}")))?;
        Ok(res)
    }
}

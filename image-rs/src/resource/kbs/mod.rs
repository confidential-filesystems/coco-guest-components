// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Fetch confidential resources from KBS (Relying Party).

//! All the fetched resources will be stored in a local filepath:
//! `/run/image-security/kbs/<filename>`
//!
//! The `<filename>` will be generated by hash256sum the KBS Resource URI/
//! For example:
//! `kbs://example.org/alice/key/1` will be stored in
//! `/run/image-security/kbs/cde48578964b30b0aa8cecf04c020f64f7cce36fc391b24f45cf8d4e5368e229`

use std::path::Path;

#[cfg(not(feature = "keywrap-native"))]
use anyhow::Context;
use anyhow::{bail, Result};
use async_trait::async_trait;
use log::info;
use sha2::{Digest, Sha256};
use tokio::fs;

use super::Protocol;

//use log::{info};
// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

#[cfg(feature = "keywrap-grpc")]
mod grpc;

#[cfg(feature = "keywrap-ttrpc")]
mod ttrpc;

#[cfg(feature = "keywrap-ttrpc")]
mod ttrpc_proto;

#[cfg(feature = "keywrap-native")]
mod native;

/// Default workdir to store downloaded kbs resources
const STORAGE_PATH: &str = "/run/image-security/kbs/";

/// SecureChannel to connect with KBS
pub struct SecureChannel {
    /// Get Resource Service client.
    client: Box<dyn Client>,
    // TODO: now the _kbs_uri from `aa_kbc_params` is not used. Because the
    // kbs uri is included in the kbs resource uri.
    kbs_uri: String,
    kbc_name: String,
    /// The path to store downloaded kbs resources
    pub storage_path: String,
}

#[async_trait]
trait Client: Send + Sync {
    async fn get_resource(
        &mut self,
        kbc_name: &str,
        resource_path: &str,
        kbs_uri: &str,
        ie_data: &crate::extra::token::InternalExtraData,
        extra_request: &str,
    ) -> Result<Vec<u8>>;
}

impl SecureChannel {
    /// Create a new [`SecureChannel`], the input parameter:
    /// * `aa_kbc_params`: s string with format `<kbc_name>::<kbs_uri>`.
    pub async fn new(aa_kbc_params: &str) -> Result<Self> {
        // unzip here is unstable
        slog::info!(sl(), "confilesystem2 - SecureChannel.new(): aa_kbc_params = {:?}", aa_kbc_params);
        if let Some((kbc_name, kbs_uri)) = aa_kbc_params.split_once("::") {
            if kbc_name.is_empty() {
                bail!("aa_kbc_params: missing KBC name");
            }

            if kbs_uri.is_empty() {
                bail!("aa_kbc_params: missing KBS URI");
            }

            let client: Box<dyn Client> = {
                cfg_if::cfg_if! {
                        if #[cfg(feature = "keywrap-grpc")] {
                            info!("secure channel uses gRPC");
                            Box::new(grpc::Grpc::new().await.context("grpc client init failed")?)
                        } else if #[cfg(feature = "keywrap-ttrpc")] {
                            info!("secure channel uses ttrpc");
                            Box::new(ttrpc::Ttrpc::new().context("ttrpc client init failed")?)
                        } else if #[cfg(feature = "keywrap-native")] {
                            info!("secure channel uses native-aa");
                Box::<native::Native>::default()
                        } else {
                            compile_error!("At last one feature of `keywrap-grpc`, `keywrap-ttrpc`, and `keywrap-native` must be enabled.");
                        }
                    }
            };

            fs::create_dir_all(STORAGE_PATH).await?;

            let kbs_uri = match kbs_uri {
                "null" => {
                    log::warn!("detected kbs uri `null`, use localhost to be placeholder");
                    "http://localhost".into()
                }
                uri => uri.into(),
            };

            Ok(Self {
                client,
                kbs_uri,
                kbc_name: kbc_name.into(),
                storage_path: STORAGE_PATH.into(),
            })
        } else {
            bail!("aa_kbc_params: KBC/KBS pair not found")
        }
    }

    /// Check whether the resource of the uri has been downloaded.
    /// Return Some(_) if exists, and return None if not.
    async fn check_local(&self, uri: &str) -> Result<Option<Vec<u8>>> {
        let file_path = self.get_filepath(uri);
        match Path::new(&file_path).exists() {
            true => {
                let contents = fs::read(&file_path).await?;
                Ok(Some(contents))
            }
            false => Ok(None),
        }
    }

    /// Get the localpath to store the kbs resource in the local filesystem
    fn get_filepath(&self, uri: &str) -> String {
        let mut sha256 = Sha256::new();
        sha256.update(uri.as_bytes());
        format!("{}/{:x}", self.storage_path, sha256.finalize())
    }
}

#[async_trait]
impl Protocol for SecureChannel {
    /// Get resource from using, using `resource_name` as `name` in a ResourceDescription,
    /// then save the gathered data into `path`
    ///
    /// Please refer to https://github.com/confidential-containers/guest-components/blob/main/image-rs/docs/ccv1_image_security_design.md#get-resource-service
    /// for more information.
    async fn get_resource(&mut self, resource_uri: &str, ie_data: &crate::extra::token::InternalExtraData, extra_request: &str) -> Result<Vec<u8>> {
        slog::info!(sl(), "confilesystem6 - SecureChannel.get_resource(): resource_uri = {:?}", resource_uri);
        if let Some(res) = self.check_local(resource_uri).await? {
            return Ok(res);
        }

        // Related issue: https://github.com/confidential-containers/attestation-agent/issues/130
        //
        // Now we use `aa_kbc_params` to specify the KBC and KBS URI
        // used in CoCo System. Different KBCs are initialized in AA lazily due
        // to the kbs uri information included in a `download_confidential_resource` or
        // `decrypt_image_layer_annotation`. The kbs uri input to the two APIs
        // are from `aa_kbc_params` but not the kbs uri in a resource uri.
        // Thus as a temporary solution, we need to overwrite the
        // kbs uri field using the one included in `aa_kbc_params`, s.t.
        // `kbs_uri` of [`SecureChannel`].
        let resource_path = get_resource_path(resource_uri)?;

        let res = self
            .client
            .get_resource(&self.kbc_name, &resource_path, &self.kbs_uri, ie_data, extra_request)
            .await?;

        let path = self.get_filepath(resource_uri);
        fs::write(path, &res).await?;
        Ok(res)
    }
}

fn get_resource_path(uri: &str) -> Result<String> {
    let path = url::Url::parse(uri)?;
    Ok(path.path().to_string())
}

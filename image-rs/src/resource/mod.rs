// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps to fetch resource using different
//! protocols. Different resources can be marked in a
//! specific uri. Now, it supports the following:
//!
//! - `file://`: from the local filesystem
//! - `kbs://`: using secure channel to fetch from the KBS

use anyhow::*;
use async_trait::async_trait;
use tokio::fs;

//use log::{info};
// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

#[cfg(feature = "getresource")]
pub mod kbs;

#[cfg(feature = "getresource")]
lazy_static::lazy_static! {
    /// SecureChannel
    pub static ref SECURE_CHANNEL: tokio::sync::Mutex<Option<kbs::SecureChannel>> = {
        tokio::sync::Mutex::new(None)
    };
}

/// A protocol should implement this trait. For example,
/// a `file://` scheme's
/// - `SCHEME`: `file` string, to distinguish different uri scheme
/// - `get_resource()`: get resource from the uri
#[async_trait]
trait Protocol: Send + Sync {
    async fn get_resource(&mut self, uri: &str, ie_data: &crate::extra::token::InternalExtraData) -> Result<Vec<u8>>;
}

/// This is a public API to retrieve resources. The input parameter `uri` should be
/// a URL. For example `file://...`
/// The resource will be retrieved in different ways due to different schemes.
/// If no scheme is given, it will by default use `file://` to look for the file
/// in the local filesystem.
pub async fn get_resource(uri: &str, ie_data: &crate::extra::token::InternalExtraData) -> Result<Vec<u8>> {
    let can_get = ie_data.can_get_res(uri);
    slog::info!(sl(), "confilesystem8 - get_resource({:?}): can_get = {:?}", uri, can_get);
    if !can_get {
        slog::info!(sl(), "confilesystem8 - get_resource(): can not get resource: uri = {:?} because of ie_data.authorized_res = {:?}",
            uri, ie_data.authorized_res);
        return Err(anyhow!("confilesystem8 - fail to get resource: {:?}", uri));
    }

    let uri = if uri.contains("://") {
        uri.to_string()
    } else {
        "file://".to_owned() + uri
    };

    let url = url::Url::parse(&uri).map_err(|e| anyhow!("Failed to parse: {:?}", e))?;
    match url.scheme() {
        "kbs" => {
            #[cfg(feature = "getresource")]
            {
                SECURE_CHANNEL
                    .lock()
                    .await
                    .as_mut()
                    .ok_or_else(|| anyhow!("Uninitialized secure channel"))?
                    .get_resource(&uri, ie_data)
                    .await
            }

            #[cfg(not(feature = "getresource"))]
            {
                bail!(
                    "`getresource` feature not enabled, cannot support fetch resource uri {}",
                    uri
                )
            }
        }
        "file" => {
            let path = url.path();
            let content = fs::read(path).await?;
            Ok(content)
        }
        others => bail!("not support scheme {}", others),
    }
}

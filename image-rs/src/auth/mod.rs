// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod auth_config;

use std::collections::HashMap;

use anyhow::*;
use oci_distribution::{secrets::RegistryAuth, Reference};
use serde::{Deserialize, Serialize};

// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

/// Hard-coded ResourceDescription of `auth.json`.
pub const RESOURCE_DESCRIPTION: &str = "Credential";

#[derive(Deserialize, Serialize)]
pub struct DockerConfigFile {
    auths: HashMap<String, DockerAuthConfig>,
    // TODO: support credential helpers
}

#[derive(Deserialize, Serialize)]
pub struct DockerAuthConfig {
    auth: String,
}

/// Get a credential (RegistryAuth) for the given Reference.
/// The path can be from different places. Like `path://` or
/// `kbs://`.
pub async fn credential_for_reference(
    reference: &Reference,
    auth_file_path: &str,
    ie_data: &crate::extra::token::InternalExtraData,
) -> Result<RegistryAuth> {
    slog::info!(sl(), "confilesystem8 - credential_for_reference(): auth_file_path = {:?}", auth_file_path);

    let auth = crate::resource::get_resource(auth_file_path, ie_data).await?;
    slog::info!(sl(), "confilesystem8 - credential_for_reference(): auth = {:?}", auth);

    let config: DockerConfigFile = serde_json::from_slice(&auth)?;

    // TODO: support credential helpers
    auth_config::credential_from_auth_config(reference, &config.auths)
}

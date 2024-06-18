// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use strum_macros::EnumString;
use self::local_fs::LocalFs;

pub mod local_fs;

/// Interface of a `Repository`.
#[async_trait::async_trait]
pub trait Repository {
    /// Read secret resource from repository.
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct ResourceDesc {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_tag: String,
}

impl ResourceDesc {
    pub fn is_valid(&self) -> bool {
        if &self.repository_name == "."
            || &self.repository_name == ".."
            || &self.resource_type == "."
            || &self.resource_type == ".."
        {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, Deserialize, EnumString)]
#[serde(tag = "type")]
pub enum RepositoryConfig {
    LocalFs(local_fs::LocalFsRepoDesc),
}

impl RepositoryConfig {
    pub fn initialize(&self) -> Result<Box<dyn Repository + Send + Sync>> {
        match self {
            Self::LocalFs(desc) => {
                // Create repository dir.
                let dir_path = desc
                    .dir_path
                    .clone()
                    .unwrap_or(local_fs::DEFAULT_REPO_DIR_PATH.to_string());

                if !Path::new(&dir_path).exists() {
                    fs::create_dir_all(&dir_path)?;
                }
                // Create default repo.
                if !Path::new(&format!("{}/default", &dir_path)).exists() {
                    fs::create_dir_all(format!("{}/default", &dir_path))?;
                }

                Ok(Box::new(LocalFs::new(desc)?) as Box<dyn Repository + Send + Sync>)
            }
        }
    }
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self::LocalFs(local_fs::LocalFsRepoDesc::default())
    }
}

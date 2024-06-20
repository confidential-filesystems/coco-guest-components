// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "aliyun")]
    #[error("Aliyun KMS error: {0}")]
    AliyunKmsError(String),

    #[error("Kbs client error: {0}")]
    KbsClientError(String),

    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),

    #[error("Set resource error: {0}")]
    SetResourceError(String),

    #[error("Delete resource error: {0}")]
    DeleteResourceError(String),
}

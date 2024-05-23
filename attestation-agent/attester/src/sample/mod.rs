// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::env;

// If the environment variable "AA_SAMPLE_ATTESTER_TEST" is set,
// the TEE platform is considered as "sample".
pub fn detect_platform() -> bool {
    env::var("AA_SAMPLE_ATTESTER_TEST").is_ok()
}

// A simple example of TEE evidence.
#[derive(Serialize, Deserialize, Debug)]
struct SampleQuote {
    svn: String,
    report_data: String,
    custom: String,
}

#[derive(Debug, Default)]
pub struct SampleAttester {}

#[async_trait::async_trait]
impl Attester for SampleAttester {
    async fn get_evidence(&self, report_data: Vec<u8>, _extra_credential: &crate::extra_credential::ExtraCredential) -> Result<String> {
        log::info!("confilesystem4 - SampleAttester.get_evidence(): report_data = {:?}", report_data);
        let evidence = SampleQuote {
            svn: "1".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
            custom: "confilesystem-Sample".to_string(),
        };

        log::info!("confilesystem4 - SampleAttester.get_evidence(): evidence.report_data = {:?}", evidence.report_data);
        serde_json::to_string(&evidence).map_err(|_| anyhow!("Serialize sample evidence failed"))
    }
}

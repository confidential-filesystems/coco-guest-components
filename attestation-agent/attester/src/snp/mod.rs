// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
//use core::result::Result;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::guest::Firmware;
use sev::firmware::host::CertTableEntry;
use std::path::Path;

use base64::Engine;

pub fn detect_platform() -> bool {
    Path::new("/sys/devices/platform/sev-guest").exists()
}

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Vec<CertTableEntry>,
}

// A simple example of TEE evidence.
#[derive(Serialize, Deserialize, Debug)]
struct SampleQuote {
    svn: String,
    report_data: String,
    custom: String,
}

#[derive(Debug, Default)]
pub struct SnpAttester {}

const SNP_EMU: bool = true;

#[async_trait::async_trait]
impl Attester for SnpAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>, _extra_credential: &crate::extra_credential::ExtraCredential) -> Result<String> {
        log::info!("confilesystem5 - SnpAttester.get_evidence(): SNP_EMU = {:?}, report_data = {:?}", SNP_EMU, report_data);

        if SNP_EMU {
            let evidence = SampleQuote {
                svn: "1".to_string(),
                report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
                custom: "confilesystem-SNP-EMU".to_string(),
            };
            log::info!("confilesystem5 - SnpAttester.get_evidence(): EMU - evidence.report_data = {:?}", evidence.report_data);
            serde_json::to_string(&evidence).context("Serialize SNP EMU evidence failed")
        } else {
        if report_data.len() > 64 {
                bail!("confilesystem5 - SNP Attester: Report data must be no more than 64 bytes");
        }
        report_data.resize(64, 0);

            let mut firmware = Firmware::open()
                .expect("confilesystem5 - SnpAttester.get_evidence(): fail to Firmware::open()");
        let data = report_data.as_slice().try_into()?;

            let get_report_res = firmware
                .get_report(None, Some(data), Some(0))
                .context("confilesystem5 - Failed to get attestation report by firmware.get_report()")
                .map_err(|e| anyhow!("confilesystem5 - SnpAttester.get_evidence(): fail to firmware.get_report()) e = {:?}", e))?;
            log::info!("confilesystem5 - SnpAttester.get_evidence(): firmware.get_report() -> get_report_res = {:?}", get_report_res);

            //let (report, certs) = firmware
            //    .get_ext_report(None, Some(data), Some(0))
            //    .context("confilesystem5 - Failed to get attestation report")
            //    .map_err(|e| anyhow!("confilesystem5 - SnpAttester.get_evidence(): fail to firmware.get_ext_report()) e = {:?}", e))?;

            match firmware.get_ext_report(None, Some(data), Some(0)) {
                core::result::Result::Ok((report, certs)) => {
        let evidence = SnpEvidence {
            attestation_report: report,
            cert_chain: certs,
        };
                    log::info!("confilesystem5 - SnpAttester.get_evidence(): evidence.attestation_report = {:?}", evidence.attestation_report);
                    //log::warn!("confilesystem5 - snp.get_evidence(): certs = {:?}", certs);
        serde_json::to_string(&evidence).context("Serialize SNP evidence failed")
                },
                core::result::Result::Err(err) => {
                    log::info!("confilesystem5 - SnpAttester.get_evidence(): firmware.get_ext_report() -> err = {:?}", err);

                    // try to use EMU evidence if firmware.get_ext_report() fail
                    let evidence = SampleQuote {
                        svn: "1".to_string(),
                        report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
                        custom: "confilesystem-SNP-EMU".to_string(),
                    };
                    log::info!("confilesystem5 - SnpAttester.get_evidence(): EMU evidence.report_data = {:?}", evidence.report_data);
                    serde_json::to_string(&evidence).context("Serialize SNP EMU evidence failed")
                }
            }
        }
    }
}

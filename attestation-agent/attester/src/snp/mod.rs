// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
//use core::result::Result;
use crate::emulate::get_hash_48bites;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::guest::Firmware;
use sev::firmware::host::CertTableEntry;
use sev::firmware::host::CertType;
use std::path::Path;

//use crate::types::{
//    AttesterReport, RAEvidence, ATTESTER_CONTROLLER, ATTESTER_METADATA, ATTESTER_SECURITY,
//    ATTESTER_WORKLOAD,
//};
use base64::Engine;

const REPORT_DATA_LEN_DEFAULT: usize = 48;

pub const ATTESTER_SECURITY: &str = "security";
pub const ATTESTER_CONTROLLER: &str = "controller";
pub const ATTESTER_METADATA: &str = "metadata";
pub const ATTESTER_WORKLOAD: &str = "workload";

#[derive(Debug, Serialize, Deserialize)]
pub struct AttesterReport {
    pub attester: String,
    pub attestation_report: AttestationReport,
    pub cert_chain: Option<Vec<CertTableEntry>>,
}

// RAE
#[derive(Debug, Serialize, Deserialize)]
pub struct RAEvidence {
    pub crp_token: Option<String>,
    pub attestation_reports: Vec<AttesterReport>,
}

impl RAEvidence {
    pub fn default() -> RAEvidence {
        let attester_report = AttesterReport {
            attester: "".to_string(),
            attestation_report: AttestationReport::default(),
            cert_chain: None,
        };
        let mut attestation_reports: Vec<AttesterReport> = Vec::new();
        attestation_reports.push(attester_report);
        let evidence = RAEvidence {
            crp_token: None,
            attestation_reports: attestation_reports,
        };
        evidence
    }
}

pub fn detect_platform() -> bool {
    Path::new("/sys/devices/platform/sev-guest").exists()
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

const SNP_EMU: bool = false;

#[async_trait::async_trait]
impl Attester for SnpAttester {
    async fn get_evidence(
        &self,
        mut report_data: Vec<u8>,
        _extra_credential: &crate::extra_credential::ExtraCredential,
    ) -> Result<String> {
        log::info!(
            "confilesystem5 - SnpAttester.get_evidence(): SNP_EMU = {:?}, report_data = {:?}",
            SNP_EMU,
            report_data
        );

        if SNP_EMU {
            let evidence = SampleQuote {
                svn: "1".to_string(),
                report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
                custom: "confilesystem-SNP-EMU".to_string(),
            };
            log::info!(
                "confilesystem5 - SnpAttester.get_evidence(): EMU - evidence.report_data = {:?}",
                evidence.report_data
            );
            serde_json::to_string(&evidence).context("Serialize SNP EMU evidence failed")
        } else {
            if report_data.len() > 64 {
                bail!("confilesystem5 - SNP Attester: Report data must be no more than 64 bytes");
            }
            report_data.resize(64, 0);

            let evidence = get_ra_evidence(report_data, _extra_credential)?;
            log::info!(
                "confilesystem10 - EmulateAttester.get_evidence(): evidence = {:?}",
                evidence
            );
            serde_json::to_string(&evidence).context("Serialize SNP evidence failed")
        }
    }
}

fn get_ra_evidence(
    report_data: Vec<u8>,
    extra_credential: &crate::extra_credential::ExtraCredential,
) -> Result<RAEvidence> {
    log::info!(
        "confilesystem10 - get_ra_evidence(): extra_credential.aa_attester = {:?}",
        extra_credential.aa_attester
    );
    let mut ra_evidence = RAEvidence::default();

    match extra_credential.aa_attester.as_str() {
        ATTESTER_CONTROLLER => {
            ra_evidence = match get_controller_ra_evidence(report_data.clone(), extra_credential) {
                core::result::Result::Ok(ra_evidence_content) => ra_evidence_content,
                Err(e) => bail!(
                    "confilesystem10 - fail to get controller emulate quoute: e = {:?}",
                    e
                ),
            };
        }
        ATTESTER_METADATA => {
            ra_evidence = match get_metadata_ra_evidence(report_data.clone(), extra_credential) {
                core::result::Result::Ok(ra_evidence_content) => ra_evidence_content,
                Err(e) => bail!(
                    "confilesystem10 - fail to get metadata emulate quoute: e = {:?}",
                    e
                ),
            };
        }
        ATTESTER_WORKLOAD => {
            ra_evidence = match get_workload_ra_evidence(report_data.clone(), extra_credential) {
                core::result::Result::Ok(ra_evidence_content) => ra_evidence_content,
                Err(e) => bail!(
                    "confilesystem10 - fail to get workload emulate quoute: e = {:?}",
                    e
                ),
            };
        }
        _ => {
            return Err(anyhow!(
                "confilesystem10 - unavailable extra_credential.aa_attester = {:?}",
                extra_credential.aa_attester
            ));
        }
    }

    Ok(ra_evidence)
}

fn get_controller_ra_evidence(
    report_data: Vec<u8>,
    extra_credential: &crate::extra_credential::ExtraCredential,
) -> Result<RAEvidence> {
    log::info!("confilesystem10 - get_controller_ra_evidence(): extra_credential.controller_crp_token.len() = {:?}", extra_credential.controller_crp_token.len());
    let mut new_report_data = report_data;
    if extra_credential.controller_crp_token.len() > 0 {
        new_report_data = get_hash_48bites(&extra_credential.controller_crp_token).to_vec();
    }

    let mut attestation_reports: Vec<AttesterReport> = Vec::new();

    let mut attestation_report = get_attestation_report(new_report_data.clone());
    let mut cert_chain: Vec<CertTableEntry> = Vec::new();
    cert_chain.push(get_cert(new_report_data.clone(), extra_credential));

    let attestation_report_str = serde_json::to_string(&attestation_report)?;
    //.expect("confilesystem8 - fail to json marsh attestation_report");
    let attestation_report_vec = serde_json::to_vec(&attestation_report)?;
    //.expect("confilesystem8 - fail to json marsh attestation_report to vec");
    let attestation_report_base64 =
        base64::engine::general_purpose::STANDARD.encode(attestation_report_vec.as_slice());
    let cert_chain_str = serde_json::to_string(&cert_chain)?;
    //.expect("confilesystem8 - fail to json marsh cert_chain");
    let cert_chain_vec = serde_json::to_vec(&cert_chain)?;
    //.expect("confilesystem8 - fail to json marsh cert_chain to vec");
    let cert_chain_base64 =
        base64::engine::general_purpose::STANDARD.encode(cert_chain_vec.as_slice());
    log::info!("confilesystem10 - EmulateAttester.get_controller_ra_evidence(): attestation_report_str = {:?}", attestation_report_str);
    log::info!("confilesystem8 - EmulateAttester.get_controller_ra_evidence(): attestation_report_base64 = {:?}", attestation_report_base64);
    log::info!(
        "confilesystem8 - EmulateAttester.get_controller_ra_evidence(): cert_chain_str = {:?}",
        cert_chain_str
    );
    log::info!(
        "confilesystem8 - EmulateAttester.get_controller_ra_evidence(): cert_chain_base64 = {:?}",
        cert_chain_base64
    );

    let attester_report = AttesterReport {
        attester: extra_credential.aa_attester.clone(),
        attestation_report: attestation_report,
        cert_chain: Some(cert_chain),
    };
    attestation_reports.push(attester_report);
    let ra_evidence = RAEvidence {
        crp_token: None,
        attestation_reports: attestation_reports,
    };
    Ok(ra_evidence)
}

fn get_metadata_ra_evidence(
    report_data: Vec<u8>,
    extra_credential: &crate::extra_credential::ExtraCredential,
) -> Result<RAEvidence> {
    let mut attestation_reports: Vec<AttesterReport> = Vec::new();

    // controller
    if extra_credential.controller_crp_token.len() == 0
        || extra_credential.controller_attestation_report.len() == 0
        || extra_credential.controller_cert_chain.len() == 0
    {
        bail!("confilesystem8 - unavailable controller_crp_token || controller_attestation_report || controller_cert_chain");
    }
    // confilesystem : base64 decode first
    let controller_attestation_report_decode = base64::engine::general_purpose::STANDARD
        .decode(&extra_credential.controller_attestation_report)
        .expect("confilesystem8 - failed to base64 decode controller_attestation_report");
    let mut controller_attestation_report: AttestationReport =
        serde_json::from_slice(controller_attestation_report_decode.as_slice())
            .expect("confilesystem8 - failed to json un-marsh controller_attestation_report");
    let controller_report_data = get_hash_48bites(&extra_credential.controller_crp_token);
    controller_attestation_report.report_data[..REPORT_DATA_LEN_DEFAULT]
        .copy_from_slice(&controller_report_data.as_slice());
    let controller_cert_chain_decode = base64::engine::general_purpose::STANDARD
        .decode(&extra_credential.controller_cert_chain)
        .expect("confilesystem8 - failed to base64 decode controller_cert_chain");
    let controller_cert_chain = serde_json::from_slice(controller_cert_chain_decode.as_slice())
        .expect("confilesystem8 - failed to json un-marsh controller_cert_chain");
    let controller_attester_report = AttesterReport {
        attester: ATTESTER_CONTROLLER.to_string(),
        attestation_report: controller_attestation_report,
        cert_chain: Some(controller_cert_chain),
    };
    attestation_reports.push(controller_attester_report);

    // metadata
    let mut metadata_attestation_report = get_attestation_report(report_data.clone());
    let mut metadata_cert_chain: Vec<CertTableEntry> = Vec::new();
    metadata_cert_chain.push(get_cert(report_data.clone(), extra_credential));

    let metadata_attestation_report_str = serde_json::to_string(&metadata_attestation_report)
        .expect("confilesystem8 - fail to json marsh metadata_attestation_report");
    let metadata_cert_chain_str = serde_json::to_string(&metadata_cert_chain)
        .expect("confilesystem8 - fail to json marsh metadata_cert_chain");
    log::info!("confilesystem8 - EmulateAttester.get_metadata_ra_evidence(): metadata_attestation_report_str = {:?}", metadata_attestation_report_str);
    log::info!("confilesystem8 - EmulateAttester.get_metadata_ra_evidence(): metadata_cert_chain_str = {:?}", metadata_cert_chain_str);

    let metadata_attester_report = AttesterReport {
        attester: extra_credential.aa_attester.clone(),
        attestation_report: metadata_attestation_report,
        cert_chain: Some(metadata_cert_chain),
    };
    attestation_reports.push(metadata_attester_report);

    let ra_evidence = RAEvidence {
        crp_token: Some(extra_credential.controller_crp_token.to_string()),
        attestation_reports: attestation_reports,
    };
    Ok(ra_evidence)
}

fn get_workload_ra_evidence(
    report_data: Vec<u8>,
    extra_credential: &crate::extra_credential::ExtraCredential,
) -> Result<RAEvidence> {
    let mut attestation_reports: Vec<AttesterReport> = Vec::new();

    // controller
    if extra_credential.controller_crp_token.len() == 0
        || extra_credential.controller_attestation_report.len() == 0
        || extra_credential.controller_cert_chain.len() == 0
    {
        bail!("confilesystem8 - unavailable controller_crp_token || controller_attestation_report || controller_cert_chain");
    }
    // confilesystem : base64 decode first
    let controller_attestation_report_decode = base64::engine::general_purpose::STANDARD
        .decode(&extra_credential.controller_attestation_report)
        .expect("confilesystem8 - failed to base64 decode controller_attestation_report");
    let mut controller_attestation_report: AttestationReport =
        serde_json::from_slice(controller_attestation_report_decode.as_slice())
            .expect("confilesystem8 - failed to json un-marsh controller_attestation_report");
    let controller_report_data = get_hash_48bites(&extra_credential.controller_crp_token);
    controller_attestation_report.report_data[..REPORT_DATA_LEN_DEFAULT]
        .copy_from_slice(&controller_report_data.as_slice());
    let controller_cert_chain_decode = base64::engine::general_purpose::STANDARD
        .decode(&extra_credential.controller_cert_chain)
        .expect("confilesystem8 - failed to base64 decode controller_cert_chain");
    let controller_cert_chain = serde_json::from_slice(controller_cert_chain_decode.as_slice())
        .expect("confilesystem8 - failed to json un-marsh controller_cert_chain");
    let controller_attester_report = AttesterReport {
        attester: ATTESTER_CONTROLLER.to_string(),
        attestation_report: controller_attestation_report,
        cert_chain: Some(controller_cert_chain),
    };
    attestation_reports.push(controller_attester_report);

    // workload
    let mut workload_attestation_report = get_attestation_report(report_data.clone());
    let mut workload_cert_chain: Vec<CertTableEntry> = Vec::new();
    workload_cert_chain.push(get_cert(report_data.clone(), extra_credential));
    let workload_attester_report = AttesterReport {
        attester: extra_credential.aa_attester.clone(),
        attestation_report: workload_attestation_report,
        cert_chain: Some(workload_cert_chain),
    };
    attestation_reports.push(workload_attester_report);

    let ra_evidence = RAEvidence {
        crp_token: Some(extra_credential.controller_crp_token.to_string()),
        attestation_reports: attestation_reports,
    };
    Ok(ra_evidence)
}

fn get_attestation_report(report_data: Vec<u8>) -> AttestationReport {
    log::info!(
        "confilesystem5 - get_attestation_report(): report_data.len() = {:?}",
        report_data.len()
    );

    let mut firmware = Firmware::open()
        .expect("confilesystem5 - SnpAttester.get_evidence(): fail to Firmware::open()");
    let data = report_data.as_slice().try_into().expect("report_data as slice error");

    let mut attestation_report = firmware
        .get_report(None, Some(data), Some(0))
        .context("confilesystem5 - Failed to get attestation report by firmware.get_report()")
        .map_err(|e| anyhow!("confilesystem5 - SnpAttester.get_evidence(): fail to firmware.get_report()) e = {:?}", e));
    log::info!("confilesystem5 - SnpAttester.get_evidence(): firmware.get_report() -> attestation_report = {:?}", attestation_report);
    attestation_report.expect("attestation_report error")
}

fn get_cert(
    report_data: Vec<u8>,
    extra_credential: &crate::extra_credential::ExtraCredential,
) -> CertTableEntry {
    let data: Vec<u8> = Vec::new();
    let cert = CertTableEntry::new(CertType::Empty, data);
    cert
}

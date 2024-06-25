// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::env;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::{CertTableEntry, CertType};
use sha2::{Digest, Sha384};

//
pub const ATTESTER_SECURITY: &str = "security";
pub const ATTESTER_CONTROLLER: &str = "controller";
pub const ATTESTER_METADATA: &str = "metadata";
pub const ATTESTER_WORKLOAD: &str = "workload";

pub const ENV_CFS_SECURITY_ID: &str  ="CFS_SECURITY_ID";
pub const ENV_CFS_CONTROLLER_ID: &str  ="CFS_CONTROLLER_ID";
pub const ENV_CFS_METADATA_ID: &str  ="CFS_METADATA_ID";
pub const ENV_CFS_WORKLOAD_ID: &str  ="CFS_WORKLOAD_ID";

pub const CFS_SECURITY_ID_DEFAULT: &str  ="confidential_filesystems_default_attester_security";
pub const CFS_CONTROLLER_ID_DEFAULT: &str  ="confidential_filesystems_default_attester_controller";
pub const CFS_METADATA_ID_DEFAULT: &str  ="confidential_filesystems_default_attester_metadata";
pub const CFS_WORKLOAD_ID_DEFAULT: &str  ="confidential_filesystems_default_attester_workload";

const ENV_EMULATE_GUEST_SVN: u32 = 0xFFFFFFFF;

const REPORT_DATA_LEN_DEFAULT: usize = 48;

// If the environment variable "AA_EMULATE_ATTESTER" is set,
// the TEE platform is considered as "emulate".
pub fn detect_platform() -> bool {
    env::var("AA_EMULATE_ATTESTER").is_ok()
}

// A Emulate evidence.
#[derive(Serialize, Deserialize, Debug)]
struct AttesterReport {
    attester: String,
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EmulateQuote {
    crp_token: Option<String>,
    attestation_reports: Vec<AttesterReport>,
}

impl EmulateQuote {
    fn default() -> EmulateQuote {
        let attester_report = AttesterReport{
            attester: "".to_string(),
            attestation_report: AttestationReport::default(),
            cert_chain: None,
        };
        let mut attestation_reports:Vec<AttesterReport> = Vec::new();
        attestation_reports.push(attester_report);
        let evidence = EmulateQuote {
            crp_token: None,
            attestation_reports: attestation_reports,
        };
        evidence
    }
}

#[derive(Debug, Default)]
pub struct EmulateAttester {}

#[async_trait::async_trait]
impl Attester for EmulateAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>, extra_credential: &crate::extra_credential::ExtraCredential) -> Result<String> {
        log::info!("confilesystem10 - EmulateAttester.get_evidence(): report_data.len() = {:?}, \
            extra_credential.controller_crp_token.len() = {:?}, extra_credential.extra_request = {:?}",
            report_data.len(), extra_credential.controller_crp_token.len(), extra_credential.extra_request);
        report_data.resize(REPORT_DATA_LEN_DEFAULT, 0);

        let evidence = get_emulate_quote(report_data, extra_credential)?;
            //.expect("confilesystem8 - failed to get emulate quote");
        log::info!("confilesystem10 - EmulateAttester.get_evidence(): evidence = {:?}", evidence);
        serde_json::to_string(&evidence).map_err(|_| anyhow!("Serialize emulate evidence failed"))
    }
}

fn get_emulate_quote(report_data: Vec<u8>, extra_credential: &crate::extra_credential::ExtraCredential) -> Result<EmulateQuote> {
    log::info!("confilesystem10 - get_emulate_quote(): extra_credential.aa_attester = {:?}", extra_credential.aa_attester);
    let mut emulate_quote = EmulateQuote::default();

    match extra_credential.aa_attester.as_str() {
        ATTESTER_SECURITY => {
            emulate_quote = match get_security_emulate_quote(report_data.clone(), extra_credential) {
                core::result::Result::Ok(emulate_quote_content) => emulate_quote_content,
                Err(e) => bail!("confilesystem10 - fail to get security emulate quoute: e = {:?}", e)
            };
        },
        ATTESTER_CONTROLLER => {
            emulate_quote = match get_controller_emulate_quote(report_data.clone(), extra_credential) {
                core::result::Result::Ok(emulate_quote_content) => emulate_quote_content,
                Err(e) => bail!("confilesystem10 - fail to get controller emulate quoute: e = {:?}", e)
            };
        },
        ATTESTER_METADATA => {
            emulate_quote = match get_metadata_emulate_quote(report_data.clone(), extra_credential) {
                core::result::Result::Ok(emulate_quote_content) => emulate_quote_content,
                Err(e) => bail!("confilesystem10 - fail to get metadata emulate quoute: e = {:?}", e)
            };
        },
        ATTESTER_WORKLOAD => {
            emulate_quote = match get_workload_emulate_quote(report_data.clone(), extra_credential) {
                core::result::Result::Ok(emulate_quote_content) => emulate_quote_content,
                Err(e) => bail!("confilesystem10 - fail to get workload emulate quoute: e = {:?}", e)
            };
        },
        _ => {
            return Err(anyhow!("confilesystem10 - unavailable extra_credential.aa_attester = {:?}", extra_credential.aa_attester));
        }
    }

    Ok(emulate_quote)
}

fn get_security_emulate_quote(report_data: Vec<u8>, extra_credential: &crate::extra_credential::ExtraCredential) -> Result<EmulateQuote> {
    log::info!("confilesystem10 - get_security_emulate_quote(): extra_credential.controller_crp_token.len() = {:?}", extra_credential.controller_crp_token.len());
    let mut new_report_data = report_data;
    if extra_credential.controller_crp_token.len() > 0 {
        new_report_data = get_hash_48bites(&extra_credential.controller_crp_token).to_vec();
    }

    let mut attestation_reports:Vec<AttesterReport> = Vec::new();
    // confilesystem : get measurement from env var:
    let security_id = env::var(ENV_CFS_SECURITY_ID).unwrap_or_else(|_| CFS_SECURITY_ID_DEFAULT.to_string());
    let measurement = get_hash_48bites(&security_id);
    let mut attestation_report = get_emulate_attestation_report(new_report_data.clone(),
                                                                &measurement, ENV_EMULATE_GUEST_SVN, extra_credential);
    let mut cert_chain: Vec<CertTableEntry> = Vec::new();
    cert_chain.push(get_emulate_cert(new_report_data.clone(), extra_credential));

    let attestation_report_str = serde_json::to_string(&attestation_report)?;
    //.expect("confilesystem8 - fail to json marsh attestation_report");
    let attestation_report_vec = serde_json::to_vec(&attestation_report)?;
    //.expect("confilesystem8 - fail to json marsh attestation_report to vec");
    let attestation_report_base64 = base64::engine::general_purpose::STANDARD.encode(attestation_report_vec.as_slice());
    let cert_chain_str = serde_json::to_string(&cert_chain)?;
    //.expect("confilesystem8 - fail to json marsh cert_chain");
    let cert_chain_vec = serde_json::to_vec(&cert_chain)?;
    //.expect("confilesystem8 - fail to json marsh cert_chain to vec");
    let cert_chain_base64 = base64::engine::general_purpose::STANDARD.encode(cert_chain_vec.as_slice());
    log::info!("confilesystem10 - EmulateAttester.get_security_emulate_quote(): attestation_report_str = {:?}", attestation_report_str);
    log::info!("confilesystem8 - EmulateAttester.get_security_emulate_quote(): attestation_report_base64 = {:?}", attestation_report_base64);
    log::info!("confilesystem8 - EmulateAttester.get_security_emulate_quote(): cert_chain_str = {:?}", cert_chain_str);
    log::info!("confilesystem8 - EmulateAttester.get_security_emulate_quote(): cert_chain_base64 = {:?}", cert_chain_base64);

    let attester_report = AttesterReport{
        attester: extra_credential.aa_attester.clone(),
        attestation_report: attestation_report,
        cert_chain: Some(cert_chain),
    };
    attestation_reports.push(attester_report);
    let emulate_quote = EmulateQuote {
        crp_token: None,
        attestation_reports: attestation_reports,
    };
    Ok(emulate_quote)
}

fn get_controller_emulate_quote(report_data: Vec<u8>, extra_credential: &crate::extra_credential::ExtraCredential) -> Result<EmulateQuote> {
    log::info!("confilesystem10 - get_controller_emulate_quote(): extra_credential.controller_crp_token.len() = {:?}", extra_credential.controller_crp_token.len());
    let mut new_report_data = report_data;
    if extra_credential.controller_crp_token.len() > 0 {
        new_report_data = get_hash_48bites(&extra_credential.controller_crp_token).to_vec();
    }

    let mut attestation_reports:Vec<AttesterReport> = Vec::new();
    // confilesystem : get measurement from env var:
    let controller_id = env::var(ENV_CFS_CONTROLLER_ID).unwrap_or_else(|_| CFS_CONTROLLER_ID_DEFAULT.to_string());
    let measurement = get_hash_48bites(&controller_id);
    let mut attestation_report = get_emulate_attestation_report(new_report_data.clone(),
        &measurement, ENV_EMULATE_GUEST_SVN, extra_credential);
    let mut cert_chain: Vec<CertTableEntry> = Vec::new();
    cert_chain.push(get_emulate_cert(new_report_data.clone(), extra_credential));

    let attestation_report_str = serde_json::to_string(&attestation_report)?;
        //.expect("confilesystem8 - fail to json marsh attestation_report");
    let attestation_report_vec = serde_json::to_vec(&attestation_report)?;
        //.expect("confilesystem8 - fail to json marsh attestation_report to vec");
    let attestation_report_base64 = base64::engine::general_purpose::STANDARD.encode(attestation_report_vec.as_slice());
    let cert_chain_str = serde_json::to_string(&cert_chain)?;
        //.expect("confilesystem8 - fail to json marsh cert_chain");
    let cert_chain_vec = serde_json::to_vec(&cert_chain)?;
        //.expect("confilesystem8 - fail to json marsh cert_chain to vec");
    let cert_chain_base64 = base64::engine::general_purpose::STANDARD.encode(cert_chain_vec.as_slice());
    log::info!("confilesystem10 - EmulateAttester.get_controller_emulate_quote(): attestation_report_str = {:?}", attestation_report_str);
    log::info!("confilesystem8 - EmulateAttester.get_controller_emulate_quote(): attestation_report_base64 = {:?}", attestation_report_base64);
    log::info!("confilesystem8 - EmulateAttester.get_controller_emulate_quote(): cert_chain_str = {:?}", cert_chain_str);
    log::info!("confilesystem8 - EmulateAttester.get_controller_emulate_quote(): cert_chain_base64 = {:?}", cert_chain_base64);

    let attester_report = AttesterReport{
        attester: extra_credential.aa_attester.clone(),
        attestation_report: attestation_report,
        cert_chain: Some(cert_chain),
    };
    attestation_reports.push(attester_report);
    let emulate_quote = EmulateQuote {
        crp_token: None,
        attestation_reports: attestation_reports,
    };
    Ok(emulate_quote)
}

fn get_metadata_emulate_quote(report_data: Vec<u8>, extra_credential: &crate::extra_credential::ExtraCredential) -> Result<EmulateQuote> {
    let mut attestation_reports:Vec<AttesterReport> = Vec::new();

    // controller
    if extra_credential.controller_crp_token.len() == 0
        || extra_credential.controller_attestation_report.len() == 0
        || extra_credential.controller_cert_chain.len() == 0 {
        bail!("confilesystem8 - unavailable controller_crp_token || controller_attestation_report || controller_cert_chain");
    }
    // confilesystem : base64 decode first
    let controller_attestation_report_decode = base64::engine::general_purpose::STANDARD.decode(&extra_credential.controller_attestation_report)
        .expect("confilesystem8 - failed to base64 decode controller_attestation_report");
    let mut controller_attestation_report: AttestationReport = serde_json::from_slice(controller_attestation_report_decode.as_slice())
        .expect("confilesystem8 - failed to json un-marsh controller_attestation_report");
    let controller_report_data = get_hash_48bites(&extra_credential.controller_crp_token);
    controller_attestation_report.report_data[..REPORT_DATA_LEN_DEFAULT].copy_from_slice(&controller_report_data.as_slice());
    let controller_cert_chain_decode = base64::engine::general_purpose::STANDARD.decode(&extra_credential.controller_cert_chain)
        .expect("confilesystem8 - failed to base64 decode controller_cert_chain");
    let controller_cert_chain = serde_json::from_slice(controller_cert_chain_decode.as_slice())
        .expect("confilesystem8 - failed to json un-marsh controller_cert_chain");
    let controller_attester_report = AttesterReport{
        attester: ATTESTER_CONTROLLER.to_string(),
        attestation_report: controller_attestation_report,
        cert_chain: Some(controller_cert_chain),
    };
    attestation_reports.push(controller_attester_report);

    // metadata
    let metadata_id = env::var(ENV_CFS_METADATA_ID).unwrap_or_else(|_| CFS_METADATA_ID_DEFAULT.to_string());
    let measurement = get_hash_48bites(&metadata_id);
    let mut metadata_attestation_report = get_emulate_attestation_report(report_data.clone(),
        &measurement, ENV_EMULATE_GUEST_SVN, extra_credential);
    let mut metadata_cert_chain: Vec<CertTableEntry> = Vec::new();
    metadata_cert_chain.push(get_emulate_cert(report_data.clone(), extra_credential));

    let metadata_attestation_report_str = serde_json::to_string(&metadata_attestation_report)
        .expect("confilesystem8 - fail to json marsh metadata_attestation_report");
    let metadata_cert_chain_str = serde_json::to_string(&metadata_cert_chain)
        .expect("confilesystem8 - fail to json marsh metadata_cert_chain");
    log::info!("confilesystem8 - EmulateAttester.get_metadata_emulate_quote(): metadata_attestation_report_str = {:?}", metadata_attestation_report_str);
    log::info!("confilesystem8 - EmulateAttester.get_metadata_emulate_quote(): metadata_cert_chain_str = {:?}", metadata_cert_chain_str);

    let metadata_attester_report = AttesterReport{
        attester: extra_credential.aa_attester.clone(),
        attestation_report: metadata_attestation_report,
        cert_chain: Some(metadata_cert_chain),
    };
    attestation_reports.push(metadata_attester_report);

    let emulate_quote = EmulateQuote {
        crp_token: Some(extra_credential.controller_crp_token.to_string()),
        attestation_reports: attestation_reports,
    };
    Ok(emulate_quote)
}

fn get_workload_emulate_quote(report_data: Vec<u8>, extra_credential: &crate::extra_credential::ExtraCredential) -> Result<EmulateQuote> {
    let mut attestation_reports:Vec<AttesterReport> = Vec::new();

    // controller
    if extra_credential.controller_crp_token.len() == 0
        || extra_credential.controller_attestation_report.len() == 0
        || extra_credential.controller_cert_chain.len() == 0 {
        bail!("confilesystem8 - unavailable controller_crp_token || controller_attestation_report || controller_cert_chain");
    }
    // confilesystem : base64 decode first
    let controller_attestation_report_decode = base64::engine::general_purpose::STANDARD.decode(&extra_credential.controller_attestation_report)
        .expect("confilesystem8 - failed to base64 decode controller_attestation_report");
    let mut controller_attestation_report: AttestationReport = serde_json::from_slice(controller_attestation_report_decode.as_slice())
        .expect("confilesystem8 - failed to json un-marsh controller_attestation_report");
    let controller_report_data = get_hash_48bites(&extra_credential.controller_crp_token);
    controller_attestation_report.report_data[..REPORT_DATA_LEN_DEFAULT].copy_from_slice(&controller_report_data.as_slice());
    let controller_cert_chain_decode = base64::engine::general_purpose::STANDARD.decode(&extra_credential.controller_cert_chain)
        .expect("confilesystem8 - failed to base64 decode controller_cert_chain");
    let controller_cert_chain = serde_json::from_slice(controller_cert_chain_decode.as_slice())
        .expect("confilesystem8 - failed to json un-marsh controller_cert_chain");
    let controller_attester_report = AttesterReport{
        attester: ATTESTER_CONTROLLER.to_string(),
        attestation_report: controller_attestation_report,
        cert_chain: Some(controller_cert_chain),
    };
    attestation_reports.push(controller_attester_report);

    // workload
    let workload_id = env::var(ENV_CFS_WORKLOAD_ID).unwrap_or_else(|_| CFS_WORKLOAD_ID_DEFAULT.to_string());
    let measurement = get_hash_48bites(&workload_id);
    let mut workload_attestation_report = get_emulate_attestation_report(report_data.clone(),
        &measurement, ENV_EMULATE_GUEST_SVN, extra_credential);
    let mut workload_cert_chain: Vec<CertTableEntry> = Vec::new();
    workload_cert_chain.push(get_emulate_cert(report_data.clone(), extra_credential));
    let workload_attester_report = AttesterReport{
        attester: extra_credential.aa_attester.clone(),
        attestation_report: workload_attestation_report,
        cert_chain: Some(workload_cert_chain),
    };
    attestation_reports.push(workload_attester_report);

    let emulate_quote = EmulateQuote {
        crp_token: Some(extra_credential.controller_crp_token.to_string()),
        attestation_reports: attestation_reports,
    };
    Ok(emulate_quote)
}

fn get_emulate_attestation_report(report_data: Vec<u8>, measurement: &[u8; REPORT_DATA_LEN_DEFAULT], guest_svn: u32,
                                  extra_credential: &crate::extra_credential::ExtraCredential) -> AttestationReport {
    log::info!("confilesystem10 - get_emulate_attestation_report(): report_data.len() = {:?}", report_data.len());
    let mut emulate_attestation_report = AttestationReport::default();
    emulate_attestation_report.report_data[..REPORT_DATA_LEN_DEFAULT].copy_from_slice(&report_data.as_slice());
    emulate_attestation_report.measurement[..REPORT_DATA_LEN_DEFAULT].copy_from_slice(measurement);
    emulate_attestation_report.guest_svn = guest_svn;
    emulate_attestation_report
}

fn get_emulate_cert(report_data: Vec<u8>, extra_credential: &crate::extra_credential::ExtraCredential) -> CertTableEntry {
    let data: Vec<u8> = Vec::new();
    let cert = CertTableEntry::new(CertType::Empty, data);
    cert
}

pub fn get_hash_48bites(input: &str) -> [u8; REPORT_DATA_LEN_DEFAULT] {
    let mut hasher = Sha384::new();
    hasher.update(input.as_bytes());
    let partial_hash = hasher.finalize();
    let mut hash = [0u8; REPORT_DATA_LEN_DEFAULT];
    // copy_from_slice:
    // Copies all elements from src into self, using a memcpy.
    // The length of src must be the same as self.
    // If T does not implement Copy, use clone_from_slice.
    // This function will panic if the two slices have different lengths.
    hash[..REPORT_DATA_LEN_DEFAULT].copy_from_slice(&partial_hash);
    hash
}

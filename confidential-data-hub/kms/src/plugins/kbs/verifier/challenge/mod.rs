use std::collections::HashMap;
use std::env;
use anyhow::{anyhow, Context, Result};
//extern crate serde;
//use super::*;
use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha384};
use log::{debug, info, warn};
use kbs_types::{Attestation};
use crate::plugins::kbs::get_kbs_infos;
use crate::plugins::kbs::resource::{Repository};
use crate::plugins::kbs::verifier::{Verifier};
use crate::plugins::kbs::verifier::types::{TeeEvidenceParsedClaim, RAEvidence, CRPTPayload};
use crate::plugins::kbs::verifier::types::{expected_hash, verify_crpt, default_authed_res_for_controller, authed_res};


const ENV_CFS_EMULATED_MODE: &str  ="CFS_EMULATED_MODE";

pub const ATTESTER_SECURITY: &str = "security";
pub const ATTESTER_CONTROLLER: &str = "controller";
pub const ATTESTER_METADATA: &str = "metadata";
pub const ATTESTER_WORKLOAD: &str = "workload";

pub const ENV_CFS_SECURITY_ID: &str  ="CFS_SECURITY_ID";
pub const ENV_CFS_CONTROLLER_ID: &str  ="CFS_CONTROLLER_ID";
pub const ENV_CFS_METADATA_ID: &str  ="CFS_METADATA_ID";
pub const ENV_CFS_WORKLOAD_ID: &str  ="CFS_WORKLOAD_ID";

pub const CFS_SECURITY_ID_DEFAULT: &str  ="cc_cfs_security_2024";
pub const CFS_CONTROLLER_ID_DEFAULT: &str  ="cc_cfs_controller_2024";
pub const CFS_METADATA_ID_DEFAULT: &str  ="cc_cfs_metadata_2024";
pub const CFS_WORKLOAD_ID_DEFAULT: &str  ="cc_cfs_workload_2024";

const EMULATED_GUEST_SVN: u32 = std::u32::MAX;

#[derive(Debug, Default)]
pub struct Challenge {}

#[async_trait]
impl Verifier for Challenge {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
        repository: &Box<dyn Repository + Send + Sync>,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_str::<RAEvidence>(&attestation.tee_evidence)
            .context("Deserialize Quote failed.")?;

        let mut hasher = Sha384::new();
        hasher.update(&nonce);
        hasher.update(&attestation.tee_pubkey.k_mod);
        hasher.update(&attestation.tee_pubkey.k_exp);
        let mut hash = [0u8; 48];
        hash[..48].copy_from_slice(&hasher.finalize());
        // let reference_report_data =
        //     base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

        let crpt_payload = verify_tee_evidence(hash, &tee_evidence, repository)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("Evidence<Challenge>: {:?}", tee_evidence);

        parse_tee_evidence(&tee_evidence, &crpt_payload)
    }
}

async fn verify_tee_evidence(
    reference_report_data: [u8; 48],
    tee_evidence: &RAEvidence,
    repository: &Box<dyn Repository + Send + Sync>
) -> Result<CRPTPayload> {
    println!("confilesystem20 println- verify_tee_evidence(): tee_evidence.attestation_reports.len() = {:?}",
             tee_evidence.attestation_reports.len());

    // Verify the TEE Hardware signature. (Null for Challenge TEE)

    // Emulate the report data.

    if tee_evidence.attestation_reports.len() == 0 {
        return Err(anyhow!("Empty attestation reports!"));
    }

    // check whether run in emulated mode
    let is_emulated = is_emulated().await?;
    info!("confilesystem20 - Evidence<Challenge>: is_emulated: {}", is_emulated);
    println!("confilesystem20 println- verify_tee_evidence(): is_emulated = {:?}", is_emulated);

    println!("confilesystem20 println- verify_tee_evidence(): tee_evidence.attestation_reports[0].attester = {:?}",
             tee_evidence.attestation_reports[0].attester);

    match tee_evidence.attestation_reports[0].attester.as_str() {
        ATTESTER_SECURITY => {
            if is_emulated {
                let security_att_report = tee_evidence.attestation_reports[0].attestation_report;
                let security_id = env::var(ENV_CFS_SECURITY_ID).unwrap_or_else(|_| CFS_SECURITY_ID_DEFAULT.to_string());
                if security_att_report.measurement != expected_hash(&security_id) {
                    warn!("Invalid security measurement!");
                    return Err(anyhow!("Invalid security measurement!"));
                }

                //security it's self, follow rcar flow
                if security_att_report.report_data[..48] != reference_report_data {
                    warn!("Security's self report data verification failed!");
                    return Err(anyhow!("Security report data verification failed!"));
                }

                // return default CRPTPayload for security
                Ok(CRPTPayload {
                    authorized_res: default_authed_res_for_controller(),
                    runtime_res: HashMap::new(),
                })
            } else {
                // security in CVM
                // TODO snp attest check
                info!("confilesystem20 - Evidence<Challenge>: security in CVM not implemented!");
                println!("confilesystem20 println- verify_tee_evidence(): security in CVM not implemented!");
                return Err(anyhow!("Not implemented!"))
            }
        },
        ATTESTER_CONTROLLER => {
            // check controller report first
            let controller_att_report = tee_evidence.attestation_reports[0].attestation_report;
            if is_emulated {
                // check mock ld
                let controller_id = env::var(ENV_CFS_CONTROLLER_ID).unwrap_or_else(|_| CFS_CONTROLLER_ID_DEFAULT.to_string());
                if controller_att_report.measurement != expected_hash(&controller_id) {
                    warn!("Invalid controller measurement!");
                    return Err(anyhow!("Invalid controller measurement!"));
                }
                // check report data
                if tee_evidence.attestation_reports.len() == 1 {
                    // controller it's self, follow rcar flow
                    if controller_att_report.report_data[..48] != reference_report_data {
                        warn!("Controller's self report data verification failed!");
                        return Err(anyhow!("Controller report data verification failed!"));
                    }
                } else {
                    // report_data should be the hash of the crp_token
                    match &tee_evidence.crp_token {
                        Some(crp_token) => {
                            if controller_att_report.report_data[..48] != expected_hash(crp_token) {
                                warn!("Controller report data(crp_token hash) verification failed!");
                                return Err(anyhow!("Controller report data verification failed!"));
                            }
                        }
                        None => {
                            warn!("Invalid controller reports!");
                            return Err(anyhow!("Invalid controller reports!"));
                        }
                    }
                }
            } else {
                // controller in CVM
                // TODO snp attest check
                info!("confilesystem20 - Evidence<Challenge>: controller in CVM not implemented!");
                println!("confilesystem20 println- verify_tee_evidence(): controller in CVM not implemented!");
                return Err(anyhow!("Not implemented!"))
            }

            match &tee_evidence.crp_token {
                Some(crp_token) => {
                    // check metadata or workload report
                    let att_report = &tee_evidence.attestation_reports[1];
                    if att_report.attester == "metadata" {
                        if !is_emulated {
                            warn!("Invalid metadata report!");
                            return Err(anyhow!("Invalid metadata report!"))
                        }
                        let meta_att_report = att_report.attestation_report;
                        // check mock ld
                        let metadata_id = env::var(ENV_CFS_METADATA_ID).unwrap_or_else(|_| CFS_METADATA_ID_DEFAULT.to_string());
                        if meta_att_report.measurement != expected_hash(&metadata_id) {
                            warn!("Invalid metadata measurement!");
                            return Err(anyhow!("Invalid metadata measurement!"));
                        }
                        // check report data
                        if meta_att_report.report_data[..48] != reference_report_data {
                            warn!("Metadata report data verification failed!");
                            return Err(anyhow!("Metadata report data verification failed!"));
                        }
                    } else if att_report.attester == "workload" {
                        let workload_att_report = att_report.attestation_report;
                        if is_emulated || workload_att_report.guest_svn == EMULATED_GUEST_SVN {
                            // check mock ld
                            let workload_id = env::var(ENV_CFS_WORKLOAD_ID).unwrap_or_else(|_| CFS_WORKLOAD_ID_DEFAULT.to_string());
                            if workload_att_report.measurement != expected_hash(&workload_id) {
                                warn!("Invalid workload measurement!");
                                return Err(anyhow!("Invalid workload measurement!"));
                            }
                            // check report data
                            if workload_att_report.report_data[..48] != reference_report_data {
                                warn!("Workload report data verification failed!");
                                return Err(anyhow!("Workload report data verification failed!"));
                            }
                        } else {
                            // workload in CVM
                            // TODO snp attest check
                            return Err(anyhow!("Not implemented!"))
                        }
                    } else {
                        warn!("Unsupported attestation report: {}", att_report.attester);
                        return Err(anyhow!("Unsupported attestation report: {}", att_report.attester ));
                    }
                    // verify crp_token
                    return verify_crpt(crp_token, repository).await
                }
                None => {
                    // should be controller it's self, already checked
                    if tee_evidence.attestation_reports.len() > 1 {
                        warn!("Invalid attestation reports! No crp_token");
                        return Err(anyhow!("Invalid attestation reports! No crp_token"));
                    }
                },
            }

            // return default CRPTPayload for controller
            Ok(CRPTPayload {
                authorized_res: default_authed_res_for_controller(),
                runtime_res: HashMap::new(),
            })
        },
        _ => {
            return Err(anyhow!("Invalid attestation reports! First is not controller's or security's report"));
        }
    }
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(_quote: &RAEvidence, crpt_payload: &CRPTPayload) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "authorized_res": authed_res(&crpt_payload),
    });
    debug!("EvidenceParsedClaim<Challenge>: {:?}", claims_map);
    Ok(claims_map as TeeEvidenceParsedClaim)
}

async fn is_emulated() -> anyhow::Result<bool> {
    //let is_emulated = env::var(ENV_CFS_EMULATED_MODE).unwrap_or_else(|_| "false".to_string()) == "true";
    let kbs_infos = get_kbs_infos().await?;
    println!("confilesystem20 println- is_emulated():  kbs_infos = {:?}", kbs_infos);
    Ok(kbs_infos.kbs_is_emulated)
}

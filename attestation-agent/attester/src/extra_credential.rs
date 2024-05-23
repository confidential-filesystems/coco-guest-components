// confilesystem

use serde::{Deserialize, Serialize};
use anyhow::{Result};

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct ExtraCredential {
    //
    pub controller_crp_token: String,
    //
    pub controller_attestation_report: String,
    //
    pub controller_cert_chain: String,
    //
    pub aa_attester: String,
    //
    pub container_name: String,
}

impl ExtraCredential {
    pub fn default() -> ExtraCredential {
        let extra_credential = ExtraCredential{
            controller_crp_token: "".to_string(),
            controller_attestation_report: "".to_string(),
            controller_cert_chain: "".to_string(),
            aa_attester: "".to_string(),
            container_name: "".to_string(),
        };
        extra_credential
    }

    pub fn new(controller_crp_token: String,
               controller_attestation_report: String,
               controller_cert_chain: String,
               aa_attester: String,
               container_name: String) -> ExtraCredential {
        let extra_credential = ExtraCredential{
            controller_crp_token,
            controller_attestation_report,
            controller_cert_chain,
            aa_attester,
            container_name,
        };
        extra_credential
    }

    pub fn from_string(ec: &str) -> Result<ExtraCredential> {
        let extra_credential: ExtraCredential = serde_json::from_str(ec)?;
        Ok(extra_credential)
    }

    pub fn to_string(&self) -> Result<String> {
        //let output = serde_json::to_string(&self).unwrap()?;
        let output = serde_json::to_string(self).expect("fail to serde_json::to_string");
            //.as_bytes()
            //.to_vec();
        Ok(output)
    }
}
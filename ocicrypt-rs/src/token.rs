// add confilesystem

use std::collections::{HashMap};
use anyhow::{anyhow, Result};
use slog::{info};

//use log::{info};
// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

// AuthorizedRes
#[derive(Clone, Default, Debug)]
pub struct AuthorizedRes {
    pub exp: u64, // Duration, // UnixTimeStamp
    pub res: String,
}

// InternalExtraData
#[derive(Debug)]
pub struct InternalExtraData {
    pub controller_crp_token: String,
    pub controller_attestation_report: String,
    pub controller_cert_chain: String,
    pub aa_attester: String,
    pub container_name: String,
    //
    pub key_id: String,
    pub key_user: String,
    pub authorized_res: Vec<AuthorizedRes>,
    pub runtime_res: HashMap<String, HashMap<String, HashMap<String, String>>>,
    //pub custom_claims: CustomClaims,
    //
    pub is_init_container: bool,
    pub is_workload_container: bool,
}

impl InternalExtraData {
    pub fn can_get_res(&self, res_id: &str) -> bool {
        let authorized_res = &self.authorized_res;
        let now = coarsetime::Clock::now_since_epoch().as_secs();
        info!(sl(), "confilesystem8 ocicrypt-rs - can_get_res(): res_id = {:?}, authorized_res = {:?}; now = {:?}",
            res_id, authorized_res, now);
        if authorized_res.len() == 0 {
            return true;
        }

        let mut new_res_id = res_id.to_string();
        if !res_id.starts_with("kbs://") {
            new_res_id = format!("{}{}", "kbs:///", res_id)
        }
        info!(sl(), "confilesystem8 ocicrypt-rs - can_get_res(): res_id = {:?} -> new_res_id = {:?}", res_id, new_res_id);
        let res_id_slices: Vec<&str> = new_res_id.split('/').filter(|&s| !s.is_empty()).collect();
        if res_id_slices.len() < 4 {
            return false;
        }

        let mut can_get = false;
        for a_res in authorized_res {
            // confilesystem : check pattern *
            if a_res.res == "*"
                || a_res.res == "*/*/*"
                || a_res.res == "*:///*/*/*" {
                return true;
            }

            let a_res_slices: Vec<&str> = (&a_res.res).split('/').filter(|&s| !s.is_empty()).collect();
            if a_res_slices.len() < 4 {
                return false;
            }

            if (a_res_slices[0] == "*:" || a_res_slices[0] == res_id_slices[0]) // "*:///*/*/*"
                && (a_res_slices[1] == "*" || a_res_slices[1] == res_id_slices[1])
                && (a_res_slices[2] == "*" || a_res_slices[2] == res_id_slices[2])
                && (a_res_slices[3] == "*" || a_res_slices[3] == res_id_slices[3]) {
                if a_res.exp < now {
                    info!(sl(), "confilesystem6 - a_res.res = {:?}'s a_res.exp = {:?} < now = {:?}",
                        a_res.res, a_res.exp, now);
                    break;
                }
                can_get = true;
                break;
            }
        }
        can_get
    }

    pub fn addr_is_ok(&self, addr: &str) -> bool {
        if self.key_user.len() == 0 || self.key_user == "*".to_string() {
            return true;
        }

        if addr.to_string() != self.key_user {
            info!(sl(), "confilesystem8 ocicrypt-rs - addr_is_ok(): addr = {:?} != self.key_user = {:?}",
                addr.to_string(), self.key_user);
            return false;
        }
        return true;
    }
}

// ExtraCredential
#[derive(Serialize, Deserialize)]
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
    pub extra_request: String,
}

impl ExtraCredential {
    pub fn default() -> ExtraCredential {
        let extra_credential = ExtraCredential{
            controller_crp_token: "".to_string(),
            controller_attestation_report: "".to_string(),
            controller_cert_chain: "".to_string(),
            aa_attester: "".to_string(),
            extra_request: "".to_string(),
        };
        extra_credential
    }

    pub fn new(controller_crp_token: String,
               controller_attestation_report: String,
               controller_cert_chain: String,
               aa_attester: String,
               extra_request: String) -> ExtraCredential {
        let extra_credential = ExtraCredential{
            controller_crp_token,
            controller_attestation_report,
            controller_cert_chain,
            aa_attester,
            extra_request,
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

// AnnotationPacket
#[derive(Serialize, Deserialize, Debug)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: resource_uri::ResourceUri,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

// util apis
pub fn get_addr_from_res_id(res_id: &str) -> Result<String> {
    let mut new_res_id = res_id.to_string();
    if !res_id.starts_with("kbs://") {
        new_res_id = format!("{}{}", "kbs:///", res_id)
    }

    let path_slices: Vec<&str> = new_res_id.split('/').filter(|&s| !s.is_empty()).collect();
    info!(sl(), "confilesystem6 - get_addr_from_res_id(): res_id = {:?} -> new_res_id = {:?} -> path_slices = {:?}",
        res_id, new_res_id, path_slices);
    if path_slices.len() < 2 {
        return Err(anyhow!("confilesystem6 - res kid format error"));
    }
    let addr = path_slices[1];
    Ok(addr.to_string())
}

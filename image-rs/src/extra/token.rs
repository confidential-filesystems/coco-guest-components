// confilesystem

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::*;
use slog::{info, error};
use coarsetime::{Clock, Duration/*, UnixTimeStamp*/};
#[allow(unused_imports)]
use serde::{Serialize, Deserialize};
#[allow(unused_imports)]
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
#[allow(unused_imports)]
use hex::*;
#[allow(unused_imports)]
use anyhow::{Context, anyhow, Result, Error, ensure, bail};
#[allow(unused_imports)]
use jwt_simple::prelude::{
    ES256PublicKey, Ed25519PublicKey, EdDSAPublicKeyLike, ECDSAP256PublicKeyLike, NoCustomClaims, VerificationOptions,
};
#[allow(unused_imports)]
use jwt_simple::prelude::{
    JWTClaims, Token
};
//use jwt_simple::reexports::ct_codecs::base64::{Base64UrlSafeNoPadding};
//use jwt_simple::serde_additions;
use jwt_simple::prelude::*;

use crate::resource;

//
pub const POD_CONTAINERS_SHARE_DIR: &str = "/run/kata-containers/sandbox/";

pub const ATTESTER_CONTROLLER: &str = "controller";
pub const ATTESTER_METADATA: &str = "metadata";
pub const ATTESTER_WORKLOAD: &str = "workload";

#[allow(dead_code)]
const CONTROLLER_CFS_EC_PUB_KEY: &str = "controller/cfs-ec-pub";
//const CONTROLLER_CFS_EC_PUB_KID: &str = "kid";
#[allow(dead_code)]
const CONTROLLER_CFS_EC_PUB_KBS_PREFIX: &str = "kbs:///controller/cfs-ec-pub/";

// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

//#[derive(Debug, Serialize, Deserialize)]
//#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
//#[derive(Debug, Serialize, Deserialize)]
//#[derive(Debug, Serialize, Deserialize)]
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct AuthorizedRes {
    // Time the claims expire at
    #[serde(
    rename = "exp",
    default,
    )]
    pub exp: u64, // Duration, // UnixTimeStamp

    // Resource - This can be set to anything application-specific
    #[serde(rename = "res", default)]
    pub res: String,
}

//#[derive(Debug, Serialize, Deserialize)]
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct CustomClaims {
    // Version - This can be set to anything application-specific
    //#[serde(rename = "svn", default)]
    //pub svn: String,

    // authorized-res
    pub authorized_res: Vec<AuthorizedRes>,

    // runtime-res
    pub runtime_res: HashMap<String, HashMap<String, HashMap<String, String>>>,
}

impl CustomClaims {
    /// Create a new instance of `CustomClaims`.
    pub fn init() -> Self {
        CustomClaims {
            //svn: "1".to_string(),
            authorized_res: vec![],
            runtime_res: HashMap::new(),
        }
    }
}

// ExternalExtraData
#[derive(Default, Debug)]
pub struct ExternalExtraData {
    pub controller_crp_token: String,
    pub controller_attestation_report: String,
    pub controller_cert_chain: String,
    pub aa_attester: String,
    //
    pub container_name: String,
    pub is_init_container: bool,
}

impl ExternalExtraData {
    /// Create a new instance of `ExternalExtraData`.
    pub fn new(controller_crp_token: String, controller_attestation_report: String, controller_cert_chain: String,
               aa_attester: String, container_name: String, is_init_container: bool) -> Self {
        ExternalExtraData {
            controller_crp_token: controller_crp_token,
            controller_attestation_report: controller_attestation_report,
            controller_cert_chain: controller_cert_chain,
            aa_attester: aa_attester,
            container_name: container_name,
            is_init_container: is_init_container,
        }
    }

    pub async fn proc(&self, aa_kbc_params: &str, confidential_image_digests_str: &str) -> Result<InternalExtraData, Error> {
        info!(sl(), "confilesystem5 - ExternalExtraData.proc(): aa_kbc_params = {:?}, confidential_image_digests_str = {:?}, \
            self.aa_attester = {:?}, self.controller_crp_token.len() = {:?}",
            aa_kbc_params, confidential_image_digests_str, self.aa_attester, self.controller_crp_token.len());
        if self.aa_attester != ATTESTER_CONTROLLER.to_string()
            && (self.controller_crp_token.len() == 0
                || self.controller_attestation_report.len() == 0
                || self.controller_cert_chain.len() == 0) {
            error!(sl(), "confilesystem8 - ExternalExtraData.proc(): self.aa_attester = {:?}, But self.controller_crp_token.len() = {:?}\
                || self.controller_attestation_report.len() = {:?} || self.controller_cert_chain.len() = {:?}",
                self.aa_attester, self.controller_crp_token.len(), self.controller_attestation_report.len(), self.controller_cert_chain.len());
        }

        let mut ie_data = InternalExtraData::init(self.controller_crp_token.clone(),
                                                  self.controller_attestation_report.clone(),
                                                  self.controller_cert_chain.clone(),
                                                  self.aa_attester.to_string(),
                                                  self.container_name.to_string(),
                                                  self.is_init_container);
        let confidential_image_digests_tmp: Vec<&str> = confidential_image_digests_str
            .split(',').filter(|&s| !s.is_empty()).collect();
        let mut confidential_image_digests = Vec::new();
        for digest in confidential_image_digests_tmp {
            confidential_image_digests.push(digest.to_string());
        }
        info!(sl(), "confilesystem5 - ExternalExtraData.proc(): confidential_image_digests_str = {:?} -> confidential_image_digests = {:?}",
            confidential_image_digests_str, confidential_image_digests);
        ie_data.confidential_image_digests = confidential_image_digests;

        if self.controller_crp_token.len() == 0 {
            // for controller?
            let mut authorized_res: Vec<AuthorizedRes> = Vec::new();
            let exp = Duration::from_mins(10).as_secs();
            let now = Clock::now_since_epoch().as_secs();
            let kbs_key_path = "*:///*/*/*";
            authorized_res.push(AuthorizedRes{exp: now + exp, res: kbs_key_path.to_string()});
            ie_data.authorized_res = authorized_res;
            //ie_data.key_id = kbs_key_path.to_string();
            ie_data.key_user = "*".to_string();

            return Ok(ie_data);
        }
        let controller_crp_token = self.controller_crp_token.as_ref();

        //let decrypt_config = image_service.get_security_config().await?;
        if aa_kbc_params.len() > 0 {
            // The secure channel to communicate with KBS.
            // This step will initialize the secure channel
            let mut channel = resource::SECURE_CHANNEL.lock().await;
            *channel = Some(resource::kbs::SecureChannel::new(aa_kbc_params).await?);
        } else {
            error!(sl(), "confilesystem2 - ExternalExtraData.proc(): Secure channel creation needs aa_kbc_params.");
        }

        let metadata = Token::decode_metadata(controller_crp_token)
            .expect("confilesystem2 - decode_metadata error");
        let kbs_key_path = metadata.key_id().expect("confilesystem2 - miss kid");
        info!(sl(), "confilesystem2 - ExternalExtraData.proc(): kbs_key_path = {:?}", kbs_key_path);
        let key_user = get_addr_from_res_id(kbs_key_path).expect("fail to get addr from res id");
        match key_user_is_only_one(&key_user) {
            Ok(ok) => {
                info!(sl(), "confilesystem15 Ok- ExternalExtraData.proc(): key_user_is_only_one(): container_name = {:?} -> ok = {:?}",
                    self.container_name, ok);
            },
            Err(err) => {
                info!(sl(), "confilesystem15 Err- ExternalExtraData.proc(): key_user_is_only_one(): container_name = {:?} -> err = {:?}",
                    self.container_name, err);
                return Err(anyhow!("confilesystem15 - key_user_is_only_one(): err = {:?}", err));
            }
        }

        //
        let mut authorized_res: Vec<AuthorizedRes> = Vec::new();
        let exp = Duration::from_mins(10).as_secs();
        let now = Clock::now_since_epoch().as_secs();
        authorized_res.push(AuthorizedRes{exp: now + exp, res: kbs_key_path.to_string()});
        ie_data.authorized_res = authorized_res;
        ie_data.key_id = kbs_key_path.to_string();
        ie_data.key_user = key_user.to_string();
        //ie_data.custom_claims = CustomClaims::init();

        //let mut pubkey_file_path = decrypt_config + "/controller/cfs/pubkey";
        // "confilesystem2 - get_resource(): uri = \\\"kbs:///default/credential/test\\\"\",
        /*
        info!(sl(), "confilesystem8 - ExternalExtraData.proc(): get_token_pubkey() -> kbs_key_path = {:?} -> key_user = {:?}",
            kbs_key_path, key_user);
        let pubkey_bytes = resource::get_resource(&kbs_key_path, &ie_data).await
            .map_err(|e| anyhow!("confilesystem3 - get_token_pubkey({:?}) failed: {:?}", kbs_key_path, e))?;
        let pubkey_str_got = String::from_utf8_lossy(&pubkey_bytes);
        let pubkey_str = pubkey_str_got.trim_end_matches('\n');
        info!(sl(), "confilesystem2 - ExternalExtraData.proc(): pubkey_str = {:?}", pubkey_str);
        let claims = verify_token_internal(controller_crp_token, pubkey_str)
            .map_err(|e| anyhow!("confilesystem2 - verify_token_internal failed: {:?}", e))?;
        info!(sl(), "confilesystem2 - ExternalExtraData.proc(): verify_token_internal: OK -> claims = {:?}", claims);
        info!(sl(), "confilesystem2 - ExternalExtraData.proc(): verify_token_internal: OK -> claims.custom = {:?}", claims.custom);
        info!(sl(), "confilesystem2 - ExternalExtraData.proc(): verify_token_internal: OK -> claims.custom.runtime_res = {:?}", claims.custom.runtime_res);
        */
        let custom = parse_crptpayload(controller_crp_token)
            .expect("confilesystem8 - fail to parse crpt payload");

        info!(sl(), "confilesystem5 - ExternalExtraData.proc(): OK -> custom = {:?}", custom);
        ie_data.authorized_res = custom.authorized_res;
        ie_data.runtime_res = custom.runtime_res;
        Ok(ie_data)
    }
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
    pub confidential_image_digests: Vec<String>,
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
    /// Create a new instance of `InternalExtraData`.
    pub fn init(controller_crp_token: String, controller_attestation_report: String, controller_cert_chain: String,
                aa_attester: String, container_name: String, is_init_container: bool) -> Self {
        InternalExtraData {
            controller_crp_token: controller_crp_token,
            controller_attestation_report: controller_attestation_report,
            controller_cert_chain: controller_cert_chain,
            aa_attester: aa_attester,
            container_name: container_name,
            //
            confidential_image_digests: vec![],
            //
            key_id: "".to_string(),
            key_user: "".to_string(),
            authorized_res: vec![],
            runtime_res: HashMap::new(),
            //
            is_init_container: is_init_container,
            is_workload_container: false,
        }
    }

    pub async fn proc(&self) -> Result<(), Error> {
        info!(sl(), "confilesystem5 - InternalExtraData.proc(): self.controller_crp_token.len() = {:?}", self.controller_crp_token.len());
        if self.controller_crp_token.len() == 0 {
            return Ok(())
        }

        info!(sl(), "confilesystem2 - InternalExtraData.proc(): self.runtime_res = {:?}", self.runtime_res);
        for (container_name, runtime_res) in &self.runtime_res {
            info!(sl(), "    ---- confilesystem12 - self.container_name = {:?}, container_name = {:?}: runtime_res.len() = {:?}",
                self.container_name, container_name, runtime_res.len());
            if self.container_name == *container_name {
                for (kbs_src, resource_infos) in runtime_res {
                    info!(sl(), "    ---- confilesystem9 - kbs_src = {:?}: resource_infos = {:?}", kbs_src, resource_infos);
                    if kbs_src == CONTROLLER_CFS_EC_PUB_KEY {
                        continue;
                    }

                    let local_dst = match resource_infos.get("target") {
                        Some(target) => target,
                        _ => { bail!("confilesystem21 - runtime_res not include target"); },
                    };

                    let extra_request = match resource_infos.get("extra") {
                        Some(extra) => extra,
                        _ => "extra-request-runtime_res not include extra",
                    };

                    let dst_data = resource::get_resource(kbs_src, &self, extra_request).await
                        .map_err(|e| anyhow!("confilesystem2 - get_resource({:?}) failed: {:?}", kbs_src, e))?;
                    info!(sl(), "    ---- confilesystem2 - kbs_src = {:?} -> dst_data = {:?}", kbs_src, dst_data);

                    let parse = need_to_parse(local_dst);
                    save_dst_data(parse, local_dst, dst_data)
                        .map_err(|e| anyhow!("confilesystem2 - save_dst_data({:?}) failed: {:?}", local_dst, e))?;
                }
            }
        }

        info!(sl(), "confilesystem9 - InternalExtraData.proc(): OK -> self.runtime_res.len() = {:?}",
            self.runtime_res.len());
        Ok(())
    }

    pub fn can_get_res(&self, res_id: &str) -> bool {
        let authorized_res = &self.authorized_res;
        let now = coarsetime::Clock::now_since_epoch().as_secs();
        info!(sl(), "confilesystem8 image-rs - can_get_res(): res_id = {:?}, authorized_res = {:?}; now = {:?}",
            res_id, authorized_res, now);
        if authorized_res.len() == 0 {
            return true;
        }

        let mut new_res_id = res_id.to_string();
        if !res_id.starts_with("kbs://") {
            new_res_id = format!("{}{}", "kbs:///", res_id)
        }
        info!(sl(), "confilesystem8 image-rs - can_get_res(): res_id = {:?} -> new_res_id = {:?}", res_id, new_res_id);
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
                if a_res.exp > 0 && a_res.exp < now {
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
            info!(sl(), "confilesystem8 image-rs - addr_is_ok(): addr = {:?} != self.key_user = {:?}",
                addr.to_string(), self.key_user);
            return false;
        }
        return true;
    }
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

fn key_user_is_only_one(key_user: &str) -> Result<bool, Error> {
    // "/run/kata-containers/sandbox/key_user"
    let existed_key_user_file = &(POD_CONTAINERS_SHARE_DIR.to_string() + "key_user");

    match fs::read_to_string(existed_key_user_file) {
        Ok(content) => {
            info!(sl(), "confilesystem6 - read_to_string({:?}) -> content = {:?}", existed_key_user_file, content);
            if content == key_user.to_string() {
                return Ok(true);
            } else if content.len() > 0 {
                return Err(anyhow!("key_user {:?} comes, but {:?} has existed", key_user, content));
            } else {
                // content is none
            }
        },
        Err(e) => {
            info!(sl(), "confilesystem6 - read_to_string({:?}) -> e = {:?}", existed_key_user_file, e.to_string());
            if e.kind() == std::io::ErrorKind::NotFound {
                // file not exist
            } else {
                return Err(anyhow!("read_to_string({:?}) -> e = {:?}", existed_key_user_file, e.to_string()));
            }
        }
    }

    let dir_path = Path::new(existed_key_user_file).parent().expect("confilesystem6 - fail to get dir");
    info!(sl(), "confilesystem6 - key_user_is_only_one(): dir_path = {:?}", dir_path);
    fs::create_dir_all(dir_path).expect("confilesystem6 - fail to create dir");
    let mut file = fs::File::create(existed_key_user_file)?;
    file.write_all(key_user.as_bytes())?;
    Ok(true)
}

pub fn parse_crptpayload(crp_token: &str) -> Result<CustomClaims> {
    let token_parts: Vec<&str> = crp_token.split('.').collect();
    if token_parts.len() != 3 {
        return Err(anyhow!("Invalid crp_token!"));
    }

    let payload_part_encoded = token_parts[1];
    let payload_part_decoded = &Base64UrlSafeNoPadding::decode_to_vec(payload_part_encoded.as_bytes(), None);
    return match payload_part_decoded {
        Ok(payload_decoded) => match serde_json::from_slice::<CustomClaims>(&payload_decoded) {
            Ok(claims) => Ok(claims),
            Err(e) => Err(anyhow!("Error parsing crp_token from decoded payload:\n{}", e)),
        },
        Err(e) => Err(anyhow!("Error decoding crp_token:\n{}", e)),
    }
}

/*
fn verify_token_internal(token: &str, user_public_key_pem: &str) -> Result<JWTClaims<CustomClaims>, Error> {
    info!(sl(), "confilesystem2 - verify_token_internal(): token = {:?}", token);
    info!(sl(), "confilesystem2 - verify_token_internal(): user_public_key_pem = {:?}", user_public_key_pem);
    let public_key = ES256PublicKey::from_pem(user_public_key_pem) // from_der, from_bytes
        .expect("confilesystem2 - new pubkey fail");
    info!(sl(), "confilesystem2 - verify_token_internal(): public_key = {:?}", public_key);

    let claims = public_key
        .verify_token::<CustomClaims>(token, Some(VerificationOptions::default()))
        .context("confilesystem2 - verify token failed")?;

    info!(sl(), "confilesystem2 - verify_token_internal(): claims = {:?}", claims);
    Ok(claims)
}
*/

/*
async fn get_token_pubkey(controller_crp_token: &str) -> Result<&str, Error> {
    let metadata = Token::decode_metadata(controller_crp_token)?;
    let kid = metadata.key_id().expect("miss kid");
    info!(sl(), "confilesystem2 - get_token_pubkey(): kid = {:?}", kid);
    let kbs_key_path = CONTROLLER_CFS_EC_PUB_KBS_PREFIX.to_owned() + kid;
    //let mut pubkey_file_path = decrypt_config + "/controller/cfs/pubkey";
    // "confilesystem2 - get_resource(): uri = \\\"kbs:///default/credential/test\\\"\",
    info!(sl(), "confilesystem2 - get_token_pubkey(): kbs_key_path = {:?}", kbs_key_path);
    Ok(&kbs_key_path)

    let pubkey_bytes = resource::get_resource(&kbs_key_path).await
        .map_err(|e| anyhow!("confilesystem2 - get_token_pubkey({:?}) failed: {:?}", kbs_key_path, e))?;
    let mut pubkey_str = String::from_utf8_lossy(&pubkey_bytes);
    Ok(&pubkey_str)
}
*/

fn need_to_parse(local_dst: &str) -> bool {
    return local_dst.ends_with("/");
}

fn save_dst_data(parse: bool, local_dst: &str, dst_data: Vec<u8>) -> Result<()> {
    info!(sl(), "confilesystem8 - save_dst_data(): parse = {:?}, local_dst = {:?}", parse, local_dst);
    if parse {
        fs::create_dir_all(local_dst).expect("confilesystem2 1- fail to create dir");

        //let json_data = serde_json::from_slice(&dst_data).expect("confilesystem2 1- fail to parse json");
        let dst_data_str = String::from_utf8_lossy(&dst_data);
        let json_data = serde_json::from_str(dst_data_str.as_ref()).expect("confilesystem2 1- fail to parse json");
        info!(sl(), "confilesystem2 - save_dst_data(): json_data = {:?}", json_data);
        if let Value::Object(obj) = json_data {
            for (key, value) in obj {
                info!(sl(), "confilesystem13 - key = {:?} -> value = {:?}", key, value);
                let local_dst_file = local_dst.to_owned() + "/" + &key;
                let mut file = fs::File::create(local_dst_file)?;
                //file.write_all(value.to_string().as_bytes())?;
                //fs::write(local_dst_file, value.to_string())?;
                let lines = value.to_string();

                let pat_str = "\\n";
                let lines_slices: Vec<&str> = lines.split(pat_str).filter(|&s| !s.is_empty()).collect(); // ?
                info!(sl(), "confilesystem14 - key = {:?}, pat_str = {:?} -> lines_slices = {:?}", key, pat_str, lines_slices);
                // lines.lines()
                for line in lines_slices {
                    let new_line = line.replace("\"", "");
                    if new_line.len() > 0 {
                        writeln!(&mut file, "{}", new_line)?;
                    }
                }
            }
        }
    } else {
        let dir_path = Path::new(local_dst).parent().expect("confilesystem2 2- fail to get dir");
        info!(sl(), "confilesystem2 - save_dst_data(): dir_path = {:?}", dir_path);
        fs::create_dir_all(dir_path).expect("confilesystem2 2- fail to create dir");

        let mut file = fs::File::create(local_dst)?;
        file.write_all(&dst_data)?;
    }
    Ok(())
}

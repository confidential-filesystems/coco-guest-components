use slog::{info};
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{anyhow, bail, Context, Result};
#[allow(unused_imports)]
use regex::Regex;
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};
use crate::extra::token::sl;
use base64::Engine;

pub struct InternalController {
    digests: Vec<String>,        // list of allowed cfs image digests
    commands: Vec<String>, // list of allowed commands for cfs containers

    kbs_url: String,
    addr: String, // account address of the workload images
    timestamp: u64,
    workload_commands: Vec<String>, // list of allowed commands for workload containers
    workload_container_ids: Vec<String>,
}

lazy_static! {
pub static ref IC: Arc<Mutex<InternalController>> = Arc::new(Mutex::new(InternalController {
        digests: vec![],
        commands: vec![],
        kbs_url: "".to_string(),
        addr: "".to_string(),
        timestamp: 0,
        workload_commands: vec![],
        workload_container_ids: vec![],
    }));
}

impl InternalController {

    pub fn set_kbs_url(&mut self, kbs_url: String) {
        info!(sl(), "confilesystem - set_kbs_url: {:?}", kbs_url);
        self.kbs_url = kbs_url;
    }
    pub fn set_addr(&mut self, addr: String) {
        info!(sl(), "confilesystem - set_addr: {:?}", addr);
        self.addr = addr;
    }

    pub fn set_digests(&mut self, digests: String) {
        self.digests = digests.split(',').filter(|&s| !s.is_empty()).map(|s| s.to_string()).collect();
        info!(sl(), "confilesystem - set_digests: {:?}", self.digests);
    }

    pub fn get_digests(&self) -> Vec<String> {
        return self.digests.clone();
    }

    pub fn get_commands(&self) -> Vec<String> {
        return self.commands.clone();
    }

    pub fn set_commands(&mut self, command: String) {
        info!(sl(), "confilesystem - set_commands: {:?}", command.clone());
        let commands: Vec<String> = command.split(',').filter(|&s| !s.is_empty())
            .filter_map(|s| {
                let decoded =base64::engine::general_purpose::STANDARD_NO_PAD.decode(s);
                if decoded.is_ok(){
                    return Some(String::from_utf8(decoded.unwrap()).unwrap());
                }
                info!(sl(), "confilesystem - set_commands failed to decode: {:?}", s.to_string());
                return None;
            }).collect();
        info!(sl(), "confilesystem - set_commands result: {:?}", commands);
        for command in commands {
            let mut modified_command = String::from(command);
            if !modified_command.starts_with('^') {
                modified_command.insert(0, '^');
            }
            if !modified_command.ends_with('$') {
                modified_command.push('$');
            }
            self.commands.push(modified_command);
        }
    }

    pub fn add_workload_container_id(&mut self, id: String) {
        if !self.workload_container_ids.contains(&id){
            info!(sl(), "confilesystem - add_workload_container_id: {:?}", id.clone());
            self.workload_container_ids.push(id);
        }
    }

    pub fn remove_workload_container_id(&mut self, id: String) {
        for (i, id_) in self.workload_container_ids.iter().enumerate() {
            if id_ == &id {
                self.workload_container_ids.remove(i);
                break;
            }
        }
    }

    pub fn is_allowed_digest(&self, digest: String) -> bool {
        return self.digests.contains(&digest);
    }

    pub fn is_allowed_command(&mut self, cid: String, command_args: Vec<String>) -> Result<(), anyhow::Error> {
        let mut allowed_commands :Vec<String> = self.commands.clone();
        let command = command_args.join(" ");
        info!(sl(), "confilesystem - is_allowed_command command: {:?}", command.clone());
        if self.workload_container_ids.contains(&cid) {
            // workload container
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            info!(sl(), "confilesystem - is_allowed_command workload cid: {:?}, pre-timestamp: {:?}, current_time: {:?}", cid.clone(), self.timestamp, current_time);
            if self.timestamp + 10 < current_time {
                // try to get the command again
                info!(sl(), "confilesystem - getting commands of {:?}", self.addr);
                let command_result = self.get_allowed_commands(&self.addr);
                if command_result.is_ok() {
                    self.timestamp = current_time;
                    self.workload_commands.clear();
                    let command_result = command_result.unwrap();
                    info!(sl(), "confilesystem - got commands: {:?}", command_result);
                    for command in command_result {
                        let mut modified_command = command.clone();
                        if !modified_command.starts_with('^') {
                            modified_command.insert(0, '^');
                        }
                        if !modified_command.ends_with('$') {
                            modified_command.push('$');
                        }
                        self.workload_commands.push(modified_command);
                    }
                } else {
                    info!(sl(), "confilesystem - unable to get commands of: {:?}", self.addr);
                    bail!("Unable to get commands of {:?}", self.addr);
                }
            }
            allowed_commands = self.workload_commands.clone();
        }

        for regex in allowed_commands {
            let re = regex::Regex::new(&regex);
            if re.is_ok() && re.unwrap().is_match(&command) {
                info!(sl(), "confilesystem - commands {:?} is allowed", command);
                return Ok(());
            }
        }
        info!(sl(), "confilesystem - commands {:?} is not allowed", command);
        bail!("Command not allowed");
    }

    pub fn get_allowed_commands(&self, addr: &String) -> Result<Vec<String>, anyhow::Error> {
        let command_url: String = format!(
            "{}/kbs/v0/cfs/{}/commands/commands",
            self.kbs_url, addr
        );

        let mut command_rsp_result = reqwest::blocking::get(command_url.clone()).context("Unable to send request for commands");
        if command_rsp_result.is_err() {
            info!(sl(), "confilesystem - got commands failed, try again. err: {:?}", command_rsp_result.err());
            command_rsp_result = reqwest::blocking::get(command_url.clone()).context("Unable to send request for commands");
        }
        if command_rsp_result.is_err() {
            info!(sl(), "confilesystem - got commands failed, err: {:?}", command_rsp_result.err());
            return Err(anyhow!("Unable to get commands response"));
        }

        let command_rsp_text = command_rsp_result
            .unwrap()
            .text()
            .context("Unable to get commands response text")?;
        let command_rsp_json: Vec<String> = serde_json::from_str(&command_rsp_text)
            .context("Unable to parse commands response json")?;
        Ok(command_rsp_json)
    }
}
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use api_ttrpc::create_sealed_secret_service;
use clap::Parser;
use log::info;
use server::Server;
use tokio::{
    fs,
    signal::unix::{signal, SignalKind},
};
use ttrpc::r#async::Server as TtrpcServer;
use kms::plugins;

use crate::api_ttrpc::create_resource_service;

mod api;
mod api_ttrpc;
mod server;

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers";
const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";

const AA_ATTESTER: &str = "all";

const KBS_URL: &str = "http://10.11.35.45:31111"; // "http://127.0.0.1:8080";
const KBS_LD: &str = "confidential_filesystems_default_attester_security";
const KBS_IS_EMULATED: &str = "true";

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// CDH ttRPC Unix socket addr.
    ///
    /// CDH will listen to this unix socket address.
    ///
    /// `--socket unix:///tmp/cdh_keyprovider`
    #[arg(default_value_t = DEFAULT_CDH_SOCKET_ADDR.to_string(), short)]
    socket: String,

    // aa_attester of attestation-agent
    #[arg(default_value_t = AA_ATTESTER.to_string(), short, long = "aa_attester")]
    aa_attester: String,

    // kbs url
    #[arg(default_value_t = KBS_URL.to_string(), short, long = "kbs_url")]
    kbs_url: String,

    // kbs ld
    #[arg(default_value_t = KBS_LD.to_string(), short, long = "kbs_ld")]
    kbs_ld: String,

    // kbs is_emulated
    #[arg(default_value_t = KBS_IS_EMULATED.to_string(), short, long = "kbs_is_emulated")]
    kbs_is_emulated: String,
}

macro_rules! ttrpc_service {
    ($func: expr) => {{
        let server = Server::new().await?;
        let server = Arc::new(Box::new(server) as _);
        $func(server)
    }};
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    //println!("cctata11 - Starting confidential-data-hub : cli.aa_attester = {:?}", cli.aa_attester);
    plugins::kbs::set_kbs_infos(&cli.aa_attester, &cli.kbs_url, &cli.kbs_ld, &cli.kbs_is_emulated)
        .await
        .context("set kbs infos failed")?;

    if !Path::new(DEFAULT_UNIX_SOCKET_DIR).exists() {
        fs::create_dir_all(DEFAULT_UNIX_SOCKET_DIR)
            .await
            .context("create unix socket dir failed")?;
    }

    let sealed_secret_service = ttrpc_service!(create_sealed_secret_service);
    let resource_service = ttrpc_service!(create_resource_service);
    let mut server = TtrpcServer::new()
        .bind(&cli.socket)
        .context("cannot bind cdh ttrpc service")?
        .register_service(sealed_secret_service)
        .register_service(resource_service);

    server.start().await?;

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => {
            info!("Client terminal disconnected.");
            server.shutdown().await?;
        }
        _ = interrupt.recv() => {
            info!("SIGINT received, gracefully shutdown.");
            server.shutdown().await?;
        }
    };

    Ok(())
}

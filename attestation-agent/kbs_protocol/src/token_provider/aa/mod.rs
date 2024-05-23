// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a token provider which connects the attestation-agent

mod attestation_agent;
mod attestation_agent_ttrpc;

use async_trait::async_trait;
use protobuf::MessageField;
use serde::Deserialize;
use ttrpc::context;

use crate::{Error, Result, TeeKeyPair, Token};

use self::{
    attestation_agent::GetTokenRequest, attestation_agent_ttrpc::AttestationAgentServiceClient,
};

use super::TokenProvider;

const AA_SOCKET_FILE: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

const TOKEN_TYPE: &str = "kbs";

pub struct AATokenProvider {
    client: AttestationAgentServiceClient,
}

#[derive(Deserialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

impl AATokenProvider {
    pub async fn new() -> Result<Self> {
        let c = ttrpc::r#async::Client::connect(AA_SOCKET_FILE)
            .map_err(|e| Error::AATokenProvider(format!("ttrpc connect failed {e}")))?;
        let client = AttestationAgentServiceClient::new(c);
        Ok(Self { client })
    }
}

#[async_trait]
impl TokenProvider for AATokenProvider {
    async fn get_token(&self, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<(Token, TeeKeyPair)> {
        let extra_credential = attestation_agent::ExtraCredential {
            ControllerCrpToken: extra_credential.controller_crp_token.clone(),
            ControllerAttestationReport: extra_credential.controller_attestation_report.clone(),
            ControllerCertChain: extra_credential.controller_cert_chain.clone(),
            AAAttester: extra_credential.aa_attester.clone(),
            ContainerName: extra_credential.container_name.clone(),
            ..Default::default()
        };
        let req = GetTokenRequest {
            TokenType: TOKEN_TYPE.to_string(),
            ExtraCredential: protobuf::MessageField::some(extra_credential),
            ..Default::default()
        };
        let bytes = self
            .client
            .get_token(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .map_err(|e| Error::AATokenProvider(format!("cal ttrpc failed: {e}")))?;
        let message: Message = serde_json::from_slice(&bytes.Token).map_err(|e| {
            Error::AATokenProvider(format!("deserialize attestation-agent reply failed: {e}"))
        })?;
        let token = Token::new(message.token)
            .map_err(|e| Error::AATokenProvider(format!("deserialize token failed: {e}")))?;
        let tee_keypair = TeeKeyPair::from_pkcs1_pem(&message.tee_keypair)
            .map_err(|e| Error::AATokenProvider(format!("deserialize tee keypair failed: {e}")))?;
        Ok((token, tee_keypair))
    }
}

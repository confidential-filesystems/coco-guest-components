// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use crypto::{decrypt, WrapType};
use kbs_protocol::{
    client::KbsClient,
    evidence_provider::{EvidenceProvider, NativeEvidenceProvider},
    KbsClientBuilder, KbsClientCapabilities,
};

use super::AnnotationPacket;
use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use resource_uri::ResourceUri;
use zeroize::Zeroizing;

pub struct Kbc {
    token: Option<String>,
    kbs_client: KbsClient<Box<dyn EvidenceProvider>>,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        log::info!("confilesystem8 - cc_kbc.decrypt_payload(): annotation_packet.kid = {:?}", annotation_packet.kid);
        let key_data = self.kbs_client.get_resource(annotation_packet.kid, extra_credential).await?;
        let key = Zeroizing::new(key_data);

        let wrap_type = WrapType::try_from(&annotation_packet.wrap_type[..])?;
        decrypt(
            key,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.wrapped_data)?,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.iv)?,
            wrap_type,
        )
    }

    async fn get_resource(&mut self, desc: ResourceUri, extra_credential: &attester::extra_credential::ExtraCredential) -> Result<Vec<u8>> {
        log::info!("confilesystem2 - cc_kbc.get_resource(): desc = {:?}", desc);

        let data = self.kbs_client.get_resource(desc, extra_credential).await?;

        Ok(data)
    }
}

impl Kbc {
    pub fn new(kbs_uri: String) -> Result<Kbc> {
        log::info!("confilesystem8 - cc_kbc.new(): kbs_uri = {:?}", kbs_uri);
        let kbs_client = KbsClientBuilder::with_evidence_provider(
            Box::new(NativeEvidenceProvider::new()?),
            &kbs_uri,
        )
        .build()?;
        Ok(Kbc {
            token: None,
            kbs_client,
        })
    }
}

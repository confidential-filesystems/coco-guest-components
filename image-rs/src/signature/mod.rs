// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod image;
pub mod mechanism;
pub mod payload;
pub mod policy;

use crate::{config::Paths, signature::policy::Policy};
use std::convert::TryFrom;

use anyhow::{Result};
use oci_distribution::secrets::RegistryAuth;

#[cfg(feature = "signature-cosign")]
#[allow(unused_imports)]
use sigstore::{
    cosign::{
        verification_constraint::{PublicKeyVerifier, VerificationConstraintVec},
        verify_constraints, ClientBuilder, CosignCapabilities,
    },
    crypto::SigningScheme,
    errors::SigstoreVerifyConstraintsError,
    registry::Auth,
};

#[cfg(feature = "signature-cosign")]
use sigstore::cosign::SignatureLayer;

#[cfg(feature = "signature")]
use crate::{resource, signature::image::Image};

use anyhow::{Context};
use crate::extra::controller::IC;

/// `allows_image` will check all the `PolicyRequirements` suitable for
/// the given image. The `PolicyRequirements` is defined in
/// [`policy_path`] and may include signature verification.
#[allow(unused_assignments)]
#[cfg(feature = "signature")]
pub async fn allows_image(
    image_reference: &str,
    image_digest: &str,
    auth: &RegistryAuth,
    file_paths: &Paths,
    ie_data: &mut crate::extra::token::InternalExtraData,
) -> Result<()> {
    slog::info!(sl(), "confilesystem12 - allows_image(): ie_data.aa_attester = {:?}, image_reference = {:?}, file_paths.policy_path = {:?}",
        ie_data.aa_attester, image_reference, file_paths.policy_path);
    let cid = ie_data.cid.clone();
    let mut digests: Vec<String>= vec![];
    {
        let ic = IC.lock().unwrap();
        digests = ic.get_digests();
    }
    let container_command = ie_data.container_command.clone();
    if ie_data.aa_attester == crate::extra::token::ATTESTER_SECURITY
        || ie_data.aa_attester == crate::extra::token::ATTESTER_CONTROLLER
        || ie_data.aa_attester == crate::extra::token::ATTESTER_METADATA {
        {
            let mut ic = IC.lock().unwrap();
            if ic.is_allowed_digest(image_digest.to_string()) {
                slog::info!(sl(), "confilesystem12 0-In- allows_image(): image_reference = {:?}, image_digest = {:?} In confidential_image_digests = {:?}",
                    image_reference, image_digest, digests);
                let result = ic.is_allowed_command(cid, container_command.clone());
                if result.is_err() {
                    return Err(anyhow::anyhow!("confilesystem12 - command {:?} is not allowed", container_command));
                }
                return Ok(());
            }
        }
        slog::info!(sl(), "confilesystem12 0-NotIn- allows_image(): image_reference = {:?}, image_digest = {:?} Not In confidential_image_digests = {:?}",
                    image_reference, image_digest, digests);
        return Err(anyhow::anyhow!("confilesystem12 - allows_image(): Not find image_digest = {:?} in confidential_image_digests = {:?} for ie_data.aa_attester = {:?}",
                image_digest, digests, ie_data.aa_attester));
    }

    let reference = oci_distribution::Reference::try_from(image_reference)?;
    let mut image = Image::default_with_reference(reference);
    image.set_manifest_digest(image_digest)?;

    // Get the signature layers in cosign signature "image"'s manifest
    let signature_layers_result = match get_signature_layers(&image, auth).await {
        Ok(layers) => {
            ie_data.is_workload_container = true;
            {
                let mut ic = IC.lock().unwrap();
                ic.add_workload_container_id(cid.clone());
            }
            Ok(layers)
        },
        Err(e) => {
            ie_data.is_workload_container = false;
            slog::info!(sl(), "confilesystem12 1-Err- allows_image(): image_reference = {:?}, image_digest = {:?} -> e = {:?}",
                image_reference, image_digest, e);
            {
                let mut ic = IC.lock().unwrap();
                if ic.is_allowed_digest(image_digest.to_string()) {
                    slog::info!(sl(), "confilesystem12 1-In- allows_image(): image_reference = {:?}, image_digest = {:?} In confidential_image_digests = {:?}",
                    image_reference, image_digest, digests);
                    let result = ic.is_allowed_command(cid, container_command.clone());
                    if result.is_err() {
                        return Err(anyhow::anyhow!("confilesystem12 - command {:?} is not allowed", container_command));
                    }
                    return Ok(());
                }
            }
            slog::info!(sl(), "confilesystem12 1-NotIn- allows_image(): image_reference = {:?}, image_digest = {:?} Not In confidential_image_digests = {:?}",
                    image_reference, image_digest, digests);
            Err(anyhow::anyhow!("confilesystem12 - allows_image(): fail to get signature layers AND not find image_digest = {:?} in confidential_image_digests = {:?}",
                image_digest, digests))
        }
    };
    if signature_layers_result.is_err() {
        return Err(anyhow::anyhow!("confilesystem12 - allows_image(): signature_layers_result is Err"));
    }
    let signature_layers = signature_layers_result.unwrap();
    slog::info!(sl(), "confilesystem12 - allows_image(): signature_layers.len() = {:?}", signature_layers.len());
    if signature_layers.len() < 1 {
        return Err(anyhow::anyhow!("confilesystem12 - allows_image(): no availabe signature layers"));
    }
    let last_signature_layer = &signature_layers[signature_layers.len()-1];
    slog::info!(sl(), "confilesystem12 - allows_image(): last_signature_layer.simple_signing.optional = {:?}",
        last_signature_layer.simple_signing.optional);
    if last_signature_layer.simple_signing.optional.is_none() {
        return Err(anyhow::anyhow!("confilesystem12 - allows_image(): last_signature_layer.simple_signing.optional is None"));
    }
    let optional =  last_signature_layer.simple_signing.optional.as_ref().unwrap();
    let value = match optional.extra.get(IMAGE_POLICY_ID_KEY){
        Some(content) => content,
        None => {
            ie_data.is_workload_container = false;
            {
                let mut ic = IC.lock().unwrap();
                ic.remove_workload_container_id(cid.clone());
                slog::info!(sl(), "confilesystem12 2-None- allows_image(): optional.extra.get({:?}) -> None", IMAGE_POLICY_ID_KEY);
                if ic.is_allowed_digest(image_digest.to_string()) {
                    slog::info!(sl(), "confilesystem12 2-In- allows_image(): image_reference = {:?}, image_digest = {:?} In confidential_image_digests = {:?}",
                    image_reference, image_digest, digests);
                    let result = ic.is_allowed_command(cid, container_command.clone());
                    if result.is_err() {
                        return Err(anyhow::anyhow!("confilesystem12 - command {:?} is not allowed", container_command));
                    }
                    return Ok(());
                }
            }
            slog::info!(sl(), "confilesystem12 2-NotIn- allows_image(): image_reference = {:?}, image_digest = {:?} Not In confidential_image_digests = {:?}",
                    image_reference, image_digest, digests);
            return Err(anyhow::anyhow!("confilesystem12 - allows_image(): fail to get IMAGE_POLICY_ID AND not find image_digest = {:?} in confidential_image_digests = {:?}",
                image_digest, digests));
        }
    };
    if value.as_str().is_none() {
        return Err(anyhow::anyhow!("confilesystem12 - allows_image(): value.as_str() is None"));
    }
    let image_policy_id = value.as_str().unwrap();

    // confilesystem: image_sign_addr == crp_sign_addr
    let image_sign_addr = crate::extra::token::get_addr_from_res_id(image_policy_id)?;
    if !ie_data.addr_is_ok(&image_sign_addr) {
        return Err(anyhow::anyhow!("confilesystem12 - allows_image(): image_sign_addr = {:?} -> addr_is_ok() = false", image_sign_addr));
    }
    {
        let mut ic = IC.lock().unwrap();
        ic.set_addr(image_sign_addr);
        let result = ic.is_allowed_command(cid, container_command.clone());
        if result.is_err() {
            return Err(anyhow::anyhow!("confilesystem12 - command {:?} is not allowed", container_command));
        }
    }

    // Read the set of signature schemes that need to be verified
    // of the image from the policy configuration.
    slog::info!(sl(), "confilesystem18 - allows_image(): image_policy_id = {:?}", image_policy_id);
    let policy_json_vec = resource::get_resource(image_policy_id/*&file_paths.policy_path*/, ie_data, "extra-request-allows_image").await?;
    slog::info!(sl(), "confilesystem18 - allows_image(): policy_json_vec = {:?}", policy_json_vec);
    let policy_json_str = String::from_utf8_lossy(&policy_json_vec);
    slog::info!(sl(), "confilesystem18 - allows_image(): policy_json_str = {:?}", policy_json_str);
    match serde_json::from_slice::<Policy>(&policy_json_vec) {
        Ok(_) => {

        },
        Err(err) => {
            slog::info!(sl(), "confilesystem18 - allows_image(): serde_json::from_slice::Policy -> err = {:?}", err);
        }
    }
    let mut policy = serde_json::from_slice::<Policy>(&policy_json_vec)?;
    slog::info!(sl(), "confilesystem18 - allows_image(): policy = 1...");
    let schemes = policy.signature_schemes(&image);

    // Get the necessary resources from KBS if needed.
    for scheme in schemes {
        scheme.init(file_paths, ie_data).await?;
    }

    slog::info!(sl(), "confilesystem18 - allows_image(): policy = 2...");
    policy
        .is_image_allowed(image, auth, signature_layers, ie_data)
        .await
        .map_err(|e| anyhow::anyhow!("confilesystem18 - allows_image(): policy.is_image_allowed(): Validate image failed: {:?}", e))
}

const IMAGE_POLICY_ID_KEY: &str = "image/cfs-ivp"; // "image/policyid";

//use log::{info};
// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

#[cfg(feature = "signature")]
async fn get_signature_layers(image: &Image, auth: &RegistryAuth) -> Result<Vec<SignatureLayer>> {
    // Get the signature layers in cosign signature "image"'s manifest
    let image_ref = image.reference.whole();
    let auth = auth.clone();
    let signature_layers = tokio::task::spawn_blocking(move || -> Result<_> {
        let auth = Auth::from(&auth);
        let mut client = ClientBuilder::default().build()?;

        // Get the cosign signature "image"'s uri and the signed image's digest
        //
        // We need a runtime here because now `triangulate` is a future
        // that cannot be `Send` between threads. Thus we need to create a
        // runtime and disable context switch here.
        let rt = tokio::runtime::Runtime::new()?;
        let (cosign_image, source_image_digest) =
            rt.block_on(client.triangulate(&image_ref, &auth))?;

        slog::info!(sl(), "confilesystem4 - get_signature_layers(): auth = {:?}", auth);
        slog::info!(sl(), "confilesystem4 - get_signature_layers(): source_image_digest = {:?}", source_image_digest);
        slog::info!(sl(), "confilesystem4 - get_signature_layers(): cosign_image = {:?}", cosign_image);
        let layers = rt.block_on(client.trusted_signature_layers(
            &auth,
            &source_image_digest,
            &cosign_image,
        ))?;

        Ok(layers)
    }).await
    .context("confilesystem4 - tokio spawn")?
    .context("confilesystem4 - get signature layers")?;
    slog::info!(sl(), "confilesystem4 - get_signature_layers(): signature_layers.len() = {:?}", signature_layers.len());
    Ok(signature_layers)
}

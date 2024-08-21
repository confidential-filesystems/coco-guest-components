use std::collections::HashMap;
use anyhow::{anyhow, Context, Result};
use base64::Engine;
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use asn1_rs::{oid, Integer, OctetString, Oid};
use async_trait::async_trait;
use kbs_types::TeePubKey;
use log::{debug, warn};
use openssl::{bn, ec::EcKey, ecdsa, pkey::{PKey, Public}, x509};
use reqwest::StatusCode;
use reqwest::blocking::{get, Response};
use serde_json::json;
use serde_big_array::BigArray;
use sev::certs::snp::ecdsa::Signature;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::{CertTableEntry, CertType};
use sha2::{Digest, Sha384, Sha256};
use x509_parser::prelude::*;
use tokio::fs;
use std::path::Path;
use crate::plugins::kbs::verifier::types::{TeeEvidenceParsedClaim, RAEvidence, AttReport};

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Vec<CertTableEntry>,
}

const HW_ID_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);
const UCODE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
const SNP_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
const TEE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
const LOADER_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);

const PROC_TYPE_MILAN: &str = "Milan";
/// 3rd Gen AMD EPYC Processor (Standard)
const PROC_TYPE_GENOA: &str = "Genoa";
/// 4th Gen AMD EPYC Processor (Standard)
const CERT_STORAGE_PATH: &str = "/run/as/certs/";

#[derive(Debug, Default)]
pub struct Snp {}

#[async_trait]
impl Verifier for Snp {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
        _repository: &Box<dyn Repository + Send + Sync>,
    ) -> Result<TeeEvidenceParsedClaim> {
        // let tee_evidence = serde_json::from_str::<SnpEvidence>(&attestation.tee_evidence)
        //     .context("Deserialize Quote failed.")?;
        //
        // verify_report_signature(&tee_evidence)?;
        //
        // let report = tee_evidence.attestation_report;
        // if report.version != 2 {
        //     return Err(anyhow!("Unexpected report version"));
        // }
        //
        // if report.vmpl != 0 {
        //     return Err(anyhow!("VMPL Check Failed"));
        // }
        //
        // let expected_report_data = calculate_expected_report_data(&nonce, &attestation.tee_pubkey);
        // if report.report_data != expected_report_data {
        //     return Err(anyhow!("Report Data Mismatch"));
        // }

        // Ok(parse_tee_evidence(&report))
        fs::create_dir_all(CERT_STORAGE_PATH).await?;

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

        verify_tee_evidence(hash, &tee_evidence)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("kbs Evidence<Snp>: {:?}", tee_evidence);

        Ok(parse_tee_evidence(&tee_evidence.attestation_reports[0].attestation_report))
    }
}


async fn verify_tee_evidence(
    reference_report_data: [u8; 48],
    tee_evidence: &RAEvidence,
) -> Result<()> {
    // Verify the TEE Hardware signature.
    if tee_evidence.attestation_reports.len() != 1 {
        return Err(anyhow!("Invalid attestation reports!"));
    }
    // should be security attestation
    if tee_evidence.attestation_reports[0].attester != "security" {
        return Err(anyhow!(
            "Invalid attestation reports! Not security's report"
        ));
    }

    // check security report
    let security_att_report = tee_evidence.attestation_reports[0].attestation_report;
    // TODO: check ld
    // if security_att_report.measurement != "security_ld" {
    //     warn!("Invalid security measurement!");
    //     return Err(anyhow!("Invalid security measurement!"));
    // }

    if security_att_report.version != 2 {
        return Err(anyhow!("Unexpected report version"));
    }

    if security_att_report.vmpl != 0 {
        return Err(anyhow!("VMPL Check Failed"));
    }

    // check report data
    if security_att_report.report_data[..48] != reference_report_data {
        warn!("Security report data verification failed!");
        return Err(anyhow!("Security report data verification failed!"));
    }

    verify_report_signature(&tee_evidence.attestation_reports[0])?;

    Ok(())
}

fn get_oid_octets<const N: usize>(
    vcek: &x509_parser::certificate::TbsCertificate,
    oid: Oid,
) -> Result<[u8; N]> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    // Previously, the hwID extension hasn't been encoded as DER octet string.
    // In this case, the value of the extension is the hwID itself (64 byte long),
    // and we can just return the value.
    if val.len() == N {
        return Ok(val.try_into().unwrap());
    }

    // Parse the value as DER encoded octet string.
    let (_, val_octet) = OctetString::from_der(val)?;
    val_octet
        .as_ref()
        .try_into()
        .context("Unexpected data size")
}

fn get_oid_int(vcek: &x509_parser::certificate::TbsCertificate, oid: Oid) -> Result<u8> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    let (_, val_int) = Integer::from_der(val)?;
    val_int.as_u8().context("Unexpected data size")
}

pub fn verify_report_signature(evidence: &AttReport) -> Result<()> {
    // verify report signature
    let sig = try_from_Signature(&evidence.attestation_report.signature)?;
    let data = &bincode::serialize(&evidence.attestation_report)?[..=0x29f];

    // verify genoa first
    let mut verify_result = verify(PROC_TYPE_GENOA, &evidence, &sig, data);
    if verify_result.is_err() {
        verify_result = verify(PROC_TYPE_MILAN, &evidence, &sig, data);
    }
    let vcek = verify_result?;

    // OpenSSL bindings do not expose custom extensions
    // Parse the vcek using x509_parser
    let vcek_der = &vcek.to_der()?;
    let parsed_vcek = X509Certificate::from_der(vcek_der)?.1.tbs_certificate;

    // verify vcek fields
    // chip id
    if get_oid_octets::<64>(&parsed_vcek, HW_ID_OID)? != evidence.attestation_report.chip_id {
        return Err(anyhow!("Chip ID mismatch"));
    }

    // tcb version
    // these integer extensions are 3 bytes with the last byte as the data
    if get_oid_int(&parsed_vcek, UCODE_SPL_OID)?
        != evidence.attestation_report.reported_tcb.microcode
    {
        return Err(anyhow!("Microcode verion mismatch"));
    }

    if get_oid_int(&parsed_vcek, SNP_SPL_OID)? != evidence.attestation_report.reported_tcb.snp {
        return Err(anyhow!("SNP verion mismatch"));
    }

    if get_oid_int(&parsed_vcek, TEE_SPL_OID)? != evidence.attestation_report.reported_tcb.tee {
        return Err(anyhow!("TEE verion mismatch"));
    }

    if get_oid_int(&parsed_vcek, LOADER_SPL_OID)?
        != evidence.attestation_report.reported_tcb.bootloader
    {
        return Err(anyhow!("Boot loader verion mismatch"));
    }

    Ok(())
}

const SIG_PIECE_SIZE: usize = std::mem::size_of::<[u8; 72]>();
const R_S_SIZE: usize = SIG_PIECE_SIZE * 2usize;
#[derive(Deserialize, Serialize)]
pub struct SignatureWrapper {
    #[serde(with = "BigArray")]
    r: [u8; 72],
    #[serde(with = "BigArray")]
    s: [u8; 72],
    #[serde(with = "BigArray")]
    _reserved: [u8; 512 - R_S_SIZE],
}

fn try_from_Signature(value: &Signature) -> Result<ecdsa::EcdsaSig> {
    let serialized = serde_json::to_string(value)?;
    let sig: SignatureWrapper = serde_json::from_str(&serialized)?;
    let r = bn::BigNum::from_slice(&sig.r)?;
    let s = bn::BigNum::from_slice(&sig.s)?;
    Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
}

fn verify(processor_model: &str, evidence: &AttReport, sig: &ecdsa::EcdsaSig, data: &[u8]) -> Result<x509::X509> {
    let vcek_data = request_vcek_kds(processor_model, &evidence.attestation_report)?;
    let mut vcek = x509::X509::from_der(&vcek_data).context(format!("Failed to load type {} VCEK", processor_model))?;
    sig.verify(data, EcKey::try_from(vcek.public_key()?)?.as_ref())
        .context(format!("Signature validation failed {}", processor_model))?;
    vcek = verify_cert_chain(vcek, processor_model)?;
    Ok(vcek)
}

// Function to request vcek from KDS. Return vcek in der format.
fn request_vcek_kds(
    processor_model: &str,
    att_report: &AttestationReport,
) -> Result<Vec<u8>, anyhow::Error> {
    // KDS URL parameters
    const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
    const KDS_VCEK: &str = "/vcek/v1";

    // Use attestation report to get data for URL
    let hw_id: String = hex::encode(att_report.chip_id);

    let vcek_url: String = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
        {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        processor_model,
        att_report.reported_tcb.bootloader,
        att_report.reported_tcb.tee,
        att_report.reported_tcb.snp,
        att_report.reported_tcb.microcode
    );
    println!("confilesystem request_vcek_kds processor_model: {}", processor_model);
    if let Some(res) = check_local(vcek_url.clone().as_str())? {
        println!("confilesystem request_vcek_kds from cache");
        return Ok(res);
    }

    // VCEK in DER format
    let vcek_rsp: Response = get(vcek_url.clone()).context("Unable to send request for VCEK")?;

    match vcek_rsp.status() {
        StatusCode::OK => {
            let vcek_rsp_bytes: Vec<u8> =
                vcek_rsp.bytes().context("Unable to parse VCEK")?.to_vec();
            let path = get_filepath(vcek_url.clone().as_str());
            let _ = std::fs::write(path, &vcek_rsp_bytes);
            println!("confilesystem cache vcek for {:?}", vcek_url);
            Ok(vcek_rsp_bytes)
        }
        status => Err(anyhow::anyhow!("Unable to fetch VCEK from URL: {vcek_url:?} {status:?}")),
    }
}

fn get_filepath(uri: &str) -> String {
    let mut sha256 = Sha256::new();
    sha256.update(uri.as_bytes());
    format!("{}/{:x}", CERT_STORAGE_PATH, sha256.finalize())
}

fn check_local(uri: &str) -> Result<Option<Vec<u8>>> {
    let file_path = get_filepath(uri);
    match Path::new(&file_path).exists() {
        true => {
            let contents = std::fs::read(&file_path).unwrap();
            Ok(Some(contents))
        },
        false => Ok(None),
    }
}

fn load_milan_cert_chain() -> Result<(x509::X509, x509::X509)> {
    let certs = x509::X509::stack_from_pem(include_bytes!("milan_ask_ark.pem"))?;
    if certs.len() != 2 {
        bail!("Malformed Milan ASK/ARK");
    }

    // ask, ark
    Ok((certs[0].clone(), certs[1].clone()))
}

fn load_genoa_cert_chain() -> Result<(x509::X509, x509::X509)> {
    let certs = x509::X509::stack_from_pem(include_bytes!("genoa_ask_ark.pem"))?;
    if certs.len() != 2 {
        bail!("Malformed Genoa ASK/ARK");
    }

    // ask, ark
    Ok((certs[0].clone(), certs[1].clone()))
}

fn verify_cert_chain(vcek: x509::X509, proc_type: &str) -> Result<x509::X509> {
    let (mut ask, mut ark) = load_milan_cert_chain()?;
    if proc_type == PROC_TYPE_GENOA {
        (ask, ark) = load_genoa_cert_chain()?;
    }

    // let raw_vcek = cert_chain
    //     .iter()
    //     .find(|c| c.cert_type == CertType::VCEK)
    //     .ok_or_else(|| anyhow!("VCEK not found."))?;
    // let vcek = x509::X509::from_der(raw_vcek.data()).context("Failed to load VCEK")?;

    // ARK -> ARK
    ark.verify(&(ark.public_key().unwrap() as PKey<Public>))
        .context("Invalid ARK Signature")?;

    // ARK -> ASK
    ask.verify(&(ark.public_key()? as PKey<Public>))
        .context("Invalid ASK Signature")?;

    // ASK -> VCEK
    vcek.verify(&(ask.public_key()? as PKey<Public>))
        .context("Invalid VCEK Signature")?;

    Ok(vcek)
}

fn calculate_expected_report_data(nonce: &String, tee_pubkey: &TeePubKey) -> [u8; 64] {
    let mut hasher = Sha384::new();

    hasher.update(nonce.as_bytes());
    hasher.update(&tee_pubkey.k_mod);
    hasher.update(&tee_pubkey.k_exp);

    let partial_hash = hasher.finalize();

    let mut hash = [0u8; 64];
    hash[..48].copy_from_slice(&partial_hash);

    hash
}

fn parse_tee_evidence(report: &AttestationReport) -> TeeEvidenceParsedClaim {
    let claims_map = json!({
        // policy fields
        "policy_abi_major": format!("{}",report.policy.abi_major()),
        "policy_abi_minor": format!("{}", report.policy.abi_minor()),
        "policy_smt_allowed": format!("{}", report.policy.smt_allowed()),
        "policy_migrate_ma": format!("{}", report.policy.migrate_ma_allowed()),
        "policy_debug_allowed": format!("{}", report.policy.debug_allowed()),
        "policy_single_socket": format!("{}", report.policy.single_socket_required()),

        // versioning info
        "reported_tcb_bootloader": format!("{}", report.reported_tcb.bootloader),
        "reported_tcb_tee": format!("{}", report.reported_tcb.tee),
        "reported_tcb_snp": format!("{}", report.reported_tcb.snp),
        "reported_tcb_microcode": format!("{}", report.reported_tcb.microcode),

        // platform info
        "platform_tsme_enabled": format!("{}", report.plat_info.tsme_enabled()),
        "platform_smt_enabled": format!("{}", report.plat_info.smt_enabled()),

        // measurement
        "measurement": format!("{}", base64::engine::general_purpose::STANDARD.encode(report.measurement)),
    });

    claims_map as TeeEvidenceParsedClaim
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::nid::Nid;
    use sev::firmware::host::CertTableEntry;

    #[test]
    fn check_milan_certificates() {
        let (ask, ark) = load_milan_cert_chain().unwrap();
        assert_eq!(get_common_name(&ark).unwrap(), "ARK-Milan");
        assert_eq!(get_common_name(&ask).unwrap(), "SEV-Milan");

        assert!(ark
            .verify(&(ark.public_key().unwrap() as PKey<Public>))
            .context("Invalid ARK Signature")
            .unwrap());

        assert!(ask
            .verify(&(ark.public_key().unwrap() as PKey<Public>))
            .context("Invalid ASK Signature")
            .unwrap());
    }

    fn get_common_name(cert: &x509::X509) -> Result<String> {
        let mut entries = cert.subject_name().entries_by_nid(Nid::COMMONNAME);

        if let Some(e) = entries.next() {
            assert_eq!(entries.count(), 0);
            return Ok(e.data().as_utf8()?.to_string());
        }
        Err(anyhow!("No CN found"))
    }

    #[test]
    fn check_vcek_parsing() {
        let vcek_der = include_bytes!("test-vcek.der");
        let parsed_vcek = X509Certificate::from_der(vcek_der)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&parsed_vcek, oid).unwrap();
        }
    }

    #[test]
    fn check_vcek_parsing_legacy() {
        let vcek_der = include_bytes!("test-vcek-invalid-legacy.der");
        let parsed_vcek = X509Certificate::from_der(vcek_der)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&parsed_vcek, oid).unwrap();
        }
    }

    #[test]
    fn check_vcek_parsing_new() {
        let vcek_der = include_bytes!("test-vcek-invalid-new.der");
        let parsed_vcek = X509Certificate::from_der(vcek_der)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&parsed_vcek, oid).unwrap();
        }
    }

    #[test]
    fn check_vcek_signature_verification() {
        let vcek = include_bytes!("test-vcek.der").to_vec();
        let cert_table = vec![CertTableEntry::new(CertType::VCEK, vcek)];
        verify_cert_chain(&cert_table).unwrap();
    }

    #[test]
    fn check_vcek_signature_failure() {
        let mut vcek = include_bytes!("test-vcek.der").to_vec();

        // corrupt some byte
        vcek[7] += 1;

        let cert_table = vec![CertTableEntry::new(CertType::VCEK, vcek)];
        assert!(verify_cert_chain(&cert_table).is_err());
    }
}

use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertTableEntry;

pub const ATTESTER_SECURITY: &str = "security";
pub const ATTESTER_CONTROLLER: &str = "controller";
pub const ATTESTER_METADATA: &str = "metadata";
pub const ATTESTER_WORKLOAD: &str = "workload";

#[derive(Debug, Serialize, Deserialize)]
pub struct AttesterReport {
    pub attester: String,
    pub attestation_report: AttestationReport,
    pub cert_chain: Option<Vec<CertTableEntry>>,
}

// RAE
#[derive(Debug, Serialize, Deserialize)]
pub struct RAEvidence {
    pub crp_token: Option<String>,
    pub attestation_reports: Vec<AttesterReport>,
}

impl RAEvidence {
    pub fn default() -> RAEvidence {
        let attester_report = AttesterReport {
            attester: "".to_string(),
            attestation_report: AttestationReport::default(),
            cert_chain: None,
        };
        let mut attestation_reports: Vec<AttesterReport> = Vec::new();
        attestation_reports.push(attester_report);
        let evidence = RAEvidence {
            crp_token: None,
            attestation_reports: attestation_reports,
        };
        evidence
    }
}

#[cfg(test)]
mod tests {
    use crate::tls_auditor::*;
    use crate::ca_monitor::*;
    use crate::key_rotation::*;
    use crate::quantum_readiness::*;

    #[test]
    fn test_tls_auditor_compliant() {
        let auditor = TlsAuditor::new();
        auditor.audit(TlsAuditResult {
            host: "srv1.example.com".into(), port: 443,
            protocol_version: "TLSv1.3".into(),
            cipher_suite: "AES256-GCM-SHA384".into(),
            compliant: true, findings: vec![], audited_at: 100,
        });
        assert_eq!(auditor.total_audited(), 1);
        assert_eq!(auditor.non_compliant(), 0);
    }

    #[test]
    fn test_tls_auditor_non_compliant() {
        let auditor = TlsAuditor::new();
        auditor.audit(TlsAuditResult {
            host: "old.example.com".into(), port: 443,
            protocol_version: "TLSv1.0".into(),
            cipher_suite: "RC4-SHA".into(),
            compliant: false, findings: vec!["Weak cipher".into()], audited_at: 100,
        });
        assert_eq!(auditor.non_compliant(), 1);
        assert!(!auditor.alerts().is_empty());
    }

    #[test]
    fn test_ca_monitor() {
        let cam = CaMonitor::new();
        cam.add_ca(CaEntry {
            issuer: "GoodCA".into(), fingerprint: "fp1".into(),
            expires_at: chrono::Utc::now().timestamp() + 86400, trusted: true,
        });
        assert_eq!(cam.total_cas(), 1);
        assert_eq!(cam.untrusted(), 0);
    }

    #[test]
    fn test_ca_monitor_untrusted() {
        let cam = CaMonitor::new();
        cam.add_ca(CaEntry {
            issuer: "BadCA".into(), fingerprint: "fp2".into(),
            expires_at: 0, trusted: false,
        });
        assert_eq!(cam.untrusted(), 1);
    }

    #[test]
    fn test_key_rotation() {
        let kr = KeyRotation::new();
        kr.register_key(KeyRecord {
            key_id: "k1".into(), algorithm: "AES-256".into(),
            created_at: 0, max_age_secs: 100, last_rotated: 0, overdue: true,
        });
        assert_eq!(kr.total_keys(), 1);
    }

    #[test]
    fn test_quantum_readiness() {
        let qr = QuantumReadiness::new();
        qr.register_asset(CryptoAsset {
            name: "RSA-2048-key".into(), algorithm: "RSA-2048".into(),
            key_bits: 2048, quantum_safe: false,
            migration_priority: crate::types::Severity::Critical,
        });
        assert_eq!(qr.total_assets(), 1);
        assert_eq!(qr.vulnerable(), 1);
    }
}

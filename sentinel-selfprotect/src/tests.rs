#[cfg(test)]
mod tests {
    use crate::binary_integrity::*;
    use crate::config_protection::*;
    use crate::anti_tampering::*;
    use crate::secure_updates::*;

    #[test]
    fn test_binary_integrity_ok() {
        let bi = BinaryIntegrity::new();
        bi.register_binary("/usr/bin/sentinel", "abc123");
        assert!(bi.verify("/usr/bin/sentinel", "abc123"));
        assert_eq!(bi.tampering_detected(), 0);
    }

    #[test]
    fn test_binary_integrity_tampered() {
        let bi = BinaryIntegrity::new();
        bi.register_binary("/usr/bin/sentinel", "abc123");
        assert!(!bi.verify("/usr/bin/sentinel", "xyz789"));
        assert_eq!(bi.tampering_detected(), 1);
        assert!(!bi.alerts().is_empty());
    }

    #[test]
    fn test_config_protection_match() {
        let cp = ConfigProtection::new();
        cp.set_baseline("main.conf", "hash1");
        assert!(cp.check("main.conf", "hash1"));
        assert_eq!(cp.violations(), 0);
    }

    #[test]
    fn test_config_protection_mismatch() {
        let cp = ConfigProtection::new();
        cp.set_baseline("main.conf", "hash1");
        assert!(!cp.check("main.conf", "hash2"));
        assert_eq!(cp.violations(), 1);
    }

    #[test]
    fn test_anti_tampering() {
        let at = AntiTampering::new();
        at.report_event("test", "test event", crate::types::Severity::Low);
        assert_eq!(at.total_events(), 1);
    }

    #[test]
    fn test_secure_updates_valid() {
        let su = SecureUpdates::new();
        let result = su.apply_update(UpdatePackage {
            package_id: "pkg1".into(), version: "2.0".into(),
            hash: "abc".into(), verified_hash: "abc".into(),
            size_bytes: 1024, created_at: 100,
        });
        assert!(result);
    }

    #[test]
    fn test_secure_updates_invalid() {
        let su = SecureUpdates::new();
        let result = su.apply_update(UpdatePackage {
            package_id: "pkg2".into(), version: "2.0".into(),
            hash: "abc".into(), verified_hash: "xyz".into(),
            size_bytes: 1024, created_at: 100,
        });
        assert!(!result);
        assert_eq!(su.rejected(), 1);
    }
}

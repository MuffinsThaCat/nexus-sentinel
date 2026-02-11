#[cfg(test)]
mod tests {
    use crate::app_permission_auditor::*;
    use crate::sim_swap_detector::*;
    use crate::mdm_lite::*;
    use crate::rogue_app_store::*;

    #[test]
    fn test_app_permissions_clean() {
        let apa = AppPermissionAuditor::new();
        apa.audit_app(AppPermissions {
            app_id: "com.good.app".into(), app_name: "GoodApp".into(),
            permissions: vec!["CAMERA".into()],
            risky_permissions: vec![],
            audited_at: 100,
        });
        assert_eq!(apa.total_audited(), 1);
        assert_eq!(apa.risky_apps(), 0);
    }

    #[test]
    fn test_app_permissions_risky() {
        let apa = AppPermissionAuditor::new();
        apa.audit_app(AppPermissions {
            app_id: "com.sketchy".into(), app_name: "Sketchy".into(),
            permissions: vec!["CAMERA".into(), "SMS".into()],
            risky_permissions: vec!["SMS".into()],
            audited_at: 100,
        });
        assert_eq!(apa.risky_apps(), 1);
    }

    #[test]
    fn test_sim_swap() {
        let ssd = SimSwapDetector::new();
        ssd.register_phone(PhoneRecord {
            user_id: "u1".into(), phone_number: "+1234".into(),
            carrier: "AT&T".into(), last_verified: 100, swap_detected: false,
        });
        let swapped = ssd.check_swap("u1", "T-Mobile");
        assert!(swapped);
        assert_eq!(ssd.swaps_detected(), 1);
    }

    #[test]
    fn test_mdm() {
        let mdm = MdmLite::new();
        mdm.register_device(ManagedDevice {
            device_id: "phone1".into(), os: "iOS".into(),
            os_version: "17.0".into(), encrypted: true,
            pin_enabled: true, compliant: true, last_check: 100,
        });
        assert_eq!(mdm.total_devices(), 1);
        assert_eq!(mdm.non_compliant(), 0);
    }

    #[test]
    fn test_rogue_store() {
        let rs = RogueAppStore::new();
        rs.add_rogue_domain("sketchy-apps.com");
        let detected = rs.check_traffic("phone1", "sketchy-apps.com");
        assert!(detected);
        assert_eq!(rs.rogue_found(), 1);
    }
}

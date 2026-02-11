#[cfg(test)]
mod tests {
    use crate::auto_quarantine::*;
    use crate::rollback_engine::*;
    use crate::dr_tester::*;
    use crate::kill_switch::*;

    #[test]
    fn test_quarantine() {
        let aq = AutoQuarantine::new();
        aq.quarantine("d1", "malware detected");
        assert!(aq.is_quarantined("d1"));
        assert_eq!(aq.active_count(), 1);
    }

    #[test]
    fn test_quarantine_release() {
        let aq = AutoQuarantine::new();
        aq.quarantine("d1", "suspicious");
        aq.release("d1");
        assert!(!aq.is_quarantined("d1"));
    }

    #[test]
    fn test_rollback() {
        let re = RollbackEngine::new();
        re.save_snapshot(Snapshot {
            snapshot_id: "snap1".into(), component: "firewall".into(),
            hash: "hash1".into(), created_at: 100, size_bytes: 1024,
        });
        assert!(re.has_snapshot("firewall"));
    }

    #[test]
    fn test_dr_tester() {
        let dr = DrTester::new();
        dr.record_test(DrTestRecord {
            test_name: "failover".into(), result: TestResult::Pass,
            duration_ms: 500, details: "ok".into(), tested_at: 100,
        });
        assert_eq!(dr.total_tests(), 1);
        assert_eq!(dr.failures(), 0);
    }

    #[test]
    fn test_dr_tester_fail() {
        let dr = DrTester::new();
        dr.record_test(DrTestRecord {
            test_name: "backup_restore".into(), result: TestResult::Fail,
            duration_ms: 1000, details: "timeout".into(), tested_at: 100,
        });
        assert_eq!(dr.failures(), 1);
    }

    #[test]
    fn test_kill_switch() {
        let ks = KillSwitch::new();
        ks.kill_component("firewall");
        assert!(ks.is_killed("firewall"));
        assert!(!ks.is_killed("other"));
    }

    #[test]
    fn test_kill_switch_all() {
        let ks = KillSwitch::new();
        ks.kill_all();
        assert!(ks.is_killed("anything"));
    }
}

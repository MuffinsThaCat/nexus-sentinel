#[cfg(test)]
mod tests {
    use crate::lookalike_domain::*;
    use crate::link_scanner::*;
    use crate::qr_scanner::*;
    use crate::vishing_detector::*;

    #[test]
    fn test_lookalike_domain() {
        let monitor = LookalikeDomainMonitor::new();
        monitor.add_domain("example.com");
        monitor.check_domain("examp1e.com");
        assert!(monitor.total_checked() > 0);
    }

    #[test]
    fn test_link_scanner_blocklist() {
        let scanner = LinkScanner::new();
        scanner.add_to_blocklist("http://evil.com", "phishing");
        let result = scanner.scan_url("http://evil.com");
        assert!(!result.verdict.is_safe());
        assert_eq!(scanner.malicious_found(), 1);
    }

    #[test]
    fn test_link_scanner_clean() {
        let scanner = LinkScanner::new();
        let _result = scanner.scan_url("https://google.com");
        assert_eq!(scanner.total_scanned(), 1);
    }

    #[test]
    fn test_qr_scanner() {
        let qs = QrScanner::new();
        let result = qs.scan_code("qr1", "https://safe.com");
        assert!(result.safe);
        assert_eq!(qs.total_scanned(), 1);
    }

    #[test]
    fn test_vishing() {
        let vd = VishingDetector::new();
        vd.record_call("+1234567890", true);
        assert_eq!(vd.total_calls(), 1);
    }
}

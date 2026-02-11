#[cfg(test)]
mod tests {
    use crate::dashboard::*;
    use crate::device_inventory::*;
    use crate::alert_feed::*;
    use crate::config_manager::*;
    use crate::update_manager::*;
    use crate::health_monitor::*;
    use crate::api_gateway::*;

    #[test]
    fn test_dashboard_widget() {
        let dash = Dashboard::new();
        dash.register_widget(DashboardWidget {
            widget_id: "w1".into(), title: "CPU".into(),
            data_source: "metrics".into(), refresh_secs: 5, last_updated: 0,
        });
        dash.record_view();
        assert_eq!(dash.total_views(), 1);
    }

    #[test]
    fn test_dashboard_unhealthy() {
        let dash = Dashboard::new();
        dash.update_status(SystemStatus {
            component: "fw".into(), healthy: false, alert_count: 3, last_check: 100,
        });
        assert!(!dash.alerts().is_empty());
    }

    #[test]
    fn test_device_inventory() {
        let inv = DeviceInventory::new();
        inv.register_device("d1", "srv1", "10.0.0.1");
        inv.update_last_seen("d1");
        assert_eq!(inv.total_devices(), 1);
    }

    #[test]
    fn test_alert_feed() {
        let feed = AlertFeed::new();
        feed.push_entry("test", "alert1", crate::types::Severity::Low);
        assert_eq!(feed.total_entries(), 1);
    }

    #[test]
    fn test_config_manager() {
        let mgr = ConfigManager::new();
        mgr.set("key1", "val1");
        assert_eq!(mgr.get("key1"), Some("val1".to_string()));
        mgr.set("key1", "val2");
        assert_eq!(mgr.get("key1"), Some("val2".to_string()));
    }

    #[test]
    fn test_update_manager() {
        let mgr = UpdateManager::new();
        mgr.check_update("sentinel-network", "1.0", "1.1");
        assert_eq!(mgr.total_checked(), 1);
    }

    #[test]
    fn test_health_monitor() {
        let hm = HealthMonitor::new();
        hm.record_check(HealthCheck {
            component: "fw".into(), memory_bytes: 20_000_000,
            memory_limit: 10_000_000, healthy: false, checked_at: 100,
        });
        assert_eq!(hm.violations(), 1);
    }

    #[test]
    fn test_api_gateway() {
        let gw = ApiGateway::new();
        gw.register_endpoint(ApiEndpoint {
            path: "/api/alerts".into(), method: "GET".into(),
            description: "Get alerts".into(), rate_limit: 100,
        });
        gw.record_request(ApiRequest {
            path: "/api/alerts".into(), method: "GET".into(),
            client_ip: "10.0.0.1".into(), timestamp: 100,
            response_ms: 15, status_code: 200,
        });
        assert_eq!(gw.total_requests(), 1);
    }
}

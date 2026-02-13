mod sentinel;
mod auth;
mod oauth;
mod config;
mod updater;

use std::sync::Arc;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let backend = Arc::new(sentinel::SentinelBackend::new());
    backend.start_checkpoint_timer();
    let user_store = Arc::new(auth::UserStore::new());
    let plan_engine = Arc::new(sentinel_ai::plan_review_engine::PlanReviewEngine::new());
    let ria = Arc::new(sentinel_ai::response_integrity_analyzer::ResponseIntegrityAnalyzer::new());
    let remediation_engine = Arc::new(sentinel_endpoint::remediation::RemediationEngine::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().level(log::LevelFilter::Info).build())
        .plugin(tauri_plugin_shell::init())
        .manage(backend)
        .manage(user_store)
        .manage(plan_engine)
        .manage(ria)
        .manage(remediation_engine)
        .invoke_handler(tauri::generate_handler![
            sentinel::get_status,
            sentinel::get_alerts,
            sentinel::get_metrics,
            sentinel::get_config,
            sentinel::get_tier_info,
            sentinel::set_tier,
            auth::get_auth_state,
            auth::signup,
            auth::login,
            auth::logout,
            auth::activate_license,
            auth::get_payment_url,
            auth::update_profile,
            auth::refresh_tier,
            auth::get_portal_url,
            oauth::oauth_login,
            updater::check_for_update,
            sentinel::scan_local_ai,
            sentinel::review_plan,
            sentinel::approve_plan,
            sentinel::get_plan_review_stats,
            sentinel::get_plan_review_alerts,
            sentinel::get_plan_review_history,
            sentinel::get_plan_risk_matrix,
            sentinel::get_plan_approval_patterns,
            sentinel::set_plan_review_enabled,
            sentinel::analyze_response,
            sentinel::get_ria_stats,
            sentinel::get_ria_alerts,
            sentinel::get_ria_history,
            sentinel::get_ria_finding_matrix,
            sentinel::set_ria_enabled,
            sentinel::get_remediation,
            sentinel::get_remediation_stats,
        ])
        .setup(|app| {
            // System tray with menu
            use tauri::menu::{MenuBuilder, MenuItemBuilder};
            use tauri::tray::TrayIconBuilder;

            let show = MenuItemBuilder::with_id("show", "Show Beaver Warrior").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&show, &quit]).build()?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("Beaver Warrior — Active")
                .on_menu_event(|app, event| {
                    match event.id().as_ref() {
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        "quit" => app.exit(0),
                        _ => {}
                    }
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

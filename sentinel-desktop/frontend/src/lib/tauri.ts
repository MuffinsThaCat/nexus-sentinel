import { invoke } from '@tauri-apps/api/core';

export type Tier = 'Free' | 'Pro' | 'Enterprise';

export interface DomainStatus {
  domain: string;
  display_name: string;
  enabled: boolean;
  module_count: number;
  tier: Tier;
}

export interface TierDetail {
  tier: Tier;
  name: string;
  price: string;
  domains: number;
  modules: number;
  features: string[];
}

export interface TierInfo {
  current: Tier;
  tiers: TierDetail[];
}

export interface UnifiedAlert {
  timestamp: number;
  severity: string;
  domain: string;
  component: string;
  title: string;
  details: string;
}

export interface StatusResponse {
  domains: DomainStatus[];
  enabled_domains: number;
  total_modules: number;
  uptime_secs: number;
  current_tier: Tier;
}

export interface AlertResponse {
  alerts: UnifiedAlert[];
  total: number;
  critical: number;
  high: number;
}

export interface MetricsResponse {
  total_budget: number;
  total_used: number;
  utilization_percent: number;
  process_rss: number;
  process_vms: number;
}

export async function getStatus(): Promise<StatusResponse> {
  try {
    return await invoke<StatusResponse>('get_status');
  } catch {
    return { domains: [], enabled_domains: 0, total_modules: 0, uptime_secs: 0, current_tier: 'Enterprise' as Tier };
  }
}

export async function getAlerts(): Promise<AlertResponse> {
  try {
    return await invoke<AlertResponse>('get_alerts');
  } catch {
    return { alerts: [], total: 0, critical: 0, high: 0 };
  }
}

export async function getMetrics(): Promise<MetricsResponse> {
  try {
    return await invoke<MetricsResponse>('get_metrics');
  } catch {
    return { total_budget: 0, total_used: 0, utilization_percent: 0, process_rss: 0, process_vms: 0 };
  }
}

export async function getTierInfo(): Promise<TierInfo> {
  try {
    return await invoke<TierInfo>('get_tier_info');
  } catch {
    return { current: 'Enterprise', tiers: [] };
  }
}

export async function setTier(tier: Tier): Promise<TierInfo> {
  try {
    return await invoke<TierInfo>('set_tier', { tier });
  } catch {
    return { current: tier, tiers: [] };
  }
}

export const tierColors: Record<Tier, string> = {
  Free: '#10b981',
  Pro: '#6366f1',
  Enterprise: '#f59e0b',
};

export const tierGradients: Record<Tier, string> = {
  Free: 'from-emerald-500/20 to-emerald-600/5',
  Pro: 'from-indigo-500/20 to-indigo-600/5',
  Enterprise: 'from-amber-500/20 to-amber-600/5',
};

// Domain icon mapping
export const domainIcons: Record<string, string> = {
  network: '🌐', endpoint: '🖥️', dns: '🔗', email: '✉️',
  identity: '🔑', siem: '📊', iot: '📡', data: '🛡️',
  threat_intel: '🧠', forensics: '🔬', vuln: '⚠️', web: '🌍',
  container: '📦', supply_chain: '🔗', compliance: '📋', privacy: '👁️',
  ai: '🤖', deception: '🪤', browser: '🌐', api: '⚡',
  vpn: '🔒', hardware: '🔧', exfiltration: '📤', mgmt: '⚙️',
  selfprotect: '🛡️', phishing: '🎣', crypto: '🔐', resilience: '💪',
  mobile: '📱', darkweb: '🕶️', ot: '🏭', microseg: '🧩',
  backup: '💾', cloud: '☁️', time: '⏱️', soceng: '🎭',
  regulatory: '⚖️', ops: '📈',
};

export function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  return `${m}m ${s}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

export function timeAgo(ts: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - ts;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

// ── Auth Types ───────────────────────────────────────────────────────────────

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  company: string | null;
  tier: Tier;
  created_at: string;
  endpoints: number;
  team_size: number;
  license_valid: boolean;
  license_expiry: string | null;
}

export interface LicenseResult {
  success: boolean;
  message: string;
  tier: Tier;
  expiry: string | null;
  state: AuthState;
}

export interface PaymentInfo {
  url: string;
  tier: string;
  price: string;
}

export interface AuthState {
  logged_in: boolean;
  user: UserProfile | null;
  session_token: string | null;
}

export interface AuthResult {
  success: boolean;
  message: string;
  state: AuthState;
}

export async function getAuthState(): Promise<AuthState> {
  try {
    return await invoke<AuthState>('get_auth_state');
  } catch {
    return { logged_in: false, user: null, session_token: null };
  }
}

export async function authSignup(email: string, password: string, name: string, company?: string): Promise<AuthResult> {
  try {
    return await invoke<AuthResult>('signup', { email, password, name, company: company || null });
  } catch (e) {
    return { success: false, message: String(e), state: { logged_in: false, user: null, session_token: null } };
  }
}

export async function authLogin(email: string, password: string): Promise<AuthResult> {
  try {
    return await invoke<AuthResult>('login', { email, password });
  } catch (e) {
    return { success: false, message: String(e), state: { logged_in: false, user: null, session_token: null } };
  }
}

export async function authLogout(): Promise<AuthState> {
  try {
    return await invoke<AuthState>('logout');
  } catch {
    return { logged_in: false, user: null, session_token: null };
  }
}

export async function activateLicense(licenseKey: string): Promise<LicenseResult> {
  try {
    return await invoke<LicenseResult>('activate_license', { licenseKey });
  } catch (e) {
    return { success: false, message: String(e), tier: 'Free', expiry: null, state: { logged_in: false, user: null, session_token: null } };
  }
}

export async function getPaymentUrl(tier: Tier): Promise<PaymentInfo | null> {
  try {
    return await invoke<PaymentInfo | null>('get_payment_url', { tier });
  } catch {
    return null;
  }
}

export async function updateProfile(name?: string, company?: string): Promise<AuthResult> {
  try {
    return await invoke<AuthResult>('update_profile', { name: name || null, company: company || null });
  } catch (e) {
    return { success: false, message: String(e), state: { logged_in: false, user: null, session_token: null } };
  }
}

export async function getPortalUrl(): Promise<string | null> {
  try {
    return await invoke<string | null>('get_portal_url');
  } catch {
    return null;
  }
}

export async function refreshTier(): Promise<string> {
  try {
    return await invoke<string>('refresh_tier');
  } catch {
    return 'Free';
  }
}

// ── Update Checker ──────────────────────────────────────────────────────────

export interface UpdateCheck {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  download_url: string;
  release_notes: string;
}

export async function checkForUpdate(): Promise<UpdateCheck> {
  try {
    return await invoke<UpdateCheck>('check_for_update');
  } catch {
    return { current_version: '0.0.0', latest_version: '0.0.0', update_available: false, download_url: '', release_notes: '' };
  }
}

export type OAuthProvider = 'Google' | 'GitHub';

export async function oauthLogin(provider: OAuthProvider): Promise<AuthResult> {
  try {
    return await invoke<AuthResult>('oauth_login', { provider });
  } catch (e) {
    return { success: false, message: String(e), state: { logged_in: false, user: null, session_token: null } };
  }
}

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

// ── Local AI Discovery ──────────────────────────────────────────────────────

export interface DiscoveredAiTool {
  name: string;
  category: string;
  detection_method: string;
  pid: number | null;
  port: number | null;
  exe_path: string;
  memory_bytes: number;
  cpu_percent: number;
  risk_level: string;
  details: string;
  privacy_info: string;
  process_count: number;
  discovered_at: number;
}

export interface AiDiscoverySummary {
  total_tools: number;
  local_llms: number;
  coding_assistants: number;
  desktop_apps: number;
  dev_frameworks: number;
  image_audio: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
  total_ai_memory_bytes: number;
}

export interface AiScanResult {
  tools: DiscoveredAiTool[];
  summary: AiDiscoverySummary;
}

export async function scanLocalAi(): Promise<AiScanResult> {
  try {
    return await invoke<AiScanResult>('scan_local_ai');
  } catch {
    return { tools: [], summary: { total_tools: 0, local_llms: 0, coding_assistants: 0, desktop_apps: 0, dev_frameworks: 0, image_audio: 0, high_risk: 0, medium_risk: 0, low_risk: 0, total_ai_memory_bytes: 0 } };
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

// ── Plan Review Engine ──────────────────────────────────────────────────────

export type PlanAction =
  | 'FileRead' | 'FileWrite' | 'FileDelete'
  | 'ProcessSpawn' | 'ProcessKill'
  | 'NetworkRequest' | 'NetworkListen'
  | 'EnvRead' | 'EnvWrite'
  | 'CredentialAccess' | 'CredentialStore'
  | 'DatabaseQuery' | 'DatabaseMutate'
  | 'CodeExecution' | 'ShellCommand'
  | 'RegistryRead' | 'RegistryWrite'
  | 'MemoryInject' | 'KernelCall'
  | 'UserImpersonation' | 'PrivilegeEscalation'
  | 'Custom';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';
export type ApprovalStatus = 'AutoApproved' | 'PendingHumanApproval' | 'Denied';

export interface PlanStep {
  step_number: number;
  action: PlanAction;
  target: string;
  description: string;
  requires_credential: string | null;
  network_endpoint: string | null;
  network_port: number | null;
  estimated_duration_ms: number;
}

export interface AgentPlan {
  plan_id: string;
  agent_name: string;
  stated_goal: string;
  steps: PlanStep[];
  submitted_at: number;
}

export interface StepReview {
  step_number: number;
  risk_level: RiskLevel;
  risk_reasons: string[];
  recommendation: string;
  alternatives: string[];
  approval: ApprovalStatus;
  blast_radius: number | null;
  goal_aligned: boolean;
}

export interface PlanReview {
  plan_id: string;
  agent_name: string;
  overall_risk: RiskLevel;
  step_reviews: StepReview[];
  chain_warnings: string[];
  trajectory_summary: string;
  auto_approved_count: number;
  needs_approval_count: number;
  denied_count: number;
  reviewed_at: number;
}

export interface PlanReviewResult {
  review: PlanReview;
  is_duplicate: boolean;
  cached_verdict: RiskLevel | null;
}

export interface PlanReviewStats {
  total_reviews: number;
  total_critical: number;
  total_denied: number;
  enabled: boolean;
  risk_checkpoints: number;
  statistics: Record<string, unknown>;
}

export interface PlanAlert {
  timestamp: number;
  severity: string;
  component: string;
  title: string;
  details: string;
}

export interface RiskMatrixEntry {
  agent: string;
  action: string;
  count: number;
}

export interface ApprovalPattern {
  agent: string;
  pattern: string;
  approved_count: number;
}

export async function reviewPlan(plan: AgentPlan): Promise<PlanReviewResult> {
  try {
    return await invoke<PlanReviewResult>('review_plan', { plan });
  } catch {
    return { review: {} as PlanReview, is_duplicate: false, cached_verdict: null };
  }
}

export async function approvePlan(agent: string, action: PlanAction, target: string, approved: boolean): Promise<Record<string, unknown>> {
  try {
    return await invoke<Record<string, unknown>>('approve_plan', { agent, action, target, approved });
  } catch {
    return { recorded: false };
  }
}

export async function getPlanReviewStats(): Promise<PlanReviewStats> {
  try {
    return await invoke<PlanReviewStats>('get_plan_review_stats');
  } catch {
    return { total_reviews: 0, total_critical: 0, total_denied: 0, enabled: false, risk_checkpoints: 0, statistics: {} };
  }
}

export async function getPlanReviewAlerts(): Promise<PlanAlert[]> {
  try {
    return await invoke<PlanAlert[]>('get_plan_review_alerts');
  } catch {
    return [];
  }
}

export async function getPlanReviewHistory(limit?: number): Promise<PlanReview[]> {
  try {
    return await invoke<PlanReview[]>('get_plan_review_history', { limit: limit ?? 25 });
  } catch {
    return [];
  }
}

export async function getPlanRiskMatrix(): Promise<RiskMatrixEntry[]> {
  try {
    return await invoke<RiskMatrixEntry[]>('get_plan_risk_matrix');
  } catch {
    return [];
  }
}

export async function getPlanApprovalPatterns(): Promise<ApprovalPattern[]> {
  try {
    return await invoke<ApprovalPattern[]>('get_plan_approval_patterns');
  } catch {
    return [];
  }
}

export async function setPlanReviewEnabled(enabled: boolean): Promise<boolean> {
  try {
    return await invoke<boolean>('set_plan_review_enabled', { enabled });
  } catch {
    return false;
  }
}

// ── Response Integrity Analyzer ──────────────────────────────────────────

export interface LlmResponse {
  response_id: string;
  model_name: string;
  content: string;
  turn_number: number;
  timestamp: number;
  conversation_id: string;
  role: string;
}

export type IntegrityLevel = 'Clean' | 'Suspicious' | 'Compromised' | 'Hostile';

export interface IntegrityFinding {
  category: string;
  severity: string;
  title: string;
  details: string;
  evidence: string;
  byte_offset: number | null;
  mitre_ids: string[];
  recommended_action: string;
}

export interface EntropyProfile {
  char_entropy: number;
  word_entropy: number;
  line_length_variance: number;
  whitespace_ratio: number;
  punctuation_ratio: number;
  uppercase_ratio: number;
  digit_ratio: number;
  non_ascii_ratio: number;
  zero_width_count: number;
  unicode_homoglyph_count: number;
  invisible_char_count: number;
  entropy_anomaly_score: number;
}

export interface ResponseAnalysis {
  response_id: string;
  model_name: string;
  overall_integrity: IntegrityLevel;
  findings: IntegrityFinding[];
  entropy_profile: EntropyProfile;
  total_findings: number;
  critical_findings: number;
  data_leak_count: number;
  stego_score: number;
  poisoned_artifact_count: number;
  summary: string;
  analyzed_at: number;
}

export interface RiaStats {
  total_analyzed: number;
  total_hostile: number;
  total_compromised: number;
  total_findings: number;
  total_clean: number;
  total_suspicious: number;
  stego_detections: number;
  data_leak_detections: number;
  poisoned_artifact_detections: number;
  malicious_code_detections: number;
  hidden_instruction_detections: number;
  unique_models: number;
  enabled: boolean;
}

export interface RiaFindingMatrixEntry {
  model: string;
  category: string;
  count: number;
}

export async function analyzeResponse(response: LlmResponse): Promise<ResponseAnalysis> {
  return await invoke<ResponseAnalysis>('analyze_response', { response });
}

export async function getRiaStats(): Promise<RiaStats> {
  try {
    return await invoke<RiaStats>('get_ria_stats');
  } catch {
    return {
      total_analyzed: 0, total_hostile: 0, total_compromised: 0,
      total_findings: 0, total_clean: 0, total_suspicious: 0,
      stego_detections: 0, data_leak_detections: 0,
      poisoned_artifact_detections: 0, malicious_code_detections: 0,
      hidden_instruction_detections: 0, unique_models: 0, enabled: false,
    };
  }
}

export async function getRiaAlerts(): Promise<UnifiedAlert[]> {
  try {
    return await invoke<UnifiedAlert[]>('get_ria_alerts');
  } catch {
    return [];
  }
}

export async function getRiaHistory(limit?: number): Promise<ResponseAnalysis[]> {
  try {
    return await invoke<ResponseAnalysis[]>('get_ria_history', { limit: limit ?? 25 });
  } catch {
    return [];
  }
}

export async function getRiaFindingMatrix(): Promise<RiaFindingMatrixEntry[]> {
  try {
    return await invoke<RiaFindingMatrixEntry[]>('get_ria_finding_matrix');
  } catch {
    return [];
  }
}

export async function setRiaEnabled(enabled: boolean): Promise<boolean> {
  try {
    return await invoke<boolean>('set_ria_enabled', { enabled });
  } catch {
    return false;
  }
}

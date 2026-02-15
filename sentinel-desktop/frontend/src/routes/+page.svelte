<script lang="ts">
	import { onMount } from 'svelte';
	import { getStatus, getAlerts, getMetrics, getTierInfo, setTier, getAuthState, authLogout, activateLicense, getPaymentUrl, updateProfile, checkForUpdate, refreshTier, getPortalUrl, domainIcons, formatUptime, formatBytes, timeAgo, tierColors, tierGradients, scanLocalAi, getRemediation, oneClickRemediate } from '$lib/tauri';
	import { open } from '@tauri-apps/plugin-shell';
	import type { StatusResponse, AlertResponse, MetricsResponse, DomainStatus, UnifiedAlert, TierInfo, Tier, AuthState, UserProfile, LicenseResult, UpdateCheck, AiScanResult, DiscoveredAiTool, RemediationResult, OneClickResult } from '$lib/tauri';

	let status: StatusResponse = $state({ domains: [], enabled_domains: 0, total_modules: 0, uptime_secs: 0, current_tier: 'Enterprise' });
	let alerts: AlertResponse = $state({ alerts: [], total: 0, critical: 0, high: 0 });
	let metrics: MetricsResponse = $state({ total_budget: 0, total_used: 0, utilization_percent: 0, process_rss: 0, process_vms: 0 });
	let tierInfo: TierInfo = $state({ current: 'Enterprise', tiers: [] });
	let auth: AuthState = $state({ logged_in: false, user: null, session_token: null });
	let now = $state(Date.now());
	let activeTab: 'overview' | 'alerts' | 'domains' | 'pricing' | 'account' = $state('overview');
	let loaded = $state(false);
	let editName = $state('');
	let editCompany = $state('');
	let profileMsg = $state('');
	let licenseKey = $state('');
	let licenseMsg = $state('');
	let licenseMsgOk = $state(false);
	let updateInfo: UpdateCheck = $state({ current_version: '0.0.0', latest_version: '0.0.0', update_available: false, download_url: '', release_notes: '' });
	let updateDismissed = $state(false);
	let aiScan: AiScanResult = $state({ tools: [], summary: { total_tools: 0, local_llms: 0, coding_assistants: 0, desktop_apps: 0, dev_frameworks: 0, image_audio: 0, high_risk: 0, medium_risk: 0, low_risk: 0, total_ai_memory_bytes: 0 } });
	let aiScanning = $state(false);
	let expandedAlert: number | null = $state(null);
	let remediationCache: Map<string, RemediationResult> = $state(new Map());
	let remediationLoading: string | null = $state(null);
	let copiedKey: string | null = $state(null);
	let fixItLoading: string | null = $state(null);
	let fixItResults: Map<string, OneClickResult> = $state(new Map());

	async function handleFixIt(alert: UnifiedAlert) {
		const key = alertKey(alert);
		if (fixItResults.has(key)) return;
		fixItLoading = key;
		const result = await oneClickRemediate(alert);
		fixItResults.set(key, result);
		fixItResults = new Map(fixItResults);
		fixItLoading = null;
	}

	function alertKey(alert: UnifiedAlert): string {
		return `${alert.component}::${alert.title}`;
	}

	function parseSteps(advice: string): { num: string; text: string }[] {
		const lines = advice.split('\n').filter(l => l.trim());
		const steps: { num: string; text: string }[] = [];
		for (const line of lines) {
			const m = line.match(/^\s*(\d+)\.\s+(.+)/);
			if (m) steps.push({ num: m[1], text: m[2] });
			else if (steps.length > 0) steps[steps.length - 1].text += ' ' + line.trim();
			else steps.push({ num: '', text: line.trim() });
		}
		return steps;
	}

	function copyAdvice(key: string, advice: string) {
		navigator.clipboard.writeText(advice);
		copiedKey = key;
		setTimeout(() => { copiedKey = null; }, 2000);
	}

	async function requestRemediation(alert: UnifiedAlert, index: number) {
		const key = alertKey(alert);
		if (expandedAlert === index && remediationCache.has(key)) {
			expandedAlert = null;
			return;
		}
		expandedAlert = index;
		if (remediationCache.has(key)) return;
		remediationLoading = key;
		const result = await getRemediation(alert.severity, alert.component, alert.title, alert.details);
		remediationCache.set(key, result);
		remediationCache = new Map(remediationCache);
		remediationLoading = null;
	}

	onMount(() => {
		async function refresh() {
			status = await getStatus();
			alerts = await getAlerts();
			metrics = await getMetrics();
			tierInfo = await getTierInfo();
			auth = await getAuthState();
			if (auth.user) {
				if (!editName) editName = auth.user.name;
				if (!editCompany) editCompany = auth.user.company || '';
			}
			loaded = true;
		}
		// Initial load + sync tier from Stripe once on startup
		(async () => {
			await refresh();
			if (auth.user) {
				await refreshTier();
				status = await getStatus();
				auth = await getAuthState();
			}
		})();
		checkForUpdate().then(u => updateInfo = u);
		// Auto-scan for local AI tools on startup
		(async () => { aiScanning = true; aiScan = await scanLocalAi(); aiScanning = false; })();
		const timer = setInterval(refresh, 5000);
		const updateTimer = setInterval(() => checkForUpdate().then(u => updateInfo = u), 600000);
		const clock = setInterval(() => now = Date.now(), 1000);
		return () => { clearInterval(timer); clearInterval(updateTimer); clearInterval(clock); };
	});

	function severityClass(sev: string) {
		if (sev === 'Critical') return 'badge-critical';
		if (sev === 'High') return 'badge-high';
		if (sev === 'Medium' || sev === 'Warning') return 'badge-medium';
		if (sev === 'Low' || sev === 'Info') return 'badge-info';
		return 'badge-low';
	}

	const tierOrder: Record<Tier, number> = { Free: 0, Pro: 1, Enterprise: 2 };

	function isDomainLocked(domain: DomainStatus): boolean {
		return tierOrder[domain.tier] > tierOrder[tierInfo.current];
	}

	function tierBadgeClass(tier: Tier): string {
		switch (tier) {
			case 'Free': return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20';
			case 'Pro': return 'bg-indigo-500/15 text-indigo-400 border-indigo-500/20';
			case 'Enterprise': return 'bg-amber-500/15 text-amber-400 border-amber-500/20';
		}
	}

	async function switchTier(tier: Tier) {
		tierInfo = await setTier(tier);
		status = await getStatus();
	}

	async function handleLogout() {
		await authLogout();
		window.location.reload();
	}

	async function saveProfile() {
		const r = await updateProfile(editName, editCompany);
		profileMsg = r.message;
		if (r.success) auth = r.state;
		setTimeout(() => profileMsg = '', 3000);
	}

	async function handleActivateLicense() {
		if (!licenseKey.trim()) { licenseMsg = 'Please enter a license key'; licenseMsgOk = false; return; }
		const r = await activateLicense(licenseKey);
		licenseMsg = r.message;
		licenseMsgOk = r.success;
		if (r.success) {
			auth = r.state;
			tierInfo = await getTierInfo();
			status = await getStatus();
		}
		setTimeout(() => licenseMsg = '', 5000);
	}

	let tierPollTimer: ReturnType<typeof setInterval> | null = $state(null);

	async function handlePayment(tier: Tier) {
		const info = await getPaymentUrl(tier);
		if (info) {
			await open(info.url);
			// Poll every 10s for up to 5 minutes to detect tier change after payment
			if (tierPollTimer) clearInterval(tierPollTimer);
			let polls = 0;
			tierPollTimer = setInterval(async () => {
				polls++;
				const newTier = await refreshTier();
				if (newTier !== 'Free' || polls >= 30) {
					if (tierPollTimer) clearInterval(tierPollTimer);
					tierPollTimer = null;
					// Refresh all data with new tier
					status = await getStatus();
					tierInfo = await getTierInfo();
					auth = await getAuthState();
				}
			}, 10000);
		}
	}

	async function handleManageSubscription() {
		const url = await getPortalUrl();
		if (url) {
			await open(url);
			// Poll for tier change after portal visit (they may cancel)
			if (tierPollTimer) clearInterval(tierPollTimer);
			let polls = 0;
			tierPollTimer = setInterval(async () => {
				polls++;
				await refreshTier();
				status = await getStatus();
				tierInfo = await getTierInfo();
				auth = await getAuthState();
				if (polls >= 30) {
					if (tierPollTimer) clearInterval(tierPollTimer);
					tierPollTimer = null;
				}
			}, 10000);
		}
	}

	function userInitials(user: UserProfile | null): string {
		if (!user) return '?';
		return user.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
	}

	function freeModules(): number {
		return status.domains.filter(d => d.tier === 'Free').reduce((s, d) => s + d.module_count, 0);
	}
	function proModules(): number {
		return status.domains.filter(d => d.tier === 'Free' || d.tier === 'Pro').reduce((s, d) => s + d.module_count, 0);
	}
</script>

<!-- ═══════════════════════ MAIN LAYOUT ═══════════════════════ -->
<div class="flex h-screen">

	<!-- ─── Sidebar ─── -->
	<aside class="w-[72px] flex flex-col items-center py-5 gap-2 border-r border-white/[0.04] bg-surface-900/60">
		<!-- Logo -->
		<div class="w-10 h-10 rounded-xl flex items-center justify-center mb-4 shadow-lg shadow-cyan-500/20 overflow-hidden">
			<svg viewBox="0 0 512 512" class="w-10 h-10" fill="none" xmlns="http://www.w3.org/2000/svg">
				<defs>
					<linearGradient id="fur" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#8B4513"/><stop offset="100%" stop-color="#A0522D"/></linearGradient>
					<linearGradient id="helmet" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#C0C0C0"/><stop offset="50%" stop-color="#A8A8A8"/><stop offset="100%" stop-color="#808080"/></linearGradient>
					<linearGradient id="shield" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#00e5ff"/><stop offset="100%" stop-color="#0088cc"/></linearGradient>
				</defs>
				<ellipse cx="256" cy="280" rx="140" ry="160" fill="url(#fur)"/>
				<ellipse cx="256" cy="260" rx="120" ry="80" fill="url(#fur)"/>
				<path d="M136 200 Q256 80 376 200 Q376 140 256 100 Q136 140 136 200Z" fill="url(#helmet)"/>
				<path d="M160 190 Q256 100 352 190" stroke="#666" stroke-width="4" fill="none"/>
				<rect x="248" y="100" width="16" height="50" rx="4" fill="#C0C0C0"/>
				<circle cx="256" cy="90" r="12" fill="#FFD700"/>
				<ellipse cx="210" cy="260" rx="25" ry="20" fill="white"/>
				<ellipse cx="302" cy="260" rx="25" ry="20" fill="white"/>
				<circle cx="215" cy="258" r="12" fill="#1a1a2e"/>
				<circle cx="297" cy="258" r="12" fill="#1a1a2e"/>
				<circle cx="219" cy="254" r="4" fill="white"/>
				<circle cx="301" cy="254" r="4" fill="white"/>
				<ellipse cx="256" cy="300" rx="18" ry="12" fill="#2d1810"/>
				<path d="M240 330 Q256 350 272 330" stroke="#2d1810" stroke-width="3" fill="none"/>
				<rect x="238" y="350" width="14" height="20" rx="3" fill="white"/>
				<rect x="260" y="350" width="14" height="20" rx="3" fill="white"/>
				<path d="M200 410 L180 460 Q256 490 332 460 L312 410" fill="url(#shield)" opacity="0.9"/>
				<path d="M256 420 L256 470" stroke="white" stroke-width="3"/>
				<path d="M230 445 L282 445" stroke="white" stroke-width="3"/>
			</svg>
		</div>

		<!-- Nav buttons -->
		<button
			class="nav-btn {activeTab === 'overview' ? 'nav-active' : ''}"
			onclick={() => activeTab = 'overview'}
			title="Overview"
		>
			<svg viewBox="0 0 24 24" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.8">
				<rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
				<rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
			</svg>
		</button>

		<button
			class="nav-btn {activeTab === 'alerts' ? 'nav-active' : ''}"
			onclick={() => activeTab = 'alerts'}
			title="Alerts"
		>
			<svg viewBox="0 0 24 24" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.8">
				<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
				<path d="M13.73 21a2 2 0 0 1-3.46 0" />
			</svg>
			{#if alerts.critical > 0}
				<span class="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-[9px] font-bold flex items-center justify-center text-white">{alerts.critical}</span>
			{/if}
		</button>

		<button
			class="nav-btn {activeTab === 'domains' ? 'nav-active' : ''}"
			onclick={() => activeTab = 'domains'}
			title="Domains"
		>
			<svg viewBox="0 0 24 24" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.8">
				<circle cx="12" cy="12" r="10" /><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
				<path d="M2 12h20" />
			</svg>
		</button>

		<button
			class="nav-btn {activeTab === 'pricing' ? 'nav-active' : ''}"
			onclick={() => activeTab = 'pricing'}
			title="Pricing"
		>
			<svg viewBox="0 0 24 24" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.8">
				<path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
			</svg>
		</button>

		<!-- Spacer -->
		<div class="flex-1"></div>

		<!-- Status indicator -->
		<div class="flex flex-col items-center gap-1 mb-3">
			<div class="status-dot active"></div>
			<span class="text-[9px] text-emerald-400/70 font-medium uppercase tracking-wider">Live</span>
		</div>

		<!-- User avatar -->
		<button
			class="w-9 h-9 rounded-full flex items-center justify-center text-[11px] font-bold transition-all
				{activeTab === 'account' ? 'bg-cyan-500/20 text-cyan-400 ring-1 ring-cyan-500/30' : 'bg-white/[0.06] text-white/40 hover:bg-white/[0.10] hover:text-white/60'}"
			onclick={() => activeTab = 'account'}
			title="Account"
		>
			{userInitials(auth.user)}
		</button>
	</aside>

	<!-- ─── Content ─── -->
	<main class="flex-1 overflow-hidden flex flex-col">
		<!-- Header bar -->
		<header class="h-14 flex items-center justify-between px-6 border-b border-white/[0.04] bg-surface-900/30 flex-shrink-0">
			<div class="flex items-center gap-3">
				<h1 class="text-[15px] font-semibold text-white/90 tracking-tight">Beaver Warrior</h1>
				<span class="text-[11px] text-white/30 font-mono">v{updateInfo.current_version}</span>
				<button onclick={() => activeTab = 'pricing'} class="px-2 py-0.5 rounded-full text-[10px] font-semibold border {tierBadgeClass(tierInfo.current)} hover:brightness-125 transition-all cursor-pointer">
					{tierInfo.current === 'Free' ? 'Community' : tierInfo.current}
				</button>
			</div>
			<div class="flex items-center gap-5 text-[12px] text-white/40 font-mono">
				<span>{status.enabled_domains} domains</span>
				<span class="text-white/10">|</span>
				<span>{status.total_modules} modules</span>
				<span class="text-white/10">|</span>
				<span>up {formatUptime(status.uptime_secs)}</span>
				<span class="text-white/10">|</span>
				<span class="tabular-nums">{new Date(now).toLocaleTimeString('en-US', { hour12: false })}</span>
			</div>
		</header>

		<!-- Update Banner -->
		{#if updateInfo.update_available && !updateDismissed}
			<div class="mx-6 mt-4 rounded-xl border border-cyan-500/25 bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-cyan-500/10 px-5 py-3 flex items-center justify-between">
				<div class="flex items-center gap-3">
					<div class="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center">
						<svg viewBox="0 0 24 24" class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
					</div>
					<div>
						<span class="text-[13px] font-semibold text-white/90">Update available — v{updateInfo.latest_version}</span>
						<span class="text-[11px] text-white/40 ml-2">{updateInfo.release_notes}</span>
					</div>
				</div>
				<div class="flex items-center gap-2 flex-shrink-0">
					<button
						onclick={() => open(updateInfo.download_url)}
						class="px-4 py-1.5 rounded-lg text-[12px] font-semibold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30 transition-all"
					>
						Download Update
					</button>
					<button
						onclick={() => updateDismissed = true}
						class="p-1.5 rounded-lg text-white/20 hover:text-white/50 hover:bg-white/[0.04] transition-all"
					>
						<svg viewBox="0 0 24 24" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
					</button>
				</div>
			</div>
		{/if}

		<!-- Scrollable content area -->
		<div class="flex-1 overflow-y-auto p-6">

			<!-- ═══ OVERVIEW TAB ═══ -->
			{#if activeTab === 'overview'}
				<div class="animate-in grid gap-5" style="animation-delay:0.05s">

					<!-- Upgrade Banner (shown when on Free tier) -->
					{#if tierInfo.current === 'Free'}
						<div class="relative overflow-hidden rounded-2xl border border-indigo-500/20 bg-gradient-to-r from-indigo-500/10 via-purple-500/10 to-indigo-500/10 p-5">
							<div class="flex items-center justify-between">
								<div class="flex items-center gap-4">
									<div class="w-10 h-10 rounded-xl bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-lg">🚀</div>
									<div>
										<h3 class="text-[14px] font-bold text-white/90">Unlock 11 more domains & 242 more modules</h3>
										<p class="text-[12px] text-white/40 mt-0.5">Upgrade to Pro for SIEM, Cloud, Identity, Malware, Supply Chain & more — $29/user/mo</p>
									</div>
								</div>
								<button
									onclick={() => handlePayment('Pro')}
									class="px-5 py-2 rounded-xl text-[13px] font-semibold bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/30 transition-all flex items-center gap-2 flex-shrink-0"
								>
									<svg viewBox="0 0 24 24" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 17L17 7M17 7H7M17 7V17"/></svg>
									Upgrade to Pro
								</button>
							</div>
						</div>
					{/if}

					<!-- KPI Row -->
					<div class="grid grid-cols-4 gap-4">
						<!-- Domains active -->
						<div class="glass glow-accent p-5 flex flex-col gap-1.5">
							<span class="text-[11px] font-medium text-white/40 uppercase tracking-wider">Active Domains</span>
							<span class="text-3xl font-bold text-white count-up tabular-nums">{status.enabled_domains}</span>
							<span class="text-[11px] text-cyan-400/60">of 39 security layers</span>
						</div>
						<!-- Total Modules -->
						<div class="glass p-5 flex flex-col gap-1.5">
							<span class="text-[11px] font-medium text-white/40 uppercase tracking-wider">Modules Loaded</span>
							<span class="text-3xl font-bold text-white count-up tabular-nums">{status.total_modules}</span>
							<span class="text-[11px] text-white/30">security components</span>
						</div>
						<!-- Active Alerts -->
						<div class="glass {alerts.critical > 0 ? 'glow-crit' : alerts.high > 0 ? 'glow-warn' : 'glow-ok'} p-5 flex flex-col gap-1.5">
							<span class="text-[11px] font-medium text-white/40 uppercase tracking-wider">Alerts</span>
							<span class="text-3xl font-bold tabular-nums count-up" style="color: {alerts.critical > 0 ? 'var(--color-crit)' : alerts.high > 0 ? 'var(--color-high)' : 'var(--color-ok)'}">{alerts.total}</span>
							<div class="flex gap-2 text-[11px]">
								{#if alerts.critical > 0}<span class="text-red-400">{alerts.critical} critical</span>{/if}
								{#if alerts.high > 0}<span class="text-orange-400">{alerts.high} high</span>{/if}
								{#if alerts.critical === 0 && alerts.high === 0}<span class="text-emerald-400/60">all clear</span>{/if}
							</div>
						</div>
						<!-- Memory -->
						<div class="glass p-5 flex flex-col gap-1.5">
							<span class="text-[11px] font-medium text-white/40 uppercase tracking-wider">Process Memory</span>
							<span class="text-3xl font-bold text-white count-up tabular-nums">{formatBytes(metrics.process_rss)}</span>
							<div class="w-full h-1.5 bg-white/[0.06] rounded-full mt-1 overflow-hidden">
								<div
									class="h-full rounded-full transition-all duration-700 ease-out bg-gradient-to-r from-cyan-500 to-blue-500"
									style="width: {metrics.process_vms > 0 ? Math.min(100, (metrics.process_rss / metrics.process_vms) * 100) : 0}%"
								></div>
							</div>
							<span class="text-[11px] text-white/30">RSS — {formatBytes(metrics.process_vms)} virtual</span>
						</div>
					</div>

					<!-- Local AI Discovery -->
					<div class="glass-bright p-5">
						<div class="flex items-center justify-between mb-4">
							<div class="flex items-center gap-2.5">
								<span class="text-base">🤖</span>
								<h2 class="text-[13px] font-semibold text-white/70 uppercase tracking-wider">Local AI Discovery</h2>
								{#if aiScan.summary.total_tools > 0}
									<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/20">{aiScan.summary.total_tools} found</span>
								{/if}
							</div>
							<button
								onclick={async () => { aiScanning = true; aiScan = await scanLocalAi(); aiScanning = false; }}
								disabled={aiScanning}
								class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-white/[0.04] text-white/50 border border-white/[0.06] hover:bg-white/[0.08] hover:text-white/70 transition-all disabled:opacity-40"
							>
								{#if aiScanning}
									<svg class="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" opacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg>
									Scanning...
								{:else}
									<svg viewBox="0 0 24 24" class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-9-9"/><polyline points="21 3 21 9 15 9"/></svg>
									Re-scan
								{/if}
							</button>
						</div>

						{#if aiScan.tools.length === 0 && !aiScanning}
							<div class="flex items-center gap-3 p-4 rounded-lg bg-white/[0.02] border border-white/[0.03]">
								<div class="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
									<svg viewBox="0 0 24 24" class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/></svg>
								</div>
								<div>
									<span class="text-[12px] text-white/60 font-medium">No local AI tools detected</span>
									<p class="text-[11px] text-white/30 mt-0.5">Scanned processes and known ports — click Re-scan to check again</p>
								</div>
							</div>
						{:else if aiScanning && aiScan.tools.length === 0}
							<div class="flex items-center justify-center p-6 text-white/30">
								<svg class="w-5 h-5 animate-spin mr-2" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" opacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg>
								<span class="text-[12px]">Scanning for local AI tools...</span>
							</div>
						{:else}
							<!-- Summary pills -->
							<div class="flex flex-wrap gap-2 mb-3">
								{#if aiScan.summary.local_llms > 0}
									<span class="px-2.5 py-1 rounded-lg text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/15">
										{aiScan.summary.local_llms} Local LLM{aiScan.summary.local_llms > 1 ? 's' : ''}
									</span>
								{/if}
								{#if aiScan.summary.coding_assistants > 0}
									<span class="px-2.5 py-1 rounded-lg text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/15">
										{aiScan.summary.coding_assistants} Coding Assistant{aiScan.summary.coding_assistants > 1 ? 's' : ''}
									</span>
								{/if}
								{#if aiScan.summary.desktop_apps > 0}
									<span class="px-2.5 py-1 rounded-lg text-[10px] font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/15">
										{aiScan.summary.desktop_apps} Desktop App{aiScan.summary.desktop_apps > 1 ? 's' : ''}
									</span>
								{/if}
								{#if aiScan.summary.dev_frameworks > 0}
									<span class="px-2.5 py-1 rounded-lg text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/15">
										{aiScan.summary.dev_frameworks} Dev Framework{aiScan.summary.dev_frameworks > 1 ? 's' : ''}
									</span>
								{/if}
								{#if aiScan.summary.image_audio > 0}
									<span class="px-2.5 py-1 rounded-lg text-[10px] font-semibold bg-pink-500/10 text-pink-400 border border-pink-500/15">
										{aiScan.summary.image_audio} Image/Audio
									</span>
								{/if}
								{#if aiScan.summary.high_risk > 0}
									<span class="px-2.5 py-1 rounded-lg text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/15">
										{aiScan.summary.high_risk} High Risk
									</span>
								{/if}
								{#if aiScan.summary.total_ai_memory_bytes > 0}
									<span class="px-2.5 py-1 rounded-lg text-[10px] font-semibold bg-white/[0.04] text-white/40 border border-white/[0.06]">
										{formatBytes(aiScan.summary.total_ai_memory_bytes)} AI memory
									</span>
								{/if}
							</div>

							<!-- Tool cards -->
							<div class="grid grid-cols-2 lg:grid-cols-3 gap-2">
								{#each aiScan.tools as tool, i}
									{@const isUnknown = tool.detection_method.startsWith('heuristic')}
									{@const riskColor = tool.risk_level === 'High' ? 'red' : tool.risk_level === 'Medium' ? 'amber' : 'emerald'}
									{@const catIcon = isUnknown ? '🚨' : tool.category === 'LocalLlm' ? '🧠' : tool.category === 'CodingAssistant' ? '💻' : tool.category === 'DesktopApp' ? '🖥️' : tool.category === 'DevFramework' ? '⚙️' : tool.category === 'ImageAudio' ? '🎨' : '🌐'}
									<div class="p-3 rounded-lg transition-all animate-in {isUnknown ? 'bg-red-500/[0.06] border-2 border-red-500/30 hover:border-red-500/50' : 'bg-white/[0.02] border border-white/[0.04] hover:border-white/[0.08]'}" style="animation-delay:{i * 40}ms">
										{#if isUnknown}
											<div class="flex items-center gap-1.5 mb-2 px-2 py-1 rounded bg-red-500/10 border border-red-500/20">
												<span class="text-[9px] font-bold text-red-400 uppercase tracking-wider">Unknown AI — Not in Database</span>
											</div>
										{/if}
										<div class="flex items-center gap-2 mb-1.5">
											<span class="text-sm">{catIcon}</span>
											<span class="text-[12px] font-semibold text-white/80 truncate flex-1">{tool.name}</span>
											<span class="px-1.5 py-px rounded text-[8px] font-bold uppercase border
												{riskColor === 'red' ? 'bg-red-500/10 text-red-400 border-red-500/20' : riskColor === 'amber' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'}">
												{tool.risk_level}
											</span>
										</div>
										<p class="text-[10px] text-white/40 leading-relaxed mb-1.5 {isUnknown ? '' : 'line-clamp-2'}">{tool.details}</p>
										{#if tool.privacy_info}
											<p class="text-[9px] text-white/25 leading-relaxed mb-1.5 line-clamp-2 italic">{tool.privacy_info}</p>
										{/if}
										<div class="flex items-center gap-3 text-[9px] text-white/25 font-mono flex-wrap">
											{#if tool.process_count > 1}<span class="text-cyan-400/60">{tool.process_count} processes</span>{/if}
											{#if tool.port}<span>:{tool.port}</span>{/if}
											{#if tool.pid}<span>PID {tool.pid}</span>{/if}
											{#if tool.memory_bytes > 0}<span>{formatBytes(tool.memory_bytes)}</span>{/if}
										</div>
									</div>
								{/each}
							</div>
						{/if}
					</div>

					<!-- Domain Grid + Recent Alerts row -->
					<div class="grid grid-cols-3 gap-5">
						<!-- Domain Grid (2/3) -->
						<div class="col-span-2 glass-bright p-5">
							<div class="flex items-center justify-between mb-4">
								<h2 class="text-[13px] font-semibold text-white/70 uppercase tracking-wider">Security Domains</h2>
								<span class="text-[11px] text-white/30">{status.domains.filter(d => d.enabled).length} active</span>
							</div>
							<div class="grid grid-cols-4 gap-2.5">
								{#each status.domains as domain, i}
									{@const locked = isDomainLocked(domain)}
									<div
										class="relative group p-3 rounded-lg transition-all duration-200 cursor-default
											{locked
												? 'bg-white/[0.01] border border-white/[0.02] opacity-50'
												: domain.enabled
													? 'bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.04] hover:border-cyan-400/20'
													: 'bg-white/[0.01] border border-white/[0.02] opacity-40'}"
										style="animation-delay: {i * 30}ms"
									>
										<div class="flex items-center gap-2 mb-1.5">
											<span class="text-base {locked ? 'grayscale' : ''}">{domainIcons[domain.domain] || '🔹'}</span>
											<span class="text-[11px] font-medium text-white/60 truncate flex-1">{domain.display_name}</span>
											{#if locked}
												<svg viewBox="0 0 24 24" class="w-3 h-3 text-white/20 flex-shrink-0" fill="none" stroke="currentColor" stroke-width="2">
													<rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
												</svg>
											{/if}
										</div>
										<div class="flex items-center justify-between">
											<span class="text-[10px] text-white/25 font-mono">{domain.module_count} mod{domain.module_count !== 1 ? 's' : ''}</span>
											<div class="flex items-center gap-1.5">
												<span class="text-[8px] font-semibold px-1 py-px rounded border {tierBadgeClass(domain.tier)}">{domain.tier === 'Free' ? 'FREE' : domain.tier === 'Pro' ? 'PRO' : 'ENT'}</span>
												{#if !locked && domain.enabled}
													<div class="w-1.5 h-1.5 rounded-full bg-emerald-400/80"></div>
												{:else}
													<div class="w-1.5 h-1.5 rounded-full bg-white/10"></div>
												{/if}
											</div>
										</div>
										{#if !locked && domain.enabled}
											<div class="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
												style="background: radial-gradient(circle at 50% 50%, rgba(0,229,255,0.04) 0%, transparent 70%);"></div>
										{/if}
									</div>
								{/each}
							</div>
						</div>

						<!-- Recent Alerts (1/3) -->
						<div class="glass-bright p-5 flex flex-col">
							<div class="flex items-center justify-between mb-4">
								<h2 class="text-[13px] font-semibold text-white/70 uppercase tracking-wider">Recent Alerts</h2>
								<button class="text-[11px] text-cyan-400/60 hover:text-cyan-400 transition-colors" onclick={() => activeTab = 'alerts'}>View all</button>
							</div>
							<div class="flex-1 overflow-y-auto space-y-2 -mr-2 pr-2">
								{#if alerts.alerts.length === 0}
									<div class="flex flex-col items-center justify-center h-full gap-2 text-white/20">
										<svg viewBox="0 0 24 24" class="w-10 h-10" fill="none" stroke="currentColor" stroke-width="1.2">
											<path d="M9 12l2 2 4-4" /><circle cx="12" cy="12" r="10" />
										</svg>
										<span class="text-[12px]">No active alerts</span>
									</div>
								{:else}
									{#each alerts.alerts.slice(0, 8) as alert, i}
										<div class="p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.03] hover:border-white/[0.06] transition-colors animate-in" style="animation-delay:{i * 50}ms">
											<div class="flex items-center justify-between mb-1">
												<span class="badge {severityClass(alert.severity)}">{alert.severity}</span>
												<span class="text-[10px] text-white/25 font-mono">{timeAgo(alert.timestamp)}</span>
											</div>
											<p class="text-[11px] text-white/60 leading-relaxed line-clamp-2">{alert.title}</p>
											<span class="text-[10px] text-white/20 mt-0.5 block">{alert.component}</span>
										</div>
									{/each}
								{/if}
							</div>
						</div>
					</div>

					<!-- System Health Bar -->
					<div class="glass p-4 flex items-center gap-6">
						<div class="flex items-center gap-2.5">
							<div class="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-lg shadow-emerald-400/30"></div>
							<span class="text-[12px] font-medium text-emerald-400">System Healthy</span>
						</div>
						<div class="h-4 w-px bg-white/[0.06]"></div>
						<span class="text-[11px] text-white/30">All {status.enabled_domains} security domains operational</span>
						<div class="flex-1"></div>
						<span class="text-[11px] text-white/20 font-mono">sentinel-core {metrics.total_budget > 0 ? 'ready' : 'init...'}</span>
					</div>
				</div>

			<!-- ═══ ALERTS TAB ═══ -->
			{:else if activeTab === 'alerts'}
				<div class="animate-in space-y-4">
					<div class="flex items-center justify-between">
						<h2 class="text-lg font-semibold text-white/90">Alert Feed</h2>
						<div class="flex gap-2 text-[12px]">
							<span class="badge badge-critical">{alerts.critical} Critical</span>
							<span class="badge badge-high">{alerts.high} High</span>
							<span class="badge badge-info">{alerts.total - alerts.critical - alerts.high} Other</span>
						</div>
					</div>

					{#if alerts.alerts.length === 0}
						<div class="glass-bright p-16 flex flex-col items-center gap-3 text-white/20">
							<svg viewBox="0 0 24 24" class="w-16 h-16" fill="none" stroke="currentColor" stroke-width="1">
								<path d="M9 12l2 2 4-4" /><circle cx="12" cy="12" r="10" />
							</svg>
							<span class="text-base">No alerts — all systems clean</span>
						</div>
					{:else}
						<div class="space-y-2">
							{#each alerts.alerts as alert, i}
								{@const key = alertKey(alert)}
								{@const isExpanded = expandedAlert === i}
								{@const rem = remediationCache.get(key)}
								{@const isLoading = remediationLoading === key}
								{@const hasChain = alert.reasoning_chain && alert.reasoning_chain.length > 0}
								{@const riskPct = (alert.risk_score ?? 0) * 100}
								{@const riskColor = riskPct >= 80 ? 'red' : riskPct >= 50 ? 'amber' : riskPct >= 20 ? 'cyan' : 'emerald'}
								<div class="glass-bright animate-in transition-all duration-300 {isExpanded ? 'ring-1 ring-cyan-500/20 shadow-lg shadow-cyan-500/5' : 'hover:border-white/[0.08]'}" style="animation-delay:{i * 30}ms">
									<!-- Alert Header — clickable to expand -->
									<button
										class="w-full p-4 flex items-start gap-4 text-left cursor-pointer"
										onclick={() => expandedAlert = isExpanded ? null : i}
									>
										<span class="badge {severityClass(alert.severity)} mt-0.5 flex-shrink-0">{alert.severity}</span>
										<div class="flex-1 min-w-0">
											<div class="flex items-center gap-2 mb-1">
												<span class="text-[13px] font-medium text-white/80">{alert.title}</span>
												{#if hasChain}
													<span class="flex items-center gap-1 px-1.5 py-px rounded-full text-[8px] font-bold uppercase border bg-cyan-500/8 text-cyan-400/60 border-cyan-500/15">
														<svg viewBox="0 0 24 24" class="w-2.5 h-2.5" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 18l6-6-6-6"/></svg>
														{alert.reasoning_chain.length} steps
													</span>
												{/if}
											</div>
											<p class="text-[12px] text-white/40 leading-relaxed line-clamp-2">{alert.details}</p>
											<div class="flex items-center gap-3 mt-1.5">
												<span class="text-[10px] text-white/25 font-mono">{alert.domain}</span>
												<span class="text-[10px] text-white/25 font-mono">{alert.component}</span>
												{#if alert.mitre_ids && alert.mitre_ids.length > 0}
													{#each alert.mitre_ids as mid}
														<span class="px-1.5 py-px rounded text-[8px] font-bold font-mono bg-red-500/8 text-red-400/50 border border-red-500/15">{mid}</span>
													{/each}
												{/if}
												{#if alert.risk_score != null}
													<div class="ml-auto flex items-center gap-1.5">
														<div class="w-16 h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
															<div class="h-full rounded-full transition-all duration-700 ease-out
																{riskColor === 'red' ? 'bg-red-500' : riskColor === 'amber' ? 'bg-amber-500' : riskColor === 'cyan' ? 'bg-cyan-500' : 'bg-emerald-500'}"
																style="width: {riskPct}%"
															></div>
														</div>
														<span class="text-[9px] font-bold font-mono tabular-nums
															{riskColor === 'red' ? 'text-red-400/70' : riskColor === 'amber' ? 'text-amber-400/70' : riskColor === 'cyan' ? 'text-cyan-400/70' : 'text-emerald-400/70'}">{riskPct.toFixed(0)}%</span>
													</div>
												{/if}
											</div>
										</div>
										<div class="flex flex-col items-end gap-1.5 flex-shrink-0">
											<span class="text-[11px] text-white/20 font-mono tabular-nums">{timeAgo(alert.timestamp)}</span>
											<svg viewBox="0 0 24 24" class="w-4 h-4 text-white/15 transition-transform duration-300 {isExpanded ? 'rotate-180' : ''}" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
										</div>
									</button>

									<!-- ═══ EXPANDED: Reasoning Chain + Remediation ═══ -->
									{#if isExpanded}
										<div class="reasoning-panel border-t border-white/[0.04]">

											<!-- ── Reasoning Chain ── -->
											{#if hasChain}
												<div class="px-4 pt-3 pb-2">
													<div class="flex items-center gap-2 mb-3">
														<div class="w-5 h-5 rounded-md bg-gradient-to-br from-violet-500/20 to-cyan-500/20 flex items-center justify-center">
															<svg viewBox="0 0 24 24" class="w-3 h-3 text-violet-400" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2zM22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
														</div>
														<span class="text-[11px] font-semibold text-violet-400/80 uppercase tracking-wider">Decision Reasoning</span>
														<span class="text-[10px] text-white/15 font-mono">&middot;</span>
														<span class="text-[10px] text-white/20 font-mono">{alert.reasoning_chain.length} evidence step{alert.reasoning_chain.length !== 1 ? 's' : ''}</span>
														{#if alert.risk_score != null}
															<div class="ml-auto flex items-center gap-2">
																<span class="text-[9px] text-white/25 uppercase tracking-wider font-medium">Risk</span>
																<div class="relative w-20 h-5 rounded-lg overflow-hidden bg-white/[0.04] border border-white/[0.06]">
																	<div class="absolute inset-y-0 left-0 rounded-lg transition-all duration-1000 ease-out
																		{riskColor === 'red' ? 'bg-gradient-to-r from-red-500/40 to-red-500/20' : riskColor === 'amber' ? 'bg-gradient-to-r from-amber-500/40 to-amber-500/20' : riskColor === 'cyan' ? 'bg-gradient-to-r from-cyan-500/40 to-cyan-500/20' : 'bg-gradient-to-r from-emerald-500/40 to-emerald-500/20'}"
																		style="width: {riskPct}%"
																	></div>
																	<span class="absolute inset-0 flex items-center justify-center text-[10px] font-bold tabular-nums
																		{riskColor === 'red' ? 'text-red-300' : riskColor === 'amber' ? 'text-amber-300' : riskColor === 'cyan' ? 'text-cyan-300' : 'text-emerald-300'}">{riskPct.toFixed(0)}%</span>
																</div>
															</div>
														{/if}
													</div>

													<!-- Step-by-step reasoning chain -->
													<div class="ml-1 space-y-0">
														{#each alert.reasoning_chain as step, si}
															{@const confPct = step.confidence * 100}
															{@const confColor = confPct >= 90 ? 'emerald' : confPct >= 70 ? 'cyan' : confPct >= 50 ? 'amber' : 'red'}
															<div class="flex gap-3 group reasoning-step" style="animation-delay:{si * 80}ms">
																<!-- Left: icon + connecting line -->
																<div class="flex flex-col items-center flex-shrink-0">
																	<div class="w-8 h-8 rounded-xl bg-gradient-to-br from-white/[0.06] to-white/[0.02] border border-white/[0.08] flex items-center justify-center text-sm group-hover:from-violet-500/15 group-hover:to-cyan-500/10 group-hover:border-violet-500/20 transition-all duration-300 shadow-sm">
																		{step.icon}
																	</div>
																	{#if si < alert.reasoning_chain.length - 1}
																		<div class="w-px flex-1 min-h-[16px] bg-gradient-to-b from-violet-500/20 via-violet-500/10 to-transparent my-1 chain-line"></div>
																	{/if}
																</div>
																<!-- Right: content -->
																<div class="flex-1 pb-3.5 {si < alert.reasoning_chain.length - 1 ? '' : 'pb-1'}">
																	<div class="flex items-center gap-2 mb-0.5">
																		<span class="text-[12px] font-semibold text-white/70 group-hover:text-white/90 transition-colors">{step.label}</span>
																		<span class="px-1.5 py-px rounded text-[8px] font-bold uppercase tracking-wider border
																			{step.step_type === 'pattern_match' ? 'bg-amber-500/8 text-amber-400/50 border-amber-500/15' :
																			 step.step_type === 'graph_edge' ? 'bg-violet-500/8 text-violet-400/50 border-violet-500/15' :
																			 step.step_type === 'flow_hop' ? 'bg-blue-500/8 text-blue-400/50 border-blue-500/15' :
																			 step.step_type === 'os_signal' ? 'bg-pink-500/8 text-pink-400/50 border-pink-500/15' :
																			 step.step_type === 'comparison' ? 'bg-teal-500/8 text-teal-400/50 border-teal-500/15' :
																			 'bg-white/[0.04] text-white/30 border-white/[0.06]'}">{step.step_type.replace('_', ' ')}</span>
																	</div>
																	<p class="text-[11px] text-white/40 leading-relaxed group-hover:text-white/55 transition-colors">{step.detail}</p>
																	<!-- Confidence bar -->
																	<div class="flex items-center gap-2 mt-1.5">
																		<span class="text-[8px] text-white/20 uppercase tracking-wider font-medium w-12">conf.</span>
																		<div class="flex-1 h-1 rounded-full bg-white/[0.04] overflow-hidden max-w-[120px]">
																			<div class="h-full rounded-full transition-all duration-700 ease-out
																				{confColor === 'emerald' ? 'bg-emerald-500/60' : confColor === 'cyan' ? 'bg-cyan-500/60' : confColor === 'amber' ? 'bg-amber-500/60' : 'bg-red-500/60'}"
																				style="width: {confPct}%"
																			></div>
																		</div>
																		<span class="text-[9px] font-mono tabular-nums
																			{confColor === 'emerald' ? 'text-emerald-400/50' : confColor === 'cyan' ? 'text-cyan-400/50' : confColor === 'amber' ? 'text-amber-400/50' : 'text-red-400/50'}">{confPct.toFixed(0)}%</span>
																	</div>
																</div>
															</div>
														{/each}
													</div>
												</div>
											{/if}

											<!-- ── Remediation section ── -->
											<div class="px-4 pb-3 pt-1">
												{#if !rem && !isLoading}
													<button
														onclick={() => requestRemediation(alert, i)}
														class="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-[11px] font-semibold transition-all bg-white/[0.03] text-white/40 border border-white/[0.06] hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/20"
													>
														<svg viewBox="0 0 24 24" class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
														Get Remediation Plan
													</button>
												{:else if isLoading}
													<div class="rounded-xl border border-cyan-500/10 bg-gradient-to-b from-cyan-950/20 to-transparent overflow-hidden">
														<div class="flex items-center gap-2.5 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.015]">
															<div class="w-5 h-5 rounded-md shimmer bg-white/[0.04]"></div>
															<div class="h-3 w-28 rounded shimmer bg-white/[0.04]"></div>
															<div class="flex-1"></div>
															<div class="h-3 w-12 rounded shimmer bg-white/[0.04]"></div>
														</div>
														<div class="p-4 space-y-3">
															{#each Array(3) as _, si}
																<div class="flex gap-3 items-start" style="opacity:{1 - si * 0.2}">
																	<div class="w-6 h-6 rounded-lg shimmer bg-white/[0.04] flex-shrink-0"></div>
																	<div class="flex-1 space-y-1.5 pt-0.5">
																		<div class="h-3 rounded shimmer bg-white/[0.04]" style="width:{85 - si * 15}%"></div>
																	</div>
																</div>
															{/each}
														</div>
														<div class="px-4 py-2.5 border-t border-white/[0.04] flex items-center justify-center gap-2">
															<div class="ai-pulse w-1.5 h-1.5 rounded-full bg-cyan-400/80"></div>
															<span class="text-[11px] text-cyan-400/50 font-medium">Generating remediation plan...</span>
														</div>
													</div>
												{:else if rem}
													{#if rem.gated}
														<div class="relative overflow-hidden rounded-xl border border-indigo-500/20 bg-gradient-to-br from-indigo-950/40 via-surface-900/60 to-purple-950/30 p-4">
															<div class="absolute inset-0 bg-gradient-to-r from-indigo-500/[0.03] via-transparent to-purple-500/[0.03] upgrade-shimmer"></div>
															<div class="relative flex items-center gap-4">
																<div class="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-400/20 flex items-center justify-center flex-shrink-0">
																	<svg viewBox="0 0 24 24" class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09Z" /></svg>
																</div>
																<div class="flex-1 min-w-0">
																	<p class="text-[12px] font-semibold text-indigo-300/90 mb-0.5">AI-Powered Remediation</p>
																	<p class="text-[10px] text-white/35 leading-relaxed">{rem.message}</p>
																</div>
																<button onclick={() => handlePayment('Pro')} class="px-3 py-1.5 rounded-lg text-[11px] font-semibold bg-gradient-to-r from-indigo-500/25 to-purple-500/25 text-indigo-300 border border-indigo-400/25 hover:from-indigo-500/35 hover:to-purple-500/35 transition-all flex-shrink-0">
																	Upgrade
																</button>
															</div>
														</div>
													{:else}
														{@const steps = parseSteps(rem.advice ?? '')}
														<div class="rounded-xl border border-cyan-500/10 bg-gradient-to-b from-cyan-950/20 to-transparent overflow-hidden">
															<div class="flex items-center gap-2.5 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.015]">
																<div class="w-5 h-5 rounded-md bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center">
																	<svg viewBox="0 0 24 24" class="w-3 h-3 text-cyan-400" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09Z" /></svg>
																</div>
																<span class="text-[11px] font-semibold text-cyan-400/80 uppercase tracking-wider">Remediation Plan</span>
																<span class="text-[10px] text-white/20 font-mono">{steps.length} step{steps.length !== 1 ? 's' : ''}</span>
																<div class="flex-1"></div>
																{#if rem.cached}<span class="text-[9px] text-white/20 font-mono px-1.5 py-0.5 rounded bg-white/[0.03]">cached</span>{/if}
																<div class="flex items-center gap-1 px-1.5 py-0.5 rounded bg-white/[0.03]">
																	<div class="w-1 h-1 rounded-full {(rem.model ?? '').includes('heuristic') ? 'bg-amber-400/60' : 'bg-cyan-400/60'}"></div>
																	<span class="text-[9px] text-white/25 font-mono">{(rem.model ?? '').includes('heuristic') ? 'built-in' : 'AI'}</span>
																</div>
																<button onclick={() => copyAdvice(key, rem.advice ?? '')} class="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium transition-all {copiedKey === key ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' : 'bg-white/[0.03] text-white/25 hover:text-white/50 hover:bg-white/[0.06]'}">
																	{#if copiedKey === key}
																		<svg viewBox="0 0 24 24" class="w-2.5 h-2.5" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6 9 17l-5-5"/></svg>
																		Copied
																	{:else}
																		<svg viewBox="0 0 24 24" class="w-2.5 h-2.5" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
																		Copy
																	{/if}
																</button>
															</div>
															<div class="p-4 space-y-0">
																{#each steps as step, si}
																	<div class="flex gap-3 group remediation-step" style="animation-delay:{si * 60}ms">
																		<div class="flex flex-col items-center flex-shrink-0">
																			{#if step.num}
																				<div class="w-6 h-6 rounded-lg bg-gradient-to-br from-cyan-500/15 to-blue-500/15 border border-cyan-500/20 flex items-center justify-center text-[10px] font-bold text-cyan-400/80 shadow-sm shadow-cyan-500/5 group-hover:from-cyan-500/25 group-hover:to-blue-500/25 group-hover:border-cyan-500/30 transition-all duration-200">{step.num}</div>
																			{:else}
																				<div class="w-6 h-6 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center"><div class="w-1.5 h-1.5 rounded-full bg-white/20"></div></div>
																			{/if}
																			{#if si < steps.length - 1}
																				<div class="w-px flex-1 min-h-[12px] bg-gradient-to-b from-cyan-500/15 to-transparent my-1"></div>
																			{/if}
																		</div>
																		<div class="flex-1 pb-3 {si < steps.length - 1 ? '' : 'pb-0'}">
																			<p class="text-[12px] text-white/60 leading-relaxed group-hover:text-white/75 transition-colors duration-200">{step.text}</p>
																		</div>
																	</div>
																{/each}
															</div>

															<!-- Fix It Button -->
															{#if !fixItResults.has(alertKey(alert))}
																<div class="px-4 py-3 border-t border-white/[0.04]">
																	<button
																		onclick={() => handleFixIt(alert)}
																		disabled={fixItLoading === alertKey(alert)}
																		class="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-[12px] font-bold transition-all {fixItLoading === alertKey(alert) ? 'bg-emerald-500/10 text-emerald-400/50 border border-emerald-500/10 cursor-wait' : 'bg-gradient-to-r from-emerald-500/20 to-cyan-500/20 text-emerald-300 border border-emerald-500/25 hover:from-emerald-500/30 hover:to-cyan-500/30 hover:border-emerald-400/40 hover:shadow-lg hover:shadow-emerald-500/10'}"
																	>
																		{#if fixItLoading === alertKey(alert)}
																			<div class="ai-pulse w-1.5 h-1.5 rounded-full bg-emerald-400/80"></div>
																			Executing remediation...
																		{:else}
																			<svg viewBox="0 0 24 24" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
																			Fix It — Auto-Remediate
																		{/if}
																	</button>
																</div>
															{:else}
																{@const fixResult = fixItResults.get(alertKey(alert))}
																{#if fixResult}
																<div class="px-4 py-3 border-t border-white/[0.04] space-y-2">
																	<div class="flex items-center gap-2">
																		<div class="w-5 h-5 rounded-md flex items-center justify-center {fixResult.report?.overall_success ? 'bg-emerald-500/20' : 'bg-amber-500/20'}">
																			{#if fixResult.report?.overall_success}
																				<svg viewBox="0 0 24 24" class="w-3 h-3 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6 9 17l-5-5"/></svg>
																			{:else}
																				<svg viewBox="0 0 24 24" class="w-3 h-3 text-amber-400" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M3.6 20h16.8a1 1 0 0 0 .87-1.5l-8.4-14.5a1 1 0 0 0-1.74 0L2.73 18.5A1 1 0 0 0 3.6 20z"/></svg>
																			{/if}
																		</div>
																		<span class="text-[11px] font-semibold {fixResult.report?.overall_success ? 'text-emerald-400/80' : 'text-amber-400/80'} uppercase tracking-wider">Remediation Result</span>
																		{#if fixResult.report}
																			<span class="text-[9px] text-white/20 font-mono">{fixResult.report.total_duration_ms}ms</span>
																		{/if}
																	</div>
																	<p class="text-[11px] text-white/50 leading-relaxed">{fixResult.summary}</p>
																	{#if fixResult.validation}
																		<div class="flex items-center gap-2 pt-1">
																			<div class="flex items-center gap-1.5 px-2 py-1 rounded-lg {fixResult.validation.passed ? 'bg-emerald-500/10 border border-emerald-500/15' : 'bg-red-500/10 border border-red-500/15'}">
																				<div class="w-1.5 h-1.5 rounded-full {fixResult.validation.passed ? 'bg-emerald-400' : 'bg-red-400'}"></div>
																				<span class="text-[9px] font-semibold {fixResult.validation.passed ? 'text-emerald-400/80' : 'text-red-400/80'}">
																					{fixResult.validation.passed ? 'Validated' : 'Blocked'}
																				</span>
																			</div>
																			<div class="flex items-center gap-1 px-2 py-1 rounded-lg bg-white/[0.03]">
																				<span class="text-[9px] text-white/30">Confidence</span>
																				<span class="text-[9px] font-mono font-bold {fixResult.validation.confidence >= 0.8 ? 'text-emerald-400/70' : fixResult.validation.confidence >= 0.5 ? 'text-amber-400/70' : 'text-red-400/70'}">{Math.round(fixResult.validation.confidence * 100)}%</span>
																			</div>
																			{#if fixResult.validation.filtered_actions.length > 0}
																				<span class="text-[9px] text-amber-400/50 font-mono">{fixResult.validation.filtered_actions.length} filtered</span>
																			{/if}
																		</div>
																		{#if fixResult.validation.findings.some(f => f.severity !== 'Info')}
																			<div class="space-y-0.5 pt-0.5">
																				{#each fixResult.validation.findings.filter(f => f.severity !== 'Info') as finding}
																					<div class="flex items-start gap-1.5 text-[9px]">
																						<div class="w-1 h-1 rounded-full mt-1 flex-shrink-0 {finding.severity === 'Critical' ? 'bg-red-400' : 'bg-amber-400'}"></div>
																						<span class="{finding.severity === 'Critical' ? 'text-red-400/60' : 'text-amber-400/50'}">{finding.message}</span>
																					</div>
																				{/each}
																			</div>
																		{/if}
																	{/if}
																	{#if fixResult.parsed_actions.length > 0}
																		<div class="flex flex-wrap gap-1.5 pt-1">
																			{#each fixResult.parsed_actions as action}
																				<span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400/70 border border-emerald-500/15">{action}</span>
																			{/each}
																		</div>
																	{/if}
																	{#if fixResult.report}
																		<div class="space-y-1 pt-1">
																			{#each fixResult.report.actions_taken as act}
																				<div class="flex items-center gap-2 text-[10px]">
																					<div class="w-1.5 h-1.5 rounded-full {act.status === 'Completed' ? 'bg-emerald-400' : act.status === 'Skipped' ? 'bg-amber-400' : act.status === 'DryRun' ? 'bg-blue-400' : 'bg-red-400'}"></div>
																					<span class="text-white/40 font-mono">{act.action_type}</span>
																					<span class="text-white/25">{act.status}</span>
																					{#if act.result?.message}
																						<span class="text-white/20 truncate">{act.result.message}</span>
																					{/if}
																				</div>
																			{/each}
																		</div>
																	{/if}
																</div>
																{/if}
															{/if}
														</div>
													{/if}
												{/if}
											</div>
										</div>
									{/if}
								</div>
							{/each}
						</div>
					{/if}
				</div>

			<!-- ═══ DOMAINS TAB ═══ -->
			{:else if activeTab === 'domains'}
				<div class="animate-in space-y-4">
					<div class="flex items-center justify-between">
						<h2 class="text-lg font-semibold text-white/90">Security Domains</h2>
						<div class="flex gap-2">
							{#each (['Free', 'Pro', 'Enterprise'] as const) as t}
								<span class="text-[10px] font-semibold px-2 py-0.5 rounded-full border {tierBadgeClass(t)}">{t === 'Free' ? 'Community' : t}</span>
							{/each}
						</div>
					</div>

					{#each (['Free', 'Pro', 'Enterprise'] as const) as tier}
						{@const tierDomains = status.domains.filter(d => d.tier === tier)}
						{#if tierDomains.length > 0}
							<div>
								<div class="flex items-center gap-2 mb-3">
									<span class="text-[12px] font-semibold uppercase tracking-wider {tier === 'Free' ? 'text-emerald-400/70' : tier === 'Pro' ? 'text-indigo-400/70' : 'text-amber-400/70'}">
										{tier === 'Free' ? 'Community Shield' : tier} — {tierDomains.length} domains, {tierDomains.reduce((s, d) => s + d.module_count, 0)} modules
									</span>
									{#if tierOrder[tier] > tierOrder[tierInfo.current]}
										<span class="text-[10px] text-white/20 flex items-center gap-1">
											<svg viewBox="0 0 24 24" class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
											Upgrade to unlock
										</span>
									{/if}
								</div>
								<div class="grid grid-cols-3 gap-3">
									{#each tierDomains as domain, i}
										{@const locked = isDomainLocked(domain)}
										<div
											class="glass-bright p-5 flex items-start gap-4 animate-in {locked ? 'opacity-40' : domain.enabled ? '' : 'opacity-40'}"
											style="animation-delay:{i * 25}ms"
										>
											<div class="w-11 h-11 rounded-xl flex items-center justify-center text-xl flex-shrink-0 {locked ? 'bg-white/[0.02] border border-white/[0.04] grayscale' : domain.enabled ? 'bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-400/10' : 'bg-white/[0.02] border border-white/[0.04]'}">
												{domainIcons[domain.domain] || '🔹'}
											</div>
											<div class="flex-1 min-w-0">
												<div class="flex items-center gap-2 mb-0.5">
													<span class="text-[13px] font-semibold text-white/80 truncate">{domain.display_name}</span>
													<span class="text-[8px] font-semibold px-1 py-px rounded border {tierBadgeClass(domain.tier)}">{domain.tier === 'Free' ? 'FREE' : domain.tier === 'Pro' ? 'PRO' : 'ENT'}</span>
													{#if locked}
														<svg viewBox="0 0 24 24" class="w-3.5 h-3.5 text-white/20 flex-shrink-0" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
													{:else if domain.enabled}
														<div class="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0"></div>
													{/if}
												</div>
												<span class="text-[11px] text-white/30 font-mono">{domain.module_count} module{domain.module_count !== 1 ? 's' : ''} {locked ? 'locked' : 'loaded'}</span>
												<div class="w-full h-1 bg-white/[0.04] rounded-full mt-2.5 overflow-hidden">
													<div class="h-full rounded-full {locked ? 'bg-white/[0.06]' : 'bg-gradient-to-r from-cyan-500/40 to-blue-500/40'}" style="width: {locked ? '0%' : '100%'}"></div>
												</div>
											</div>
										</div>
									{/each}
								</div>
							</div>
						{/if}
					{/each}
				</div>

			<!-- ═══ PRICING TAB ═══ -->
			{:else if activeTab === 'pricing'}
				<div class="animate-in space-y-6 max-w-4xl mx-auto">
					<div class="text-center mb-2">
						<h2 class="text-2xl font-bold text-white/90 mb-1">Choose Your Plan</h2>
						<p class="text-[13px] text-white/40">Powered by memory breakthroughs — runs on your device, not the cloud</p>
					</div>

					<div class="grid grid-cols-3 gap-5">
						{#each tierInfo.tiers as td, i}
							{@const active = tierInfo.current === td.tier}
							{@const isCurrent = (auth.user?.tier || 'Free') === td.tier}
							<div
								class="relative glass-bright p-6 flex flex-col animate-in rounded-2xl transition-all duration-300
									{active ? 'ring-1 ' + (td.tier === 'Free' ? 'ring-emerald-500/30' : td.tier === 'Pro' ? 'ring-indigo-500/30' : 'ring-amber-500/30') : ''}"
								style="animation-delay:{i * 80}ms"
							>
								{#if isCurrent}
									<div class="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider
										{td.tier === 'Free' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : td.tier === 'Pro' ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'}">
										Current Plan
									</div>
								{/if}

								<div class="mb-5">
									<h3 class="text-[18px] font-bold text-white/90 mb-1">{td.name}</h3>
									<div class="flex items-baseline gap-1">
										<span class="text-3xl font-bold {td.tier === 'Free' ? 'text-emerald-400' : td.tier === 'Pro' ? 'text-indigo-400' : 'text-amber-400'}">{td.price === '$0' ? 'Free' : td.price.split('/')[0]}</span>
										{#if td.price !== '$0'}
											<span class="text-[12px] text-white/30">/{td.price.split('/').slice(1).join('/')}</span>
										{/if}
									</div>
								</div>

								<div class="flex gap-6 mb-5 pb-5 border-b border-white/[0.06]">
									<div>
										<span class="text-2xl font-bold text-white/80 tabular-nums">{td.domains}</span>
										<span class="text-[11px] text-white/30 block">domains</span>
									</div>
									<div>
										<span class="text-2xl font-bold text-white/80 tabular-nums">{td.modules}</span>
										<span class="text-[11px] text-white/30 block">modules</span>
									</div>
								</div>

								<ul class="space-y-2.5 flex-1">
									{#each td.features as feature}
										<li class="flex items-center gap-2 text-[12px] text-white/50">
											<svg viewBox="0 0 24 24" class="w-4 h-4 flex-shrink-0 {td.tier === 'Free' ? 'text-emerald-400/60' : td.tier === 'Pro' ? 'text-indigo-400/60' : 'text-amber-400/60'}" fill="none" stroke="currentColor" stroke-width="2.5">
												<path d="M20 6L9 17l-5-5" />
											</svg>
											{feature}
										</li>
									{/each}
								</ul>

								<button
									onclick={() => {
										if (isCurrent) return;
										if (td.tier !== 'Free' && tierOrder[td.tier] > tierOrder[(auth.user?.tier || 'Free') as Tier]) {
											handlePayment(td.tier);
										} else {
											switchTier(td.tier);
										}
									}}
									class="mt-5 w-full py-2.5 rounded-xl text-[13px] font-semibold transition-all
										{isCurrent
											? 'bg-white/[0.04] text-white/30 border border-white/[0.06] cursor-default'
											: td.tier === 'Free' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30'
											: td.tier === 'Pro' ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/30'
											: 'bg-amber-500/20 text-amber-400 border border-amber-500/30 hover:bg-amber-500/30'}"
								>
									{isCurrent ? 'Current Plan' : tierOrder[td.tier] > tierOrder[(auth.user?.tier || 'Free') as Tier] ? 'Upgrade' : 'Switch'}
								</button>
							</div>
						{/each}
					</div>

					<!-- Value comparison -->
					<div class="glass p-5 mt-2">
						<div class="flex items-center gap-3 mb-3">
							<span class="text-[13px] font-semibold text-white/70">Why Beaver Warrior?</span>
						</div>
						<div class="grid grid-cols-3 gap-4 text-center">
							<div>
								<span class="text-2xl font-bold text-cyan-400">$2-5M</span>
								<span class="text-[11px] text-white/30 block mt-1">Traditional security stack cost/yr</span>
							</div>
							<div>
								<span class="text-2xl font-bold text-emerald-400">512 MB</span>
								<span class="text-[11px] text-white/30 block mt-1">Runs on your laptop — not a server farm</span>
							</div>
							<div>
								<span class="text-2xl font-bold text-amber-400">466</span>
								<span class="text-[11px] text-white/30 block mt-1">Security modules across 39 domains</span>
							</div>
						</div>
					</div>
				</div>

			<!-- ═══ ACCOUNT TAB ═══ -->
			{:else if activeTab === 'account'}
				<div class="animate-in space-y-6 max-w-2xl mx-auto">
					<!-- Profile Header -->
					<div class="glass-bright rounded-2xl p-6 flex items-center gap-5">
						<div class="w-16 h-16 rounded-2xl flex items-center justify-center text-xl font-bold
							{auth.user?.tier === 'Free' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20'
							: auth.user?.tier === 'Pro' ? 'bg-indigo-500/15 text-indigo-400 border border-indigo-500/20'
							: 'bg-amber-500/15 text-amber-400 border border-amber-500/20'}">
							{userInitials(auth.user)}
						</div>
						<div class="flex-1">
							<h2 class="text-[18px] font-bold text-white/90">{auth.user?.name || 'User'}</h2>
							<p class="text-[13px] text-white/40">{auth.user?.email || ''}</p>
							{#if auth.user?.company}
								<p class="text-[12px] text-white/25 mt-0.5">{auth.user.company}</p>
							{/if}
						</div>
						<div class="flex flex-col items-end gap-2">
							<span class="px-3 py-1 rounded-full text-[11px] font-semibold border {tierBadgeClass(auth.user?.tier || 'Free')}">
								{auth.user?.tier === 'Free' ? 'Community Shield' : auth.user?.tier || 'Free'}
							</span>
							<span class="text-[10px] text-white/20">
								Member since {auth.user?.created_at ? new Date(auth.user.created_at).toLocaleDateString() : ''}
							</span>
						</div>
					</div>

					<div class="grid grid-cols-2 gap-5">
						<!-- Edit Profile -->
						<div class="glass-bright rounded-2xl p-6">
							<h3 class="text-[14px] font-semibold text-white/70 mb-4">Edit Profile</h3>
							<div class="space-y-3">
								<div>
									<label for="edit-name" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1">Name</label>
									<input id="edit-name" type="text" bind:value={editName} class="acct-input" />
								</div>
								<div>
									<label for="edit-company" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1">Company</label>
									<input id="edit-company" type="text" bind:value={editCompany} placeholder="Optional" class="acct-input" />
								</div>
								{#if profileMsg}
									<p class="text-[11px] text-emerald-400/80">{profileMsg}</p>
								{/if}
								<button onclick={saveProfile} class="w-full py-2 rounded-lg text-[12px] font-medium bg-white/[0.04] text-white/60 border border-white/[0.06] hover:bg-white/[0.08] transition-all">
									Save Changes
								</button>
							</div>
						</div>

						<!-- Subscription -->
						<div class="glass-bright rounded-2xl p-6">
							<h3 class="text-[14px] font-semibold text-white/70 mb-4">Subscription</h3>
							<div class="space-y-3">
								<div class="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
									<div>
										<span class="text-[13px] font-semibold text-white/70">Current Plan</span>
										<span class="text-[11px] text-white/30 block">{auth.user?.tier === 'Free' ? 'Community Shield — $0' : auth.user?.tier === 'Pro' ? 'Pro — $29/user/mo' : 'Enterprise — $99/user/mo'}</span>
									</div>
									<span class="px-2 py-0.5 rounded-full text-[10px] font-semibold border {tierBadgeClass(auth.user?.tier || 'Free')}">
										{auth.user?.tier || 'Free'}
									</span>
								</div>

								<div class="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
									<span class="text-[12px] text-white/50">Domains Available</span>
									<span class="text-[12px] text-white/70 font-mono tabular-nums">
										{status.domains.filter(d => !isDomainLocked(d)).length} / {status.domains.length}
									</span>
								</div>
								<div class="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
									<span class="text-[12px] text-white/50">Modules Active</span>
									<span class="text-[12px] text-white/70 font-mono tabular-nums">
										{status.domains.filter(d => !isDomainLocked(d)).reduce((s, d) => s + d.module_count, 0)} / {status.total_modules}
									</span>
								</div>
								<div class="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
									<span class="text-[12px] text-white/50">Team Size</span>
									<span class="text-[12px] text-white/70 font-mono tabular-nums">{auth.user?.team_size || 1}</span>
								</div>

								{#if auth.user?.license_valid && auth.user?.tier !== 'Free'}
									<div class="flex items-center gap-2 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/15">
										<svg viewBox="0 0 24 24" class="w-4 h-4 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><path d="M22 4 12 14.01l-3-3" />
										</svg>
										<div class="flex-1">
											<span class="text-[11px] text-emerald-400 font-medium">License Active</span>
											{#if auth.user?.license_expiry}
												<span class="text-[10px] text-white/25 block">Expires {new Date(auth.user.license_expiry).toLocaleDateString()}</span>
											{/if}
										</div>
									</div>
								{:else if auth.user?.tier === 'Free'}
									<div class="flex items-center gap-2 p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
										<span class="text-[11px] text-white/40">Free tier — no license required</span>
									</div>
								{:else}
									<div class="flex items-center gap-2 p-3 rounded-lg bg-amber-500/5 border border-amber-500/15">
										<svg viewBox="0 0 24 24" class="w-4 h-4 text-amber-400 flex-shrink-0" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><path d="M12 9v4M12 17h.01" />
										</svg>
										<span class="text-[11px] text-amber-400">License expired or missing — tier reverted to Free</span>
									</div>
								{/if}

								{#if auth.user?.tier === 'Free'}
								<!-- Payment buttons -->
								<div class="grid grid-cols-2 gap-2">
									<button onclick={() => handlePayment('Pro')}
										class="py-2 rounded-lg text-[11px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 hover:bg-indigo-500/20 transition-all">
										Buy Pro — $29/mo
									</button>
									<button onclick={() => handlePayment('Enterprise')}
										class="py-2 rounded-lg text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20 transition-all">
										Buy Enterprise — $99/mo
									</button>
								</div>
							{:else}
								<!-- Manage / Cancel subscription -->
								<button onclick={handleManageSubscription}
									class="w-full py-2 rounded-lg text-[11px] font-semibold bg-white/[0.04] text-white/50 border border-white/10 hover:bg-white/[0.08] hover:text-white/70 transition-all">
									Manage Subscription
								</button>
							{/if}

								<!-- License key input -->
								<div>
									<label for="license-key" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1">License Key</label>
									<div class="flex gap-2">
										<input id="license-key" type="text" bind:value={licenseKey} placeholder="NS-PRO-xxxx-xxxx-xxxx" class="acct-input flex-1 font-mono text-[12px]" />
										<button onclick={handleActivateLicense}
											class="px-3 py-2 rounded-lg text-[11px] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-all whitespace-nowrap">
											Activate
										</button>
									</div>
									{#if licenseMsg}
										<p class="text-[11px] mt-1 {licenseMsgOk ? 'text-emerald-400/80' : 'text-red-400/80'}">{licenseMsg}</p>
									{/if}
								</div>
							</div>
						</div>
					</div>

					<!-- Usage Stats -->
					<div class="glass-bright rounded-2xl p-6">
						<h3 class="text-[14px] font-semibold text-white/70 mb-4">Usage Statistics</h3>
						<div class="grid grid-cols-4 gap-4">
							<div class="text-center p-4 rounded-xl bg-white/[0.02] border border-white/[0.04]">
								<span class="text-2xl font-bold text-white/80 tabular-nums block">{status.enabled_domains}</span>
								<span class="text-[10px] text-white/30">Active Domains</span>
							</div>
							<div class="text-center p-4 rounded-xl bg-white/[0.02] border border-white/[0.04]">
								<span class="text-2xl font-bold text-white/80 tabular-nums block">{status.total_modules}</span>
								<span class="text-[10px] text-white/30">Total Modules</span>
							</div>
							<div class="text-center p-4 rounded-xl bg-white/[0.02] border border-white/[0.04]">
								<span class="text-2xl font-bold text-white/80 tabular-nums block">{alerts.total}</span>
								<span class="text-[10px] text-white/30">Alerts Generated</span>
							</div>
							<div class="text-center p-4 rounded-xl bg-white/[0.02] border border-white/[0.04]">
								<span class="text-2xl font-bold text-white/80 tabular-nums block">{formatBytes(metrics.process_rss)}</span>
								<span class="text-[10px] text-white/30">Memory Used</span>
							</div>
						</div>
					</div>

					<!-- Danger Zone -->
					<div class="glass-bright rounded-2xl p-6 border border-red-500/10">
						<div class="flex items-center justify-between">
							<div>
								<h3 class="text-[14px] font-semibold text-white/70">Sign Out</h3>
								<p class="text-[11px] text-white/30 mt-0.5">Your session and preferences will be preserved</p>
							</div>
							<button
								onclick={handleLogout}
								class="px-4 py-2 rounded-lg text-[12px] font-medium bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-all"
							>
								Sign Out
							</button>
						</div>
					</div>
				</div>
			{/if}

		</div>
	</main>
</div>

<!-- ═══ Scoped Styles ═══ -->
<style>
	.nav-btn {
		position: relative;
		width: 44px;
		height: 44px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 12px;
		color: rgba(255,255,255,0.3);
		transition: all 0.2s ease;
		cursor: pointer;
		background: transparent;
		border: 1px solid transparent;
	}
	.nav-btn:hover {
		color: rgba(255,255,255,0.6);
		background: rgba(255,255,255,0.03);
	}
	.nav-active {
		color: rgba(0,229,255,0.9) !important;
		background: rgba(0,229,255,0.08) !important;
		border-color: rgba(0,229,255,0.15) !important;
		box-shadow: 0 0 12px rgba(0,229,255,0.08);
	}

	.line-clamp-2 {
		display: -webkit-box;
		-webkit-line-clamp: 2;
		line-clamp: 2;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}

	:global(.acct-input) {
		width: 100%;
		padding: 8px 12px;
		border-radius: 8px;
		background: rgba(255,255,255,0.03);
		border: 1px solid rgba(255,255,255,0.06);
		color: rgba(255,255,255,0.85);
		font-size: 13px;
		outline: none;
		transition: all 0.2s ease;
	}
	:global(.acct-input::placeholder) {
		color: rgba(255,255,255,0.2);
	}
	:global(.acct-input:focus) {
		border-color: rgba(0,229,255,0.3);
		background: rgba(255,255,255,0.04);
		box-shadow: 0 0 0 3px rgba(0,229,255,0.06);
	}
</style>

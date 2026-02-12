<script lang="ts">
	import { onMount } from 'svelte';
	import { getStatus, getAlerts, getMetrics, getTierInfo, setTier, getAuthState, authLogout, activateLicense, getPaymentUrl, updateProfile, checkForUpdate, refreshTier, getPortalUrl, domainIcons, formatUptime, formatBytes, timeAgo, tierColors, tierGradients } from '$lib/tauri';
	import { open } from '@tauri-apps/plugin-shell';
	import type { StatusResponse, AlertResponse, MetricsResponse, DomainStatus, UnifiedAlert, TierInfo, Tier, AuthState, UserProfile, LicenseResult, UpdateCheck } from '$lib/tauri';

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
										<h3 class="text-[14px] font-bold text-white/90">Unlock 21 domains & 161 modules</h3>
										<p class="text-[12px] text-white/40 mt-0.5">Upgrade to Pro for SIEM, Cloud, Identity, Supply Chain & more — $29/user/mo</p>
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
							<span class="text-[11px] text-cyan-400/60">of 38 security layers</span>
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
								<div class="glass-bright p-4 flex items-start gap-4 animate-in" style="animation-delay:{i * 30}ms">
									<span class="badge {severityClass(alert.severity)} mt-0.5 flex-shrink-0">{alert.severity}</span>
									<div class="flex-1 min-w-0">
										<div class="flex items-center gap-2 mb-1">
											<span class="text-[13px] font-medium text-white/80">{alert.title}</span>
										</div>
										<p class="text-[12px] text-white/40 leading-relaxed">{alert.details}</p>
										<div class="flex gap-3 mt-1.5 text-[10px] text-white/25 font-mono">
											<span>{alert.domain}</span>
											<span>{alert.component}</span>
										</div>
									</div>
									<span class="text-[11px] text-white/20 font-mono flex-shrink-0 tabular-nums">{timeAgo(alert.timestamp)}</span>
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
								<span class="text-2xl font-bold text-amber-400">241</span>
								<span class="text-[11px] text-white/30 block mt-1">Security modules across 38 domains</span>
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

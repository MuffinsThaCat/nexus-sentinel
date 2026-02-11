<script lang="ts">
	import { authSignup, authLogin, oauthLogin } from '$lib/tauri';
	import type { AuthState, OAuthProvider } from '$lib/tauri';

	let { onAuth }: { onAuth: (state: AuthState) => void } = $props();

	let mode: 'login' | 'signup' = $state('login');
	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let name = $state('');
	let company = $state('');
	let error = $state('');
	let loading = $state(false);
	let oauthLoading: OAuthProvider | null = $state(null);

	async function handleSubmit() {
		error = '';
		if (!email.trim() || !password) {
			error = 'Email and password are required';
			return;
		}
		if (mode === 'signup') {
			if (!name.trim()) { error = 'Name is required'; return; }
			if (password.length < 6) { error = 'Password must be at least 6 characters'; return; }
			if (password !== confirmPassword) { error = 'Passwords do not match'; return; }
		}

		loading = true;
		const result = mode === 'signup'
			? await authSignup(email, password, name, company || undefined)
			: await authLogin(email, password);
		loading = false;

		if (result.success) {
			onAuth(result.state);
		} else {
			error = result.message;
		}
	}

	function switchMode() {
		mode = mode === 'login' ? 'signup' : 'login';
		error = '';
	}

	async function handleOAuth(provider: OAuthProvider) {
		error = '';
		oauthLoading = provider;
		const result = await oauthLogin(provider);
		oauthLoading = null;
		if (result.success) {
			onAuth(result.state);
		} else {
			error = result.message;
		}
	}
</script>

<div class="h-full overflow-y-auto py-8">
	<div class="w-full max-w-md mx-auto">
		<!-- Logo + branding -->
		<div class="flex flex-col items-center mb-6">
			<div class="w-20 h-20 rounded-2xl overflow-hidden mb-4 shadow-xl shadow-cyan-500/20">
				<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="w-full h-full">
					<defs>
						<linearGradient id="abg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#0f172a"/><stop offset="100%" stop-color="#020617"/></linearGradient>
						<linearGradient id="afur" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#a16207"/><stop offset="100%" stop-color="#78350f"/></linearGradient>
						<linearGradient id="ahelmet" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#67e8f9"/><stop offset="100%" stop-color="#0891b2"/></linearGradient>
						<linearGradient id="ashield" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#22d3ee"/><stop offset="100%" stop-color="#0e7490"/></linearGradient>
						<linearGradient id="acrest" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#a5f3fc"/><stop offset="100%" stop-color="#06b6d4"/></linearGradient>
					</defs>
					<circle cx="256" cy="256" r="250" fill="url(#abg)"/>
					<circle cx="256" cy="256" r="240" fill="none" stroke="#22d3ee" stroke-width="3" opacity="0.2"/>
					<ellipse cx="120" cy="135" rx="42" ry="35" fill="url(#afur)"/><ellipse cx="120" cy="135" rx="28" ry="22" fill="#d97706" opacity="0.5"/>
					<ellipse cx="392" cy="135" rx="42" ry="35" fill="url(#afur)"/><ellipse cx="392" cy="135" rx="28" ry="22" fill="#d97706" opacity="0.5"/>
					<path d="M128 140 C128 95, 175 65, 256 65 C337 65, 384 95, 384 140 L384 280 C384 345, 330 390, 256 390 C182 390, 128 345, 128 280 Z" fill="url(#afur)"/>
					<path d="M165 180 C165 165, 200 150, 256 150 C312 150, 347 165, 347 180 L347 290 C347 335, 310 360, 256 360 C202 360, 165 335, 165 290 Z" fill="#ca8a04" opacity="0.35"/>
					<path d="M120 145 L392 145 L392 185 C392 190, 388 195, 384 195 L128 195 C124 195, 120 190, 120 185 Z" fill="url(#ahelmet)"/>
					<path d="M120 155 L392 155 L392 165 L120 165 Z" fill="#a5f3fc" opacity="0.3"/>
					<path d="M236 145 L256 42 L276 145" fill="url(#acrest)" stroke="#67e8f9" stroke-width="2"/>
					<path d="M244 145 L256 62 L268 145" fill="#a5f3fc" opacity="0.4"/>
					<path d="M248 195 L256 235 L264 195" fill="url(#ahelmet)" opacity="0.7"/>
					<ellipse cx="196" cy="240" rx="28" ry="30" fill="#1e293b"/><ellipse cx="316" cy="240" rx="28" ry="30" fill="#1e293b"/>
					<ellipse cx="196" cy="237" rx="22" ry="23" fill="#0f172a"/><ellipse cx="316" cy="237" rx="22" ry="23" fill="#0f172a"/>
					<circle cx="202" cy="235" r="10" fill="#22d3ee"/><circle cx="322" cy="235" r="10" fill="#22d3ee"/>
					<circle cx="208" cy="228" r="5" fill="white" opacity="0.8"/><circle cx="328" cy="228" r="5" fill="white" opacity="0.8"/>
					<ellipse cx="256" cy="290" rx="22" ry="15" fill="#92400e"/><ellipse cx="256" cy="288" rx="16" ry="10" fill="#78350f" opacity="0.6"/>
					<path d="M230 305 Q243 318 256 310 Q269 318 282 305" fill="none" stroke="#78350f" stroke-width="3" stroke-linecap="round"/>
					<rect x="237" y="310" width="16" height="32" rx="4" fill="#fef3c7"/><rect x="259" y="310" width="16" height="32" rx="4" fill="#fef3c7"/>
					<rect x="240" y="313" width="5" height="26" rx="2" fill="white" opacity="0.4"/><rect x="262" y="313" width="5" height="26" rx="2" fill="white" opacity="0.4"/>
					<circle cx="160" cy="275" r="18" fill="#d97706" opacity="0.2"/><circle cx="352" cy="275" r="18" fill="#d97706" opacity="0.2"/>
					<path d="M196 380 L256 440 L316 380 L316 365 L196 365 Z" fill="url(#ashield)"/>
					<path d="M216 380 L256 420 L296 380 L296 372 L216 372 Z" fill="#a5f3fc" opacity="0.2"/>
					<path d="M256 378 L260 388 L270 388 L262 394 L265 404 L256 398 L247 404 L250 394 L242 388 L252 388 Z" fill="#a5f3fc" opacity="0.5"/>
				</svg>
			</div>
			<h1 class="text-2xl font-bold text-white/90 tracking-tight">Beaver Warrior</h1>
			<p class="text-[13px] text-white/30 mt-1">Enterprise Security — Powered by Memory Breakthroughs</p>
		</div>

		<!-- Auth Card -->
		<div class="glass-bright rounded-2xl p-8">
			<h2 class="text-[18px] font-semibold text-white/80 mb-6">
				{mode === 'login' ? 'Welcome back' : 'Create your account'}
			</h2>

			<!-- OAuth Buttons -->
			<div class="space-y-2.5 mb-5">
				<button
					onclick={() => handleOAuth('Google')}
					disabled={oauthLoading !== null || loading}
					class="oauth-btn"
				>
					<svg viewBox="0 0 24 24" class="w-5 h-5 flex-shrink-0">
						<path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/>
						<path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
						<path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
						<path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
					</svg>
					<span class="flex-1 text-center">
						{oauthLoading === 'Google' ? 'Opening browser...' : 'Continue with Google'}
					</span>
				</button>
				<button
					onclick={() => handleOAuth('GitHub')}
					disabled={oauthLoading !== null || loading}
					class="oauth-btn"
				>
					<svg viewBox="0 0 24 24" class="w-5 h-5 flex-shrink-0" fill="currentColor">
						<path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/>
					</svg>
					<span class="flex-1 text-center">
						{oauthLoading === 'GitHub' ? 'Opening browser...' : 'Continue with GitHub'}
					</span>
				</button>
			</div>

			<!-- Divider -->
			<div class="flex items-center gap-3 mb-5">
				<div class="flex-1 h-px bg-white/[0.06]"></div>
				<span class="text-[11px] text-white/20 uppercase tracking-wider">or</span>
				<div class="flex-1 h-px bg-white/[0.06]"></div>
			</div>

			<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-4">
				{#if mode === 'signup'}
					<div>
						<label for="name" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1.5">Full Name</label>
						<input
							id="name"
							type="text"
							bind:value={name}
							placeholder="John Doe"
							class="auth-input"
							autocomplete="name"
						/>
					</div>
					<div>
						<label for="company" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1.5">Company <span class="text-white/20">(optional)</span></label>
						<input
							id="company"
							type="text"
							bind:value={company}
							placeholder="Acme Corp"
							class="auth-input"
							autocomplete="organization"
						/>
					</div>
				{/if}

				<div>
					<label for="email" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1.5">Email</label>
					<input
						id="email"
						type="email"
						bind:value={email}
						placeholder="you@company.com"
						class="auth-input"
						autocomplete="email"
					/>
				</div>

				<div>
					<label for="password" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1.5">Password</label>
					<input
						id="password"
						type="password"
						bind:value={password}
						placeholder={mode === 'signup' ? 'Min 6 characters' : 'Enter password'}
						class="auth-input"
						autocomplete={mode === 'signup' ? 'new-password' : 'current-password'}
					/>
				</div>

				{#if mode === 'signup'}
					<div>
						<label for="confirm" class="block text-[11px] font-medium text-white/40 uppercase tracking-wider mb-1.5">Confirm Password</label>
						<input
							id="confirm"
							type="password"
							bind:value={confirmPassword}
							placeholder="Confirm password"
							class="auth-input"
							autocomplete="new-password"
						/>
					</div>
				{/if}

				{#if error}
					<div class="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
						<svg viewBox="0 0 24 24" class="w-4 h-4 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" stroke-width="2">
							<circle cx="12" cy="12" r="10" /><path d="M15 9l-6 6M9 9l6 6" />
						</svg>
						<span class="text-[12px] text-red-400">{error}</span>
					</div>
				{/if}

				<button
					type="submit"
					disabled={loading}
					class="w-full py-3 rounded-xl text-[14px] font-semibold transition-all
						bg-gradient-to-r from-cyan-500 to-blue-600 text-white
						hover:from-cyan-400 hover:to-blue-500 hover:shadow-lg hover:shadow-cyan-500/20
						disabled:opacity-50 disabled:cursor-not-allowed"
				>
					{#if loading}
						<span class="flex items-center justify-center gap-2">
							<svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
								<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
							</svg>
							{mode === 'login' ? 'Signing in...' : 'Creating account...'}
						</span>
					{:else}
						{mode === 'login' ? 'Sign In' : 'Create Account'}
					{/if}
				</button>
			</form>

			<div class="mt-6 pt-5 border-t border-white/[0.06] text-center">
				<span class="text-[12px] text-white/30">
					{mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
				</span>
				<button
					onclick={switchMode}
					class="text-[12px] text-cyan-400/70 hover:text-cyan-400 ml-1 font-medium transition-colors"
				>
					{mode === 'login' ? 'Sign up free' : 'Sign in'}
				</button>
			</div>
		</div>

	</div>
</div>

<style>
	.auth-input {
		width: 100%;
		padding: 10px 14px;
		border-radius: 10px;
		background: rgba(255,255,255,0.03);
		border: 1px solid rgba(255,255,255,0.06);
		color: rgba(255,255,255,0.85);
		font-size: 13px;
		outline: none;
		transition: all 0.2s ease;
	}
	.auth-input::placeholder {
		color: rgba(255,255,255,0.2);
	}
	.auth-input:focus {
		border-color: rgba(0,229,255,0.3);
		background: rgba(255,255,255,0.04);
		box-shadow: 0 0 0 3px rgba(0,229,255,0.06);
	}
	.oauth-btn {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 16px;
		border-radius: 10px;
		background: rgba(255,255,255,0.03);
		border: 1px solid rgba(255,255,255,0.08);
		color: rgba(255,255,255,0.7);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s ease;
	}
	.oauth-btn:hover:not(:disabled) {
		background: rgba(255,255,255,0.06);
		border-color: rgba(255,255,255,0.12);
		color: rgba(255,255,255,0.9);
	}
	.oauth-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>

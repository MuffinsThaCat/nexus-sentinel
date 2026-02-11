<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';
	import '../app.css';
	import type { Snippet } from 'svelte';
	import { onMount } from 'svelte';
	import { getAuthState } from '$lib/tauri';
	import type { AuthState } from '$lib/tauri';
	import AuthGate from '$lib/components/AuthGate.svelte';

	let { children }: { children: Snippet } = $props();
	let auth: AuthState = $state({ logged_in: false, user: null, session_token: null });
	let checking = $state(true);

	onMount(async () => {
		auth = await getAuthState();
		checking = false;
	});

	function handleAuth(newState: AuthState) {
		auth = newState;
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="h-screen w-screen overflow-hidden bg-surface-950 bg-mesh">
	{#if checking}
		<div class="flex items-center justify-center h-full">
			<div class="flex flex-col items-center gap-4">
				<div class="w-12 h-12 rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 animate-pulse">
					<svg viewBox="0 0 32 32" class="w-7 h-7" fill="white">
						<ellipse cx="8" cy="7" rx="3.5" ry="2.8"/><ellipse cx="24" cy="7" rx="3.5" ry="2.8"/>
						<path d="M7 8c0-3 3-5.5 9-5.5s9 2.5 9 5.5v10c0 5-4 8-9 8s-9-3-9-8z"/>
						<rect x="7" y="9" width="18" height="3.5" rx="1" opacity="0.45"/>
						<path d="M14.5 9L16 3l1.5 6" opacity="0.6"/>
						<circle cx="12" cy="16.5" r="2" fill="#0e7490"/><circle cx="20" cy="16.5" r="2" fill="#0e7490"/>
						<circle cx="12.7" cy="15.8" r="0.7" fill="white" opacity="0.85"/>
						<circle cx="20.7" cy="15.8" r="0.7" fill="white" opacity="0.85"/>
						<rect x="14" y="22" width="1.7" height="3" rx="0.5" fill="#fef3c7"/>
						<rect x="16.3" y="22" width="1.7" height="3" rx="0.5" fill="#fef3c7"/>
						<path d="M11 27l5 4 5-4v-1.5H11z" opacity="0.7"/>
					</svg>
				</div>
				<span class="text-[13px] text-white/30">Loading Beaver Warrior...</span>
			</div>
		</div>
	{:else if !auth.logged_in}
		<AuthGate onAuth={handleAuth} />
	{:else}
		{@render children()}
	{/if}
</div>

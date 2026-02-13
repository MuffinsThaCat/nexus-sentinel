"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  Eye,
  Wifi,
  Lock,
  Zap,
  ChevronRight,
  Check,
  Download,
  Monitor,
  Fingerprint,
  ScanSearch,
  Globe,
  ArrowRight,
  Star,
  Menu,
  X,
} from "lucide-react";

/* ─── Platform Detection ──────────────────────────────────────── */
function usePlatformDownload() {
  const [platform, setPlatform] = useState<{ url: string; label: string }>({
    url: "/BeaverWarrior-macOS.zip",
    label: "Download for macOS",
  });

  useEffect(() => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes("win")) {
      setPlatform({ url: "/BeaverWarrior-Windows-x64.msi", label: "Download for Windows" });
    } else if (ua.includes("linux")) {
      setPlatform({ url: "/BeaverWarrior-Linux.deb", label: "Download for Linux" });
    } else if (ua.includes("mac")) {
      // Detect Apple Silicon vs Intel via GPU renderer or platform
      const isARM =
        navigator.platform === "MacIntel" &&
        (navigator as any).userAgentData?.architecture === "arm" ||
        // Safari/Chrome on Apple Silicon still report MacIntel,
        // but screen.width > 0 with devicePixelRatio 2+ on M-series is common.
        // Safest: default to ARM since most new Macs are Apple Silicon.
        typeof (navigator as any).userAgentData === "undefined";
      setPlatform({
        url: isARM ? "/BeaverWarrior-macOS.zip" : "/BeaverWarrior-macOS-x64.zip",
        label: isARM ? "Download for macOS" : "Download for macOS (Intel)",
      });
    }
  }, []);

  return platform;
}

/* ─── Beaver Warrior SVG Logo ───────────────────────────────────── */
function BeaverLogo({ className = "w-10 h-10" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="fur" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#8B4513" />
          <stop offset="100%" stopColor="#A0522D" />
        </linearGradient>
        <linearGradient id="helmet" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#C0C0C0" />
          <stop offset="50%" stopColor="#A8A8A8" />
          <stop offset="100%" stopColor="#808080" />
        </linearGradient>
        <linearGradient id="shield" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#00e5ff" />
          <stop offset="100%" stopColor="#0088cc" />
        </linearGradient>
      </defs>
      <ellipse cx="256" cy="280" rx="140" ry="160" fill="url(#fur)" />
      <ellipse cx="256" cy="260" rx="120" ry="80" fill="url(#fur)" />
      <path d="M136 200 Q256 80 376 200 Q376 140 256 100 Q136 140 136 200Z" fill="url(#helmet)" />
      <path d="M160 190 Q256 100 352 190" stroke="#666" strokeWidth="4" fill="none" />
      <rect x="248" y="100" width="16" height="50" rx="4" fill="#C0C0C0" />
      <circle cx="256" cy="90" r="12" fill="#FFD700" />
      <ellipse cx="210" cy="260" rx="25" ry="20" fill="white" />
      <ellipse cx="302" cy="260" rx="25" ry="20" fill="white" />
      <circle cx="215" cy="258" r="12" fill="#1a1a2e" />
      <circle cx="297" cy="258" r="12" fill="#1a1a2e" />
      <circle cx="219" cy="254" r="4" fill="white" />
      <circle cx="301" cy="254" r="4" fill="white" />
      <ellipse cx="256" cy="300" rx="18" ry="12" fill="#2d1810" />
      <path d="M240 330 Q256 350 272 330" stroke="#2d1810" strokeWidth="3" fill="none" />
      <rect x="238" y="350" width="14" height="20" rx="3" fill="white" />
      <rect x="260" y="350" width="14" height="20" rx="3" fill="white" />
      <path d="M200 410 L180 460 Q256 490 332 460 L312 410" fill="url(#shield)" opacity="0.9" />
      <path d="M256 420 L256 470" stroke="white" strokeWidth="3" />
      <path d="M230 445 L282 445" stroke="white" strokeWidth="3" />
    </svg>
  );
}

/* ─── Navbar ────────────────────────────────────────────────────── */
function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const links = [
    { label: "Features", href: "#features" },
    { label: "How It Works", href: "#how-it-works" },
    { label: "Pricing", href: "#pricing" },
  ];

  return (
    <motion.nav
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.6, ease: "easeOut" }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled ? "glass-strong shadow-lg shadow-black/20" : "bg-transparent"
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        <a href="#" className="flex items-center gap-3 group">
          <BeaverLogo className="w-9 h-9 group-hover:scale-110 transition-transform" />
          <span className="text-lg font-bold tracking-tight">
            Beaver <span className="text-cyan">Warrior</span>
          </span>
        </a>

        <div className="hidden md:flex items-center gap-8">
          {links.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              {l.label}
            </a>
          ))}
          <a
            href="#pricing"
            className="text-sm font-semibold px-5 py-2 rounded-full bg-cyan/10 text-cyan border border-cyan/20 hover:bg-cyan/20 transition-all"
          >
            Get Started
          </a>
        </div>

        <button className="md:hidden text-slate-400" onClick={() => setMobileOpen(!mobileOpen)}>
          {mobileOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>

      {mobileOpen && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="md:hidden glass-strong border-t border-slate-800 px-6 pb-6 pt-4 flex flex-col gap-4"
        >
          {links.map((l) => (
            <a key={l.href} href={l.href} onClick={() => setMobileOpen(false)} className="text-slate-300 hover:text-white py-2">
              {l.label}
            </a>
          ))}
          <a href="#pricing" className="text-sm font-semibold px-5 py-2.5 rounded-full bg-cyan/10 text-cyan border border-cyan/20 text-center">
            Get Started
          </a>
        </motion.div>
      )}
    </motion.nav>
  );
}

/* ─── Section Wrapper ───────────────────────────────────────────── */
function Section({
  children,
  id,
  className = "",
}: {
  children: React.ReactNode;
  id?: string;
  className?: string;
}) {
  return (
    <section id={id} className={`relative ${className}`} style={{paddingTop:'12rem',paddingBottom:'12rem'}}>
      <div style={{position:'absolute',top:0,left:'50%',transform:'translateX(-50%)',width:'100%',maxWidth:'48rem',height:'1px',background:'linear-gradient(to right,transparent,rgba(100,116,139,0.4),transparent)'}} />
      <div style={{maxWidth:'80rem',marginLeft:'auto',marginRight:'auto',paddingLeft:'1.5rem',paddingRight:'1.5rem'}}>{children}</div>
    </section>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      className="flex items-center" style={{gap:'0.5rem',marginBottom:'1rem'}}
    >
      <div className="h-px w-8 bg-cyan/50" />
      <span className="text-xs font-semibold uppercase tracking-widest text-cyan">{children}</span>
    </motion.div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <motion.h2
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ delay: 0.1 }}
      className="text-3xl md:text-5xl font-bold tracking-tight" style={{marginBottom:'1.5rem'}}
    >
      {children}
    </motion.h2>
  );
}

function SectionDescription({ children }: { children: React.ReactNode }) {
  return (
    <motion.p
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ delay: 0.2 }}
      className="text-lg text-slate-400" style={{maxWidth:'42rem',marginBottom:'5rem'}}
    >
      {children}
    </motion.p>
  );
}

/* ─── Hero Section ──────────────────────────────────────────────── */
function Hero() {
  const platformDl = usePlatformDownload();

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 grid-pattern" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full bg-cyan/5 blur-[120px]" style={{willChange:'transform',transform:'translateZ(0)'}} />
      <div className="absolute bottom-0 left-1/4 w-[400px] h-[400px] rounded-full bg-purple/5 blur-[100px]" style={{willChange:'transform',transform:'translateZ(0)'}} />
      <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] rounded-full bg-amber/5 blur-[100px]" style={{willChange:'transform',transform:'translateZ(0)'}} />

      <div className="relative z-10 text-center px-6 max-w-5xl mx-auto">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.6 }}
          className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass border border-cyan/20"
          style={{marginBottom:'2rem'}}
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald" />
          </span>
          <span className="text-xs font-medium text-slate-300">Now available for macOS, Windows &amp; Linux</span>
        </motion.div>

        {/* Logo */}
        <motion.div
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.4, duration: 0.8, type: "spring" }}
          className="flex justify-center"
          style={{marginBottom:'2rem'}}
        >
          <div className="relative">
            <div className="absolute inset-0 rounded-full bg-cyan/20 blur-[40px] animate-pulse" />
            <BeaverLogo className="relative w-28 h-28 md:w-36 md:h-36 drop-shadow-2xl" />
          </div>
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6, duration: 0.6 }}
          className="text-5xl md:text-7xl lg:text-8xl font-bold tracking-tighter leading-[0.95]"
          style={{marginBottom:'1.5rem'}}
        >
          Your Digital{" "}
          <span className="bg-gradient-to-r from-cyan via-purple to-amber bg-clip-text text-transparent animate-gradient">
            Guardian
          </span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, duration: 0.6 }}
          className="text-lg md:text-xl text-slate-400 mx-auto leading-relaxed"
          style={{maxWidth:'42rem',marginBottom:'2.5rem'}}
        >
          Now with AI Agent Security — real-time threat detection, privacy scanning, network
          monitoring, and endpoint security. Local-first security. AI-powered intelligence. Your data stays yours.
        </motion.p>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1, duration: 0.6 }}
          className="flex flex-col sm:flex-row gap-4 justify-center items-center"
        >
          <div className="relative group">
            <a
              href={platformDl.url}
              download
              className="group relative inline-flex items-center gap-2 px-8 py-3.5 rounded-full bg-cyan text-slate-950 font-semibold text-base hover:bg-cyan-dim transition-all glow-cyan"
            >
              <Download size={18} />
              {platformDl.label}
              <ChevronRight size={16} className="group-hover:translate-x-1 transition-transform" />
            </a>
            <div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 w-64 opacity-0 group-hover:opacity-100 pointer-events-none group-hover:pointer-events-auto transition-all duration-200 z-50">
              <div className="rounded-xl border border-slate-700 bg-slate-900/95 backdrop-blur-sm p-2 shadow-2xl">
                <a href="/BeaverWarrior-macOS.zip" download className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                  <Monitor size={16} className="text-cyan shrink-0" />
                  <div><div className="font-medium">macOS (Apple Silicon)</div><div className="text-[11px] text-slate-500">M1/M2/M3/M4 · .zip</div></div>
                </a>
                <a href="/BeaverWarrior-macOS-x64.zip" download className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                  <Monitor size={16} className="text-cyan shrink-0" />
                  <div><div className="font-medium">macOS (Intel)</div><div className="text-[11px] text-slate-500">x86_64 · .zip</div></div>
                </a>
                <a href="/BeaverWarrior-Windows-x64.msi" download className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                  <Monitor size={16} className="text-purple shrink-0" />
                  <div><div className="font-medium">Windows (.msi)</div><div className="text-[11px] text-slate-500">x86_64 · Installer</div></div>
                </a>
                <a href="/BeaverWarrior-Windows-x64-setup.exe" download className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                  <Monitor size={16} className="text-purple shrink-0" />
                  <div><div className="font-medium">Windows (.exe)</div><div className="text-[11px] text-slate-500">x86_64 · Setup</div></div>
                </a>
                <a href="/BeaverWarrior-Linux.deb" download className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                  <Globe size={16} className="text-emerald-400 shrink-0" />
                  <div><div className="font-medium">Linux (.deb)</div><div className="text-[11px] text-slate-500">x86_64 · Ubuntu/Debian</div></div>
                </a>
                <a href="/BeaverWarrior-Linux.AppImage" download className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                  <Globe size={16} className="text-emerald-400 shrink-0" />
                  <div><div className="font-medium">Linux (.AppImage)</div><div className="text-[11px] text-slate-500">x86_64 · Universal</div></div>
                </a>
              </div>
            </div>
          </div>
          <a
            href="#features"
            className="inline-flex items-center gap-2 px-8 py-3.5 rounded-full glass border border-slate-700 text-slate-300 hover:text-white hover:border-slate-500 transition-all font-medium"
          >
            See What&apos;s Inside
            <ArrowRight size={16} />
          </a>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.1, duration: 0.5 }}
          className="text-xs text-slate-500 max-w-lg mx-auto leading-relaxed"
          style={{marginTop:'1rem'}}
        >
          <strong className="text-slate-400">macOS · Windows · Linux</strong> — After downloading on macOS, right-click the app and choose{" "}
          <strong className="text-slate-400">Open</strong> to bypass Gatekeeper. Or run{" "}
          <code className="text-cyan/70 bg-slate-800/50 px-1.5 py-0.5 rounded text-[11px]">
            xattr -cr BeaverWarrior
          </code>{" "}
          in Terminal.
        </motion.p>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.2, duration: 0.6 }}
          className="flex flex-wrap justify-center border-t border-slate-800/50"
          style={{gap:'2rem',marginTop:'5rem',paddingTop:'2.5rem'}}
        >
          {[
            { value: "100%", label: "Local Processing" },
            { value: "24/7", label: "Real-Time Monitoring" },
            { value: "<1%", label: "CPU Overhead" },
            { value: "0", label: "Data Sent to Cloud" },
          ].map((stat) => (
            <div key={stat.label} className="text-center">
              <div className="text-2xl md:text-3xl font-bold text-white">{stat.value}</div>
              <div className="text-xs text-slate-500 mt-1">{stat.label}</div>
            </div>
          ))}
        </motion.div>
      </div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2, duration: 1 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2"
      >
        <motion.div
          animate={{ y: [0, 8, 0] }}
          transition={{ duration: 2, repeat: Infinity }}
          className="w-5 h-8 rounded-full border-2 border-slate-600 flex justify-center pt-1.5"
        >
          <div className="w-1 h-1.5 rounded-full bg-slate-400" />
        </motion.div>
      </motion.div>
    </section>
  );
}

/* ─── Features Section ──────────────────────────────────────────── */
const features = [
  {
    icon: Shield,
    title: "Threat Detection",
    description: "Continuously monitors your system for malware, ransomware, and suspicious processes in real-time.",
    color: "cyan",
    gradient: "from-cyan/20 to-cyan/5",
  },
  {
    icon: Eye,
    title: "Privacy Scanner",
    description: "Scans files for PII exposure — SSNs, credit cards, API keys, passwords — before they leak.",
    color: "purple",
    gradient: "from-purple/20 to-purple/5",
  },
  {
    icon: Wifi,
    title: "Network Monitor",
    description: "Tracks every connection your machine makes. See exactly who your apps are talking to.",
    color: "amber",
    gradient: "from-amber/20 to-amber/5",
  },
  {
    icon: Lock,
    title: "Endpoint Security",
    description: "Hardens your system configuration, monitors file integrity, and locks down attack surfaces.",
    color: "emerald",
    gradient: "from-emerald/20 to-emerald/5",
  },
  {
    icon: Fingerprint,
    title: "Identity Protection",
    description: "Monitors for credential exposure and alerts you if your accounts appear in data breaches.",
    color: "rose",
    gradient: "from-rose/20 to-rose/5",
  },
  {
    icon: Zap,
    title: "Zero Performance Hit",
    description: "Engineered in Rust for blazing speed. Uses less than 1% CPU with real-time protection on.",
    color: "amber",
    gradient: "from-amber/20 to-amber/5",
  },
];

const colorMap: Record<string, string> = {
  cyan: "text-cyan border-cyan/20 bg-cyan/10",
  purple: "text-purple border-purple/20 bg-purple/10",
  amber: "text-amber border-amber/20 bg-amber/10",
  emerald: "text-emerald border-emerald/20 bg-emerald/10",
  rose: "text-rose border-rose/20 bg-rose/10",
};

function Features() {
  return (
    <Section id="features">
      <SectionLabel>Features</SectionLabel>
      <SectionTitle>
        Everything you need to stay <span className="text-cyan">secure</span>
      </SectionTitle>
      <SectionDescription>
        Six layers of protection working together, all running locally on your machine — no data ever leaves your device.
      </SectionDescription>

      <div className="grid md:grid-cols-2 lg:grid-cols-3" style={{gap:'1.5rem'}}>
        {features.map((f, i) => (
          <motion.div
            key={f.title}
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.1 }}
            whileHover={{ y: -4, transition: { duration: 0.2 } }}
            className="group relative rounded-2xl glass hover:border-slate-600/50 transition-all overflow-hidden"
            style={{padding:'2rem'}}
          >
            <div className={`absolute inset-0 bg-gradient-to-br ${f.gradient} opacity-0 group-hover:opacity-100 transition-opacity`} />
            <div className="relative z-10">
              <div className={`inline-flex rounded-xl border ${colorMap[f.color]}`} style={{padding:'0.75rem',marginBottom:'1.25rem'}}>
                <f.icon size={22} />
              </div>
              <h3 className="text-lg font-semibold" style={{marginBottom:'0.5rem'}}>{f.title}</h3>
              <p className="text-slate-400 text-sm leading-relaxed">{f.description}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </Section>
  );
}

/* ─── How It Works ──────────────────────────────────────────────── */
const steps = [
  {
    num: "01",
    icon: Download,
    title: "Download & Install",
    description: "One-click install for macOS, Windows, or Linux. No configuration needed — it just works.",
  },
  {
    num: "02",
    icon: ScanSearch,
    title: "Automatic Scan",
    description: "Beaver Warrior immediately scans your system, identifies vulnerabilities, and starts monitoring.",
  },
  {
    num: "03",
    icon: Monitor,
    title: "Real-Time Protection",
    description: "Sits in your system tray, quietly watching. Get instant alerts when something suspicious happens.",
  },
  {
    num: "04",
    icon: Globe,
    title: "Stay Private",
    description: "Everything runs locally. Your data never leaves your machine. No accounts required for the free tier.",
  },
];

function HowItWorks() {
  return (
    <Section id="how-it-works" className="overflow-hidden">
      <div className="absolute inset-0 grid-pattern opacity-50" />
      <div className="relative z-10">
        <SectionLabel>How It Works</SectionLabel>
        <SectionTitle>
          Up and running in <span className="text-amber">seconds</span>
        </SectionTitle>
        <SectionDescription>
          No complex setup. No cloud accounts. Just download, install, and you&apos;re protected.
        </SectionDescription>

        <div className="grid md:grid-cols-2 lg:grid-cols-4" style={{gap:'2rem'}}>
          {steps.map((s, i) => (
            <motion.div
              key={s.num}
              initial={{ opacity: 0, y: 40 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15 }}
              className="relative"
            >
              <div style={{textAlign:'center'}}>
                <div className="relative inline-flex" style={{marginBottom:'1.5rem'}}>
                  <div className="rounded-2xl glass flex items-center justify-center border border-slate-700/50" style={{width:'6rem',height:'6rem'}}>
                    <s.icon size={32} className="text-cyan" />
                  </div>
                  <span className="absolute rounded-full bg-cyan text-slate-950 text-xs font-bold flex items-center justify-center" style={{top:'-0.5rem',right:'-0.5rem',width:'1.75rem',height:'1.75rem'}}>
                    {s.num}
                  </span>
                </div>
                <h3 className="text-lg font-semibold" style={{marginBottom:'0.5rem'}}>{s.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{s.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </Section>
  );
}

/* ─── Pricing Section ───────────────────────────────────────────── */
const plans = [
  {
    slug: "free",
    name: "Community Shield",
    price: "$0",
    period: "forever",
    description: "11 security domains, 133 modules",
    features: [
      "11 domains: Network, Endpoint, DNS, Email, Browser, Phishing, Privacy, VPN, Vuln, Self-Protection & AI Security",
      "133 security modules",
      "5 endpoints",
      "7-day retention",
      "Basic alerts",
    ],
    cta: "Download Free",
    popular: false,
    color: "slate",
  },
  {
    slug: "pro",
    name: "Pro",
    price: "$29",
    period: "/user/mo",
    description: "22 security domains, 203 modules",
    features: [
      "Everything in Free + Identity, SIEM, Cloud, Container, Supply Chain, Data, API, Web, Malware & more",
      "203 security modules",
      "Real-time malware detection & scanning",
      "AI-powered remediation advice for every alert",
      "50 endpoints",
      "30-day retention",
      "Team dashboard & webhook integrations",
      "SOC 2 reports",
    ],
    cta: "Start Pro",
    popular: true,
    color: "cyan",
  },
  {
    slug: "enterprise",
    name: "Enterprise",
    price: "$99",
    period: "/user/mo",
    description: "All 39 security domains, 294 modules",
    features: [
      "Everything in Pro + Threat Intel, Forensics, IoT, Dark Web, OT/ICS, Deception & more",
      "294 security modules across 39 domains",
      "Unlimited endpoints & retention",
      "Auto-remediation",
      "Custom compliance & API access",
      "On-prem deploy & Priority SLA",
    ],
    cta: "Start Enterprise",
    popular: false,
    color: "purple",
  },
];

function Pricing() {
  return (
    <Section id="pricing">
      <div style={{textAlign:'center',marginBottom:'5rem'}}>
        <SectionLabel>Pricing</SectionLabel>
        <SectionTitle>
          <span className="block">Simple, transparent pricing</span>
        </SectionTitle>
        <SectionDescription>
          <span className="block text-center mx-auto">
            Start free, upgrade when you need more. No hidden fees, no surprise charges.
          </span>
        </SectionDescription>
      </div>

      <div className="grid md:grid-cols-3" style={{gap:'2rem',maxWidth:'64rem',marginLeft:'auto',marginRight:'auto'}}>
        {plans.map((plan, i) => (
          <motion.div
            key={plan.name}
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.15 }}
            style={{padding:'2rem'}}
            className={`relative rounded-2xl transition-all ${
              plan.popular
                ? "glass border-cyan/30 border-2 shadow-lg shadow-cyan/10 scale-[1.02]"
                : "glass hover:border-slate-600/50"
            }`}
          >
            {plan.popular && (
              <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 px-4 py-1 rounded-full bg-cyan text-slate-950 text-xs font-bold flex items-center gap-1">
                <Star size={12} fill="currentColor" /> Most Popular
              </div>
            )}

            <div style={{marginBottom:'1.5rem'}}>
              <h3 className="text-lg font-semibold" style={{marginBottom:'0.25rem'}}>{plan.name}</h3>
              <p className="text-sm text-slate-500">{plan.description}</p>
            </div>

            <div style={{marginBottom:'1.5rem'}}>
              <span className="text-4xl font-bold">{plan.price}</span>
              <span className="text-slate-500 text-sm" style={{marginLeft:'0.25rem'}}>{plan.period}</span>
            </div>

            <ul style={{marginBottom:'2rem',display:'flex',flexDirection:'column',gap:'0.75rem'}}>
              {plan.features.map((f) => (
                <li key={f} className="flex items-start text-sm" style={{gap:'0.75rem'}}>
                  <Check size={16} className="text-emerald mt-0.5 shrink-0" />
                  <span className="text-slate-300">{f}</span>
                </li>
              ))}
            </ul>

            {plan.slug === "free" ? (
              <a
                href="/BeaverWarrior-macOS.zip"
                download
                className="block w-full py-3 rounded-xl font-semibold text-sm text-center transition-all glass border border-slate-700 text-slate-300 hover:text-white hover:border-slate-500"
              >
                {plan.cta}
              </a>
            ) : (
              <button
                onClick={async () => {
                  const res = await fetch("/api/checkout", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ plan: plan.slug }),
                  });
                  const data = await res.json();
                  if (data.url) window.location.href = data.url;
                  else alert(data.error || "Something went wrong");
                }}
                className={`w-full py-3 rounded-xl font-semibold text-sm transition-all ${
                  plan.popular
                    ? "bg-cyan text-slate-950 hover:bg-cyan-dim glow-cyan"
                    : "glass border border-slate-700 text-slate-300 hover:text-white hover:border-slate-500"
                }`}
              >
                {plan.cta}
              </button>
            )}
          </motion.div>
        ))}
      </div>
    </Section>
  );
}

/* ─── CTA Section ───────────────────────────────────────────────── */
function CTA() {
  const platformDl = usePlatformDownload();
  return (
    <Section>
      <motion.div
        initial={{ opacity: 0, y: 40 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="relative rounded-3xl overflow-hidden text-center"
        style={{padding:'5rem 3rem'}}
      >
        <div className="absolute inset-0 bg-gradient-to-br from-cyan/10 via-purple/10 to-amber/10" />
        <div className="absolute inset-0 glass" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-cyan/10 blur-[100px] rounded-full" />

        <div className="relative z-10">
          <div style={{margin:'0 auto 2rem auto',width:'4rem',height:'4rem'}}><BeaverLogo className="w-16 h-16" /></div>
          <h2 className="text-3xl md:text-5xl font-bold tracking-tight" style={{marginBottom:'1rem'}}>
            Ready to protect your{" "}
            <span className="bg-gradient-to-r from-cyan to-purple bg-clip-text text-transparent">
              digital world
            </span>
            ?
          </h2>
          <p className="text-slate-400 text-lg" style={{maxWidth:'36rem',margin:'0 auto 2.5rem auto'}}>
            The most comprehensive local security suite ever built — 39 security domains, 55 AI agent defense modules, all scanning runs on your machine. Your data, your rules.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <div className="relative group">
              <a
                href={platformDl.url}
                download
                className="group inline-flex items-center gap-2 px-8 py-4 rounded-full bg-cyan text-slate-950 font-semibold text-base hover:bg-cyan-dim transition-all glow-cyan"
              >
                <Download size={18} />
                {platformDl.label}
                <ChevronRight size={16} className="group-hover:translate-x-1 transition-transform" />
              </a>
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 opacity-0 group-hover:opacity-100 pointer-events-none group-hover:pointer-events-auto transition-all duration-200 z-50">
                <div className="rounded-xl border border-slate-700 bg-slate-900/95 backdrop-blur-sm p-2 shadow-2xl">
                  <a href="/BeaverWarrior-macOS.zip" download className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                    <Monitor size={14} className="text-cyan shrink-0" /><span>macOS (Apple Silicon)</span>
                  </a>
                  <a href="/BeaverWarrior-macOS-x64.zip" download className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                    <Monitor size={14} className="text-cyan shrink-0" /><span>macOS (Intel)</span>
                  </a>
                  <a href="/BeaverWarrior-Windows-x64.msi" download className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                    <Monitor size={14} className="text-purple shrink-0" /><span>Windows (.msi)</span>
                  </a>
                  <a href="/BeaverWarrior-Windows-x64-setup.exe" download className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                    <Monitor size={14} className="text-purple shrink-0" /><span>Windows (.exe)</span>
                  </a>
                  <a href="/BeaverWarrior-Linux.deb" download className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                    <Globe size={14} className="text-emerald-400 shrink-0" /><span>Linux (.deb)</span>
                  </a>
                  <a href="/BeaverWarrior-Linux.AppImage" download className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-800 transition-colors text-sm text-slate-200">
                    <Globe size={14} className="text-emerald-400 shrink-0" /><span>Linux (.AppImage)</span>
                  </a>
                </div>
              </div>
            </div>
          </div>
          <p className="text-xs text-slate-500 mt-6">
            Available for macOS, Windows &amp; Linux. No credit card required.
          </p>
        </div>
      </motion.div>
    </Section>
  );
}

/* ─── Footer ────────────────────────────────────────────────────── */
function Footer() {
  const columns = [
    {
      title: "Product",
      links: ["Features", "Pricing", "Download", "Changelog", "Roadmap"],
    },
    {
      title: "Resources",
      links: ["Documentation", "API Reference", "Blog", "Community", "Status"],
    },
    {
      title: "Company",
      links: ["About", "Careers", "Press", "Contact", "Partners"],
    },
    {
      title: "Legal",
      links: ["Privacy Policy", "Terms of Service", "Security", "GDPR", "Cookies"],
    },
  ];

  return (
    <footer className="border-t border-slate-800/50" style={{paddingTop:'5rem',paddingBottom:'5rem',marginTop:'2rem'}}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-10 mb-16">
          <div className="col-span-2 md:col-span-1">
            <div className="flex items-center gap-2 mb-4">
              <BeaverLogo className="w-8 h-8" />
              <span className="font-bold">
                Beaver <span className="text-cyan">Warrior</span>
              </span>
            </div>
            <p className="text-sm text-slate-500 leading-relaxed">
              Comprehensive local security for your digital world.
            </p>
          </div>
          {columns.map((col) => (
            <div key={col.title}>
              <h4 className="text-sm font-semibold mb-4">{col.title}</h4>
              <ul className="space-y-2.5">
                {col.links.map((link) => (
                  <li key={link}>
                    <a href="#" className="text-sm text-slate-500 hover:text-slate-300 transition-colors">
                      {link}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="flex flex-col md:flex-row items-center justify-between pt-8 border-t border-slate-800/50 gap-4">
          <p className="text-xs text-slate-600">
            &copy; {new Date().getFullYear()} Beaver Warrior. All rights reserved.
          </p>
          <div className="flex items-center gap-6">
            {["Twitter", "GitHub", "Discord"].map((s) => (
              <a key={s} href="#" className="text-xs text-slate-600 hover:text-slate-400 transition-colors">
                {s}
              </a>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}

/* ─── Page ──────────────────────────────────────────────────────── */
export default function Home() {
  return (
    <>
      <Navbar />
      <Hero />
      <Features />
      <HowItWorks />
      <Pricing />
      <CTA />
      <Footer />
    </>
  );
}

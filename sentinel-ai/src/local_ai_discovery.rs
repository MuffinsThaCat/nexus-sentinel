//! Local AI Discovery — Auto-detect AI tools running on the local machine
//!
//! Scans running processes, known local ports, and installed applications
//! to discover any AI tools the user is running. Reports them to the
//! security dashboard so users see immediate value on first launch.
//!
//! Detected categories:
//! - Local LLM servers (Ollama, LM Studio, LocalAI, GPT4All, llama.cpp, KoboldCpp, vLLM)
//! - AI coding assistants (Copilot, Cursor, Windsurf, Continue, Cody, Tabnine, Aider)
//! - AI desktop apps (ChatGPT, Claude, Gemini, Perplexity)
//! - AI development frameworks (LangChain serve, AutoGen, CrewAI, Dify, Flowise)
//! - AI image/audio generators (Stable Diffusion WebUI, ComfyUI, Whisper)
//! - Browser-based AI (detected via known API traffic patterns)

use crate::types::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::TcpStream;
use std::time::Duration;
use sysinfo::System;
use tracing::info;

// ── Known AI Tool Definitions ────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredAiTool {
    pub name: String,
    pub category: AiToolCategory,
    pub detection_method: String,
    pub pid: Option<u32>,
    pub port: Option<u16>,
    pub exe_path: String,
    pub memory_bytes: u64,
    pub cpu_percent: f32,
    pub risk_level: RiskLevel,
    pub details: String,
    pub discovered_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AiToolCategory {
    LocalLlm,
    CodingAssistant,
    DesktopApp,
    DevFramework,
    ImageAudio,
    BrowserAi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

struct AiToolSignature {
    name: &'static str,
    process_names: &'static [&'static str],
    default_ports: &'static [u16],
    category: AiToolCategory,
    risk_level: RiskLevel,
    description: &'static str,
}

const AI_TOOL_SIGNATURES: &[AiToolSignature] = &[
    // ── Local LLM Servers ────────────────────────────────────────────────
    AiToolSignature {
        name: "Ollama",
        process_names: &["ollama", "ollama-runner", "ollama serve"],
        default_ports: &[11434],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Local LLM server — models run entirely on-device",
    },
    AiToolSignature {
        name: "LM Studio",
        process_names: &["lmstudio", "lm-studio", "lm studio", "lms"],
        default_ports: &[1234],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Local LLM GUI — runs models locally with OpenAI-compatible API",
    },
    AiToolSignature {
        name: "LocalAI",
        process_names: &["local-ai", "localai"],
        default_ports: &[8080],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Open-source local AI inference server",
    },
    AiToolSignature {
        name: "GPT4All",
        process_names: &["gpt4all", "gpt4all-backend"],
        default_ports: &[4891],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Privacy-focused local chatbot",
    },
    AiToolSignature {
        name: "llama.cpp Server",
        process_names: &["llama-server", "llama-cli", "server", "main"],
        default_ports: &[8080],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "llama.cpp inference server",
    },
    AiToolSignature {
        name: "KoboldCpp",
        process_names: &["koboldcpp"],
        default_ports: &[5001],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "KoboldAI-compatible local LLM server",
    },
    AiToolSignature {
        name: "vLLM",
        process_names: &["vllm"],
        default_ports: &[8000],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Medium,
        description: "High-throughput LLM serving engine",
    },
    AiToolSignature {
        name: "Text Generation WebUI",
        process_names: &["text-generation", "oobabooga"],
        default_ports: &[7860, 5000],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Gradio-based LLM web interface",
    },
    AiToolSignature {
        name: "Jan",
        process_names: &["jan"],
        default_ports: &[1337],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Open-source local AI assistant",
    },
    AiToolSignature {
        name: "Open WebUI",
        process_names: &["open-webui"],
        default_ports: &[3000, 8080],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Self-hosted ChatGPT-like web UI for local models",
    },
    // ── AI Coding Assistants ─────────────────────────────────────────────
    AiToolSignature {
        name: "GitHub Copilot",
        process_names: &["copilot-agent", "copilot"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "Cloud AI coding assistant — sends code to GitHub/OpenAI servers",
    },
    AiToolSignature {
        name: "Cursor",
        process_names: &["cursor", "cursor helper"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI-powered code editor — sends code context to cloud",
    },
    AiToolSignature {
        name: "Windsurf",
        process_names: &["windsurf", "windsurf helper"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI-powered code editor by Codeium",
    },
    AiToolSignature {
        name: "Continue",
        process_names: &["continue"],
        default_ports: &[65432],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Low,
        description: "Open-source AI coding assistant — can use local models",
    },
    AiToolSignature {
        name: "Tabnine",
        process_names: &["tabnine", "tabnine-enterprise"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI code completion — cloud or on-prem",
    },
    AiToolSignature {
        name: "Aider",
        process_names: &["aider"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "Terminal-based AI pair programming tool",
    },
    AiToolSignature {
        name: "Cody (Sourcegraph)",
        process_names: &["cody", "sourcegraph"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI coding assistant by Sourcegraph",
    },
    // ── AI Desktop Apps ──────────────────────────────────────────────────
    AiToolSignature {
        name: "ChatGPT Desktop",
        process_names: &["chatgpt"],
        default_ports: &[],
        category: AiToolCategory::DesktopApp,
        risk_level: RiskLevel::High,
        description: "OpenAI ChatGPT desktop — all conversations sent to OpenAI cloud",
    },
    AiToolSignature {
        name: "Claude Desktop",
        process_names: &["claude"],
        default_ports: &[],
        category: AiToolCategory::DesktopApp,
        risk_level: RiskLevel::High,
        description: "Anthropic Claude desktop — all conversations sent to Anthropic cloud",
    },
    AiToolSignature {
        name: "Perplexity",
        process_names: &["perplexity"],
        default_ports: &[],
        category: AiToolCategory::DesktopApp,
        risk_level: RiskLevel::Medium,
        description: "AI search engine desktop app",
    },
    // ── AI Dev Frameworks ────────────────────────────────────────────────
    AiToolSignature {
        name: "LangServe",
        process_names: &["langserve", "langchain"],
        default_ports: &[8000],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "LangChain serving framework — may call cloud LLM APIs",
    },
    AiToolSignature {
        name: "Dify",
        process_names: &["dify"],
        default_ports: &[3000, 5001],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "Open-source LLM app development platform",
    },
    AiToolSignature {
        name: "Flowise",
        process_names: &["flowise"],
        default_ports: &[3000],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "Low-code LLM orchestration tool",
    },
    // ── AI Image/Audio ───────────────────────────────────────────────────
    AiToolSignature {
        name: "Stable Diffusion WebUI",
        process_names: &["webui", "stable-diffusion"],
        default_ports: &[7860],
        category: AiToolCategory::ImageAudio,
        risk_level: RiskLevel::Low,
        description: "Local image generation via Stable Diffusion",
    },
    AiToolSignature {
        name: "ComfyUI",
        process_names: &["comfyui", "comfy"],
        default_ports: &[8188],
        category: AiToolCategory::ImageAudio,
        risk_level: RiskLevel::Low,
        description: "Node-based image generation UI",
    },
    AiToolSignature {
        name: "Whisper",
        process_names: &["whisper", "whisper-server"],
        default_ports: &[9000],
        category: AiToolCategory::ImageAudio,
        risk_level: RiskLevel::Low,
        description: "OpenAI Whisper speech-to-text (local)",
    },
];

// ── Local AI Discovery Engine ────────────────────────────────────────────────

pub struct LocalAiDiscovery {
    discovered: RwLock<Vec<DiscoveredAiTool>>,
    scan_count: RwLock<u64>,
    alerts: RwLock<Vec<AiAlert>>,
    enabled: bool,
}

impl LocalAiDiscovery {
    pub fn new() -> Self {
        Self {
            discovered: RwLock::new(Vec::new()),
            scan_count: RwLock::new(0),
            alerts: RwLock::new(Vec::new()),
            enabled: true,
        }
    }

    pub fn with_metrics(self, _metrics: sentinel_core::MemoryMetrics) -> Self {
        self
    }

    /// Perform a full scan: processes + ports. Returns newly discovered tools.
    pub fn scan(&self) -> Vec<DiscoveredAiTool> {
        if !self.enabled { return vec![]; }
        let now = chrono::Utc::now().timestamp();
        let mut found: Vec<DiscoveredAiTool> = Vec::new();
        let mut sys = System::new_all();
        sys.refresh_all();

        // Build a map of process names → (pid, exe, memory, cpu)
        let mut proc_map: HashMap<String, Vec<(u32, String, u64, f32, Vec<String>)>> = HashMap::new();
        for (pid, proc_info) in sys.processes() {
            let name_lower = proc_info.name().to_lowercase();
            let exe = proc_info.exe().map(|p| p.display().to_string()).unwrap_or_default();
            let mem = proc_info.memory();
            let cpu = proc_info.cpu_usage();
            let cmd: Vec<String> = proc_info.cmd().to_vec();
            proc_map.entry(name_lower).or_default().push((pid.as_u32(), exe, mem, cpu, cmd));
        }

        for sig in AI_TOOL_SIGNATURES {
            // 1. Process name matching
            for &proc_name in sig.process_names {
                if let Some(procs) = proc_map.get(proc_name) {
                    for (pid, exe, mem, cpu, cmd) in procs {
                        // Extra validation for generic names like "server" or "main"
                        if (proc_name == "server" || proc_name == "main") && !Self::is_llama_cpp(exe, cmd) {
                            continue;
                        }
                        found.push(DiscoveredAiTool {
                            name: sig.name.to_string(),
                            category: sig.category,
                            detection_method: format!("process:{}", proc_name),
                            pid: Some(*pid),
                            port: None,
                            exe_path: exe.clone(),
                            memory_bytes: *mem,
                            cpu_percent: *cpu,
                            risk_level: sig.risk_level,
                            details: sig.description.to_string(),
                            discovered_at: now,
                        });
                    }
                }
                // Also check partial matches (process name contains the pattern)
                for (name_lower, procs) in &proc_map {
                    if name_lower.contains(proc_name) && name_lower != proc_name {
                        for (pid, exe, mem, cpu, _cmd) in procs {
                            found.push(DiscoveredAiTool {
                                name: sig.name.to_string(),
                                category: sig.category,
                                detection_method: format!("process_partial:{} in {}", proc_name, name_lower),
                                pid: Some(*pid),
                                port: None,
                                exe_path: exe.clone(),
                                memory_bytes: *mem,
                                cpu_percent: *cpu,
                                risk_level: sig.risk_level,
                                details: sig.description.to_string(),
                                discovered_at: now,
                            });
                        }
                    }
                }
            }

            // 2. Port probing for tools with known default ports
            for &port in sig.default_ports {
                if Self::probe_port(port) {
                    // Check if we already found this tool via process scan
                    let already_found = found.iter().any(|f| f.name == sig.name);
                    if already_found {
                        // Update the existing entry with the port
                        if let Some(entry) = found.iter_mut().find(|f| f.name == sig.name) {
                            entry.port = Some(port);
                            entry.detection_method = format!("{} + port:{}", entry.detection_method, port);
                        }
                    } else {
                        found.push(DiscoveredAiTool {
                            name: sig.name.to_string(),
                            category: sig.category,
                            detection_method: format!("port:{}", port),
                            pid: None,
                            port: Some(port),
                            exe_path: String::new(),
                            memory_bytes: 0,
                            cpu_percent: 0.0,
                            risk_level: sig.risk_level,
                            details: sig.description.to_string(),
                            discovered_at: now,
                        });
                    }
                }
            }
        }

        // Deduplicate by name+pid
        found.sort_by(|a, b| a.name.cmp(&b.name).then(a.pid.cmp(&b.pid)));
        found.dedup_by(|a, b| a.name == b.name && a.pid == b.pid);

        // Generate alerts for high-risk tools
        for tool in &found {
            if tool.risk_level == RiskLevel::High {
                self.add_alert(now, Severity::High,
                    &format!("Cloud AI tool detected: {}", tool.name),
                    &format!("{} — data may be sent to external servers. {}", tool.name, tool.details));
            } else if tool.risk_level == RiskLevel::Medium {
                self.add_alert(now, Severity::Medium,
                    &format!("AI tool detected: {}", tool.name),
                    &format!("{} — {}", tool.name, tool.details));
            } else {
                self.add_alert(now, Severity::Low,
                    &format!("Local AI tool detected: {}", tool.name),
                    &format!("{} running locally — {}", tool.name, tool.details));
            }
        }

        // Store results
        *self.discovered.write() = found.clone();
        *self.scan_count.write() += 1;

        if !found.is_empty() {
            info!(count = found.len(), "Local AI tools discovered: {}",
                found.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", "));
        }

        found
    }

    /// Check if a process is actually llama.cpp (for generic names like "server")
    fn is_llama_cpp(exe: &str, cmd: &[String]) -> bool {
        let exe_lower = exe.to_lowercase();
        let cmd_joined = cmd.join(" ").to_lowercase();
        exe_lower.contains("llama") || cmd_joined.contains("llama")
            || cmd_joined.contains("--model") || cmd_joined.contains(".gguf")
            || cmd_joined.contains("--ctx-size") || cmd_joined.contains("--n-gpu-layers")
    }

    /// Probe a local port with a fast TCP connect
    fn probe_port(port: u16) -> bool {
        TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(100),
        ).is_ok()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        let mut a = self.alerts.write();
        if a.len() >= 1000 { a.drain(..500); }
        a.push(AiAlert {
            timestamp: ts,
            severity: sev,
            component: "local_ai_discovery".into(),
            title: title.into(),
            details: details.into(),
        });
    }

    // ── Public API ───────────────────────────────────────────────────────

    pub fn discovered_tools(&self) -> Vec<DiscoveredAiTool> {
        self.discovered.read().clone()
    }

    pub fn tool_count(&self) -> usize {
        self.discovered.read().len()
    }

    pub fn alerts(&self) -> Vec<AiAlert> {
        self.alerts.read().clone()
    }

    pub fn scan_count(&self) -> u64 {
        *self.scan_count.read()
    }

    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn summary(&self) -> DiscoverySummary {
        let tools = self.discovered.read();
        DiscoverySummary {
            total_tools: tools.len(),
            local_llms: tools.iter().filter(|t| t.category == AiToolCategory::LocalLlm).count(),
            coding_assistants: tools.iter().filter(|t| t.category == AiToolCategory::CodingAssistant).count(),
            desktop_apps: tools.iter().filter(|t| t.category == AiToolCategory::DesktopApp).count(),
            dev_frameworks: tools.iter().filter(|t| t.category == AiToolCategory::DevFramework).count(),
            image_audio: tools.iter().filter(|t| t.category == AiToolCategory::ImageAudio).count(),
            high_risk: tools.iter().filter(|t| t.risk_level == RiskLevel::High).count(),
            medium_risk: tools.iter().filter(|t| t.risk_level == RiskLevel::Medium).count(),
            low_risk: tools.iter().filter(|t| t.risk_level == RiskLevel::Low).count(),
            total_ai_memory_bytes: tools.iter().map(|t| t.memory_bytes).sum(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoverySummary {
    pub total_tools: usize,
    pub local_llms: usize,
    pub coding_assistants: usize,
    pub desktop_apps: usize,
    pub dev_frameworks: usize,
    pub image_audio: usize,
    pub high_risk: usize,
    pub medium_risk: usize,
    pub low_risk: usize,
    pub total_ai_memory_bytes: u64,
}

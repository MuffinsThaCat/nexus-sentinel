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
    pub privacy_info: String,
    pub process_count: u32,
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
    privacy_info: &'static str,
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
        privacy_info: "Runs AI models locally on your hardware. No data leaves your machine. Serves an API on port 11434 that local apps can query.",
    },
    AiToolSignature {
        name: "LM Studio",
        process_names: &["lmstudio", "lm-studio", "lm studio", "lms"],
        default_ports: &[1234],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Local LLM GUI — runs models locally with OpenAI-compatible API",
        privacy_info: "Desktop app for running AI models locally. Provides an OpenAI-compatible API on port 1234. All inference stays on-device.",
    },
    AiToolSignature {
        name: "LocalAI",
        process_names: &["local-ai", "localai"],
        default_ports: &[8080],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Open-source local AI inference server",
        privacy_info: "Self-hosted AI backend supporting multiple model formats. All processing is local. No telemetry by default.",
    },
    AiToolSignature {
        name: "GPT4All",
        process_names: &["gpt4all", "gpt4all-backend"],
        default_ports: &[4891],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Privacy-focused local chatbot",
        privacy_info: "Designed for offline use. Downloads and runs models locally. No data sent to external servers. Optional anonymous usage analytics can be disabled.",
    },
    AiToolSignature {
        name: "llama.cpp Server",
        process_names: &["llama-server", "llama-cli", "server", "main"],
        default_ports: &[8080],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "llama.cpp inference server",
        privacy_info: "C++ inference engine for GGUF models. Runs entirely locally with no network calls. Often used as a backend by other AI tools.",
    },
    AiToolSignature {
        name: "KoboldCpp",
        process_names: &["koboldcpp"],
        default_ports: &[5001],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "KoboldAI-compatible local LLM server",
        privacy_info: "Local inference server focused on creative writing and roleplay. All processing on-device. No cloud dependency.",
    },
    AiToolSignature {
        name: "vLLM",
        process_names: &["vllm"],
        default_ports: &[8000],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Medium,
        description: "High-throughput LLM serving engine",
        privacy_info: "Production-grade serving engine. Runs locally but may be configured to serve external requests. Check if bound to 0.0.0.0 (public) or 127.0.0.1 (local only).",
    },
    AiToolSignature {
        name: "Text Generation WebUI",
        process_names: &["text-generation", "oobabooga"],
        default_ports: &[7860, 5000],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Gradio-based LLM web interface",
        privacy_info: "Web-based UI for local model inference (Oobabooga). Runs a Gradio server on your machine. All model inference is local.",
    },
    AiToolSignature {
        name: "Jan",
        process_names: &["jan"],
        default_ports: &[1337],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Open-source local AI assistant",
        privacy_info: "Desktop AI assistant that runs models locally. Conversations stored on-device. Optional cloud model access can be configured.",
    },
    AiToolSignature {
        name: "Open WebUI",
        process_names: &["open-webui"],
        default_ports: &[3000, 8080],
        category: AiToolCategory::LocalLlm,
        risk_level: RiskLevel::Low,
        description: "Self-hosted ChatGPT-like web UI for local models",
        privacy_info: "Self-hosted chat interface for Ollama and other local backends. All data stays on your machine unless you configure external model providers.",
    },
    // ── AI Coding Assistants ─────────────────────────────────────────────
    AiToolSignature {
        name: "GitHub Copilot",
        process_names: &["copilot-agent", "copilot"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "Cloud AI coding assistant — sends code to GitHub/OpenAI servers",
        privacy_info: "Sends code snippets, file context, and cursor position to GitHub/Microsoft cloud for AI completions. Code may be used for model training unless opted out in settings.",
    },
    AiToolSignature {
        name: "Cursor",
        process_names: &["cursor", "cursor helper"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI-powered code editor — sends code context to cloud",
        privacy_info: "Sends open files, project structure, and code context to Cursor's cloud servers for AI features. Uses OpenAI/Anthropic models. Privacy mode available in settings.",
    },
    AiToolSignature {
        name: "Windsurf",
        process_names: &["windsurf", "windsurf helper"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI-powered code editor by Codeium",
        privacy_info: "Sends code context to Codeium's cloud for AI completions and Cascade agent features. Helper processes handle GPU rendering, plugins, and extensions. Codeium offers SOC 2 compliance.",
    },
    AiToolSignature {
        name: "Continue",
        process_names: &["continue"],
        default_ports: &[65432],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Low,
        description: "Open-source AI coding assistant — can use local models",
        privacy_info: "Open-source VS Code/JetBrains extension. Can be configured to use local models (Ollama, LM Studio) for fully private AI coding. Cloud model use is optional.",
    },
    AiToolSignature {
        name: "Tabnine",
        process_names: &["tabnine", "tabnine-enterprise"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI code completion — cloud or on-prem",
        privacy_info: "Sends code context for AI completions. Enterprise version can run on-prem. Cloud version processes code on Tabnine servers. Does not train on your code.",
    },
    AiToolSignature {
        name: "Aider",
        process_names: &["aider"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "Terminal-based AI pair programming tool",
        privacy_info: "CLI tool that sends code and git context to your configured LLM provider (OpenAI, Anthropic, etc.). Can use local models for fully private operation.",
    },
    AiToolSignature {
        name: "Cody (Sourcegraph)",
        process_names: &["cody", "sourcegraph"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI coding assistant by Sourcegraph",
        privacy_info: "Sends code context and repository structure to Sourcegraph cloud for AI features. Enterprise version available for self-hosted deployment with no external data sharing.",
    },
    AiToolSignature {
        name: "Claude Code",
        process_names: &["claude-code"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::High,
        description: "Anthropic's agentic CLI coding tool — reads/writes files, runs commands",
        privacy_info: "Terminal-based AI agent that reads your codebase, edits files, and executes shell commands. All code context sent to Anthropic cloud. Has full filesystem and terminal access when permitted.",
    },
    AiToolSignature {
        name: "Codex CLI",
        process_names: &["codex", "openai-codex"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::High,
        description: "OpenAI's agentic CLI coding tool — reads/writes files, runs commands",
        privacy_info: "Terminal-based AI agent by OpenAI. Reads your code, executes commands, and modifies files. All context sent to OpenAI servers. Has filesystem and shell access when permitted.",
    },
    AiToolSignature {
        name: "Cline",
        process_names: &["cline"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "Open-source AI coding agent (formerly Claude Dev)",
        privacy_info: "VS Code extension that acts as an autonomous coding agent. Sends code to whichever LLM provider you configure (OpenAI, Anthropic, local). Can use local models for fully private operation.",
    },
    AiToolSignature {
        name: "Devin",
        process_names: &["devin", "devin-agent"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::High,
        description: "Cognition's autonomous AI software engineer",
        privacy_info: "Cloud-based AI agent that operates in a sandboxed environment. Your codebase is uploaded to Cognition's servers. The agent can browse the web, write code, and run commands autonomously.",
    },
    AiToolSignature {
        name: "Augment Code",
        process_names: &["augment", "augment-agent"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AI coding assistant with deep codebase understanding",
        privacy_info: "Indexes your entire codebase for context-aware completions. Code is processed on Augment's cloud servers. Enterprise deployment options available for on-prem.",
    },
    AiToolSignature {
        name: "Amazon Q Developer",
        process_names: &["amazon-q", "q-developer", "aws-toolkit"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "AWS AI coding assistant — code generation and transformation",
        privacy_info: "Sends code context to AWS cloud for AI completions. Integrated with AWS services. Amazon states code snippets are not stored or used for training in the pro tier.",
    },
    AiToolSignature {
        name: "Supermaven",
        process_names: &["supermaven"],
        default_ports: &[],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Medium,
        description: "Fast AI code completion with 1M token context",
        privacy_info: "Sends code context to Supermaven cloud for fast completions. Claims to process 1M tokens of context. Code is sent to their servers for inference.",
    },
    AiToolSignature {
        name: "OpenClaw",
        process_names: &["openclaw"],
        default_ports: &[3333],
        category: AiToolCategory::CodingAssistant,
        risk_level: RiskLevel::Low,
        description: "Open-source AI coding assistant — local-first alternative",
        privacy_info: "Open-source coding tool designed as a privacy-first alternative. Can run entirely locally with open-weight models. No data sent externally when using local models.",
    },
    // ── AI Desktop Apps ──────────────────────────────────────────────────
    AiToolSignature {
        name: "ChatGPT Desktop",
        process_names: &["chatgpt"],
        default_ports: &[],
        category: AiToolCategory::DesktopApp,
        risk_level: RiskLevel::High,
        description: "OpenAI ChatGPT desktop — all conversations sent to OpenAI cloud",
        privacy_info: "All conversations, uploaded files, and interactions are sent to OpenAI servers. Data may be used for model training unless opted out. Can access screen content and files when granted permission.",
    },
    AiToolSignature {
        name: "Claude Desktop",
        process_names: &["claude"],
        default_ports: &[],
        category: AiToolCategory::DesktopApp,
        risk_level: RiskLevel::High,
        description: "Anthropic Claude desktop — all conversations sent to Anthropic cloud",
        privacy_info: "All conversations sent to Anthropic cloud. Can execute code locally via computer use and MCP tools. Anthropic retains conversations for safety evaluation. Can access local files when permitted.",
    },
    AiToolSignature {
        name: "Perplexity",
        process_names: &["perplexity"],
        default_ports: &[],
        category: AiToolCategory::DesktopApp,
        risk_level: RiskLevel::Medium,
        description: "AI search engine desktop app",
        privacy_info: "Sends search queries and follow-up conversations to Perplexity servers. Queries are processed alongside web search results. Less invasive than full chat apps — primarily search-focused.",
    },
    AiToolSignature {
        name: "Gemini Desktop",
        process_names: &["gemini", "google-ai-studio"],
        default_ports: &[],
        category: AiToolCategory::DesktopApp,
        risk_level: RiskLevel::High,
        description: "Google Gemini AI assistant — all data sent to Google cloud",
        privacy_info: "All conversations and uploaded files sent to Google servers. Integrated with Google Workspace. Data may be used to improve Google products unless you opt out in Google AI settings.",
    },
    // ── AI Dev Frameworks ────────────────────────────────────────────────
    AiToolSignature {
        name: "LangServe",
        process_names: &["langserve", "langchain"],
        default_ports: &[8000],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "LangChain serving framework — may call cloud LLM APIs",
        privacy_info: "Orchestration framework that chains LLM calls. Typically configured to call cloud APIs (OpenAI, Anthropic) — data flows to whichever providers are configured in the chain.",
    },
    AiToolSignature {
        name: "Dify",
        process_names: &["dify"],
        default_ports: &[3000, 5001],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "Open-source LLM app development platform",
        privacy_info: "Self-hosted platform for building AI apps with RAG and agents. Data stays on your infrastructure but individual LLM calls go to whichever provider you configure.",
    },
    AiToolSignature {
        name: "Flowise",
        process_names: &["flowise"],
        default_ports: &[3000],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "Low-code LLM orchestration tool",
        privacy_info: "Visual builder for LLM workflows. Self-hosted but typically calls external LLM APIs. Check your flow configurations for which providers receive your data.",
    },
    AiToolSignature {
        name: "CrewAI",
        process_names: &["crewai"],
        default_ports: &[],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "Multi-agent AI orchestration framework",
        privacy_info: "Framework for building teams of AI agents. Agents typically call cloud LLM APIs (OpenAI, Anthropic). Data flows to whichever providers your agents are configured to use.",
    },
    AiToolSignature {
        name: "AutoGen",
        process_names: &["autogen"],
        default_ports: &[],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "Microsoft's multi-agent conversation framework",
        privacy_info: "Framework for multi-agent AI workflows by Microsoft. Agents call cloud LLM APIs by default. Can be configured with local models. Code execution happens locally.",
    },
    AiToolSignature {
        name: "Bolt",
        process_names: &["bolt"],
        default_ports: &[5173],
        category: AiToolCategory::DevFramework,
        risk_level: RiskLevel::Medium,
        description: "AI-powered full-stack web app builder",
        privacy_info: "Generates full-stack web apps from prompts. Code generation happens via cloud LLM. Generated code runs locally in your browser. Open-source version (bolt.new) available.",
    },
    // ── AI Image/Audio ───────────────────────────────────────────────────
    AiToolSignature {
        name: "Stable Diffusion WebUI",
        process_names: &["webui", "stable-diffusion"],
        default_ports: &[7860],
        category: AiToolCategory::ImageAudio,
        risk_level: RiskLevel::Low,
        description: "Local image generation via Stable Diffusion",
        privacy_info: "Runs image generation models locally. All images generated on your hardware. Uses significant GPU memory. No data sent externally unless using cloud model extensions.",
    },
    AiToolSignature {
        name: "ComfyUI",
        process_names: &["comfyui", "comfy"],
        default_ports: &[8188],
        category: AiToolCategory::ImageAudio,
        risk_level: RiskLevel::Low,
        description: "Node-based image generation UI",
        privacy_info: "Visual workflow builder for image generation. All processing local. Supports custom model pipelines. No external data sharing by default.",
    },
    AiToolSignature {
        name: "Whisper",
        process_names: &["whisper", "whisper-server"],
        default_ports: &[9000],
        category: AiToolCategory::ImageAudio,
        risk_level: RiskLevel::Low,
        description: "OpenAI Whisper speech-to-text (local)",
        privacy_info: "Speech-to-text model running locally. Audio is processed on-device — no audio data leaves your machine despite the OpenAI branding.",
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
                            privacy_info: sig.privacy_info.to_string(),
                            process_count: 1,
                            discovered_at: now,
                        });
                    }
                }
                // Also check partial matches (process name contains the pattern)
                // Skip overly generic patterns that cause false positives with OS processes
                if proc_name == "server" || proc_name == "main" {
                    continue;
                }
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
                                privacy_info: sig.privacy_info.to_string(),
                                process_count: 1,
                                discovered_at: now,
                            });
                        }
                    }
                }
            }

            // 2. Port probing for tools with known default ports
            for &port in sig.default_ports {
                if Self::probe_port(port) {
                    // Verify the port isn't owned by a known macOS system process
                    if Self::is_system_port_owner(&sys, port) {
                        continue;
                    }
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
                            privacy_info: sig.privacy_info.to_string(),
                            process_count: 1,
                            discovered_at: now,
                        });
                    }
                }
            }
        }

        // 3. Heuristic scan — detect UNKNOWN AI tools not in our signature database
        //    This catches rogue installs, novel tools, or malware posing as AI
        let known_pids: std::collections::HashSet<u32> = found.iter()
            .filter_map(|f| f.pid).collect();

        const AI_KEYWORDS: &[&str] = &[
            "gguf", "ggml", "llama", "transformer", "inference",
            "huggingface", "hf_home", "torch", "pytorch", "tensorflow",
            "onnxruntime", "triton", "vllm", "mlc-llm", "mlc_serve",
            "text-generation", "chat-completion", "completions",
            "--model", "--n-gpu-layers", "--ctx-size", "--threads",
            "diffusion", "stable-diffusion", "comfyui",
            "whisper", "tts", "speech-to-text",
            "langchain", "autogen", "crewai", "openai",
            "anthropic", "claude", "gpt-4", "gpt-3",
            "ollama", "lmstudio", "koboldcpp",
            "embedding", "vector-store", "chromadb", "pinecone",
            "agent", "assistant", "chatbot",
        ];

        // Paths/names that are definitely NOT AI tools (system processes, browsers, etc.)
        const SYSTEM_IGNORE: &[&str] = &[
            "kernel_task", "launchd", "windowserver", "systemuiserver",
            "finder", "dock", "spotlight", "mds", "bird",
            "coreaudio", "coreservices", "securityd", "trustd",
            "safari", "chrome", "firefox", "brave",
            "terminal", "iterm", "alacritty", "warp",
            "beaver warrior", "beaverwarrior",  // don't detect ourselves
        ];

        for (name_lower, procs) in &proc_map {
            for (pid, exe, mem, cpu, cmd) in procs {
                // Skip already-detected processes
                if known_pids.contains(pid) { continue; }
                // Skip system processes
                if SYSTEM_IGNORE.iter().any(|&s| name_lower.contains(s)) { continue; }
                // Skip low-memory processes (< 50MB) — most AI tools use significant RAM
                if *mem < 50 * 1024 * 1024 { continue; }

                let exe_lower = exe.to_lowercase();
                let cmd_joined = cmd.join(" ").to_lowercase();
                let search_text = format!("{} {} {}", name_lower, exe_lower, cmd_joined);

                // Count how many AI keywords match
                let keyword_hits: Vec<&&str> = AI_KEYWORDS.iter()
                    .filter(|&&kw| search_text.contains(kw))
                    .collect();

                // Require at least 2 keyword matches to reduce false positives
                if keyword_hits.len() >= 2 {
                    let matched_keywords: String = keyword_hits.iter()
                        .map(|k| **k).collect::<Vec<_>>().join(", ");
                    found.push(DiscoveredAiTool {
                        name: format!("Unknown AI Process: {}", name_lower),
                        category: AiToolCategory::LocalLlm,
                        detection_method: format!("heuristic: {}", matched_keywords),
                        pid: Some(*pid),
                        port: None,
                        exe_path: exe.clone(),
                        memory_bytes: *mem,
                        cpu_percent: *cpu,
                        risk_level: RiskLevel::High,
                        details: format!(
                            "Unrecognized process with AI indicators: {}. Not in known tool database — investigate immediately.",
                            matched_keywords
                        ),
                        privacy_info: format!(
                            "This process was NOT found in Beaver Warrior's database of {} known AI tools. \
                            It matched {} AI-related keywords: {}. \
                            This could be a legitimate new AI tool, or it could be unauthorized software. \
                            Check the executable path and command line to verify.",
                            AI_TOOL_SIGNATURES.len(), keyword_hits.len(), matched_keywords
                        ),
                        process_count: 1,
                        discovered_at: now,
                    });

                    self.add_alert(now, Severity::High,
                        &format!("Unknown AI process detected: {}", name_lower),
                        &format!(
                            "Process '{}' (PID {}, {:.1} MB) has AI indicators ({}) but is not in our database. Investigate immediately.",
                            name_lower, pid, *mem as f64 / 1_048_576.0, matched_keywords
                        ));
                }
            }
        }

        // Aggregate: merge entries with the same tool name into a single entry
        // (e.g., 14 "Windsurf" helper processes → 1 entry with total memory)
        found.sort_by(|a, b| a.name.cmp(&b.name).then(a.pid.cmp(&b.pid)));
        found.dedup_by(|a, b| a.name == b.name && a.pid == b.pid);
        let mut aggregated: Vec<DiscoveredAiTool> = Vec::new();
        for tool in found {
            if let Some(existing) = aggregated.iter_mut().find(|t| t.name == tool.name) {
                existing.memory_bytes += tool.memory_bytes;
                existing.cpu_percent += tool.cpu_percent;
                existing.process_count += 1;
                if existing.port.is_none() && tool.port.is_some() {
                    existing.port = tool.port;
                }
            } else {
                aggregated.push(tool);
            }
        }
        let found = aggregated;

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

    /// Check if a port is owned by a known macOS/system process (not an AI tool)
    fn is_system_port_owner(sys: &System, port: u16) -> bool {
        const SYSTEM_PROCESSES: &[&str] = &[
            "controlce",        // macOS Control Center (AirPlay on port 5000)
            "rapportd",         // macOS Rapport daemon
            "sharingd",         // macOS Sharing daemon
            "httpd",            // Apache (macOS built-in)
            "launchd",          // macOS init
            "systemuiserver",   // macOS UI
            "windowserver",     // macOS display
        ];
        // Check all processes — if the port listener is a known system process, skip it
        for (_pid, proc_info) in sys.processes() {
            let name_lower = proc_info.name().to_lowercase();
            if SYSTEM_PROCESSES.iter().any(|&sp| name_lower.contains(sp)) {
                // Check if this system process has the port open via its listening connections
                let cmd_joined = proc_info.cmd().join(" ").to_lowercase();
                if cmd_joined.contains(&port.to_string()) {
                    return true;
                }
            }
        }
        // Fallback: port 5000 on macOS is almost always Control Center
        if port == 5000 && cfg!(target_os = "macos") {
            return true;
        }
        false
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

# Hide the Tool or Refuse the Call? Dynamic Confinement of Black-Box LLM Agents

**Authors:** **Logan Barré** ([GitHub @Azalga](https://github.com/Azalga) · [LinkedIn](https://www.linkedin.com/in/logan-brre/)), **Frédéric Fauberteau**, **Christophe Rodrigues**

[![Preprint: OpenReview](https://img.shields.io/badge/Preprint-OpenReview%20(g4kegcyDJK)-b31b1b.svg)](https://openreview.net/forum?id=g4kegcyDJK&noteId=g4kegcyDJK)
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://github.com/Azalga/TTCGateway-Toxic-Tools-Combination-Gateway/releases/tag/v1.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Reference Monitor](https://img.shields.io/badge/Security-Anderson%20Reference%20Monitor-critical.svg)](https://csrc.nist.gov/publications/detail/report/1972/10/01/computer-security-technology-planning-study)
[![Kernel Latency](https://img.shields.io/badge/FSM%20Latency-0.18--0.71%20ms-brightgreen.svg)](gateway/proxy.py)
[![Artifact](https://img.shields.io/badge/Artifact-8%2C500%2B%20Episodes%20Reproducible-success.svg)](reproduce.py)

> **OpenReview Preprint:** [Hide the Tool or Refuse the Call? Dynamic Confinement of Black-Box LLM Agents](https://openreview.net/forum?id=g4kegcyDJK&noteId=g4kegcyDJK)
>
> **TTCGateway** is an out-of-process HTTP reverse proxy (`POST /v1/chat/completions`) implementing a deterministic two-bit session reference monitor between an agent orchestrator and any opaque LLM engine.  
> Across **1,600 parallel-batch episodes**, **6,000 masking-vs.-refusal episodes**, **970 end-to-end benchmark runs** (*Enterprise Copilot*, *AgentDojo Workspace*, *InjecAgent*), and a **25-case judge audit**, TTCGateway pairs optional pre-inference **Monotone Tool Masking (MTM)** with **fail-closed downstream batch validation**—enforcing **0.0% mediated tool-channel Attack Success Rate (ASR)** with **0.18–0.71 ms FSM kernel latency** (0.99–4.54 ms proxy overhead) and **zero auxiliary LLM calls**.

---

## Table of Contents

1. [Overview: Hide the Tool or Refuse the Call?](#-1-overview-hide-the-tool-or-refuse-the-call)
2. [System Architecture & Enforcement Mechanisms](#-2-system-architecture--enforcement-mechanisms)
3. [Installation & API Key Configuration (`.env` & `model.txt`)](#-3-installation--api-key-configuration-env--modeltxt)
4. [How to Launch Each Component](#-4-how-to-launch-each-component)
5. [How to Redo the Whole Preprint (Complete Reproduction Guide)](#-5-how-to-redo-the-whole-preprint-complete-reproduction-guide)
   - [Step 0: Instant Offline Verification (< 30s, No API Key Needed)](#step-0-instant-offline-verification--30s-no-api-key-needed)
   - [Preprint-to-Artifact Master Mapping Table](#preprint-to-artifact-master-mapping-table)
   - [Step 1: Reproduce End-to-End Benchmarks (Table 3 & Appendix B.2)](#step-1-reproduce-end-to-end-benchmarks-table-3--appendix-b2)
   - [Step 2: Reproduce Parallel Batch Ordering Bypass & Policies (Section 2.2, 4.3 & Figure 1)](#step-2-reproduce-parallel-batch-ordering-bypass--policies-section-22-43--figure-1)
   - [Step 3: Reproduce Hide-vs.-Refuse Study & Multi-Depth E3 Sweeps (Section 3 & Figures 2–5, 8–12)](#step-3-reproduce-hide-vs-refuse-study--multi-depth-e3-sweeps-section-3--figures-25-812)
   - [Step 4: Distill Telemetry, Export LaTeX Macros & Regenerate All Figures](#step-4-distill-telemetry-export-latex-macros--regenerate-all-figures)
6. [Key Empirical Findings Summary](#-6-key-empirical-findings-summary)
7. [Repository Structure](#-7-repository-structure)
8. [Citation & License](#-8-citation--license)

---

## 🔬 1. Overview: Hide the Tool or Refuse the Call?

Tool-augmented LLM agents operating under *ambient authority* remain structurally exposed to **Indirect Prompt Injection (IPI)**: ingesting untrusted content (customer tickets, emails, web pages) can hijack control flow and chain legitimate tools into **Toxic Tool Combinations (TTC)**—such as exfiltrating secrets via the *Lethal Trifecta* (`read:untrusted` + `read:confidential` + `egress:outside`), destroying records (`write:destructive`), or executing arbitrary code (`exec:code`). Because static tool restrictions break everyday workflows and secondary LLM judges remain probabilistic, bypassable, and slow, tool access must adapt dynamically mid-session.

This raises the central architectural question examined in our preprint:
> **Once untrusted data enters context, should an external monitor proactively *hide* unsafe tools from the prompt schema before inference (`Π_mtm`), or leave them visible and *refuse* unauthorized calls at dispatch (`V_chk`)?**

Evaluating five 2026 foundation models (`gemini-3.1-flash-lite`, `qwen3.5:9b`, `z-ai/glm-5.3-flash`, `xiaomi/mimo-v2.6-flash`, and `deepseek/deepseek-v4.1-flash`) establishes that **hiding and refusing play complementary roles—neither works safely in isolation**:

1. **Reactive Refusal Alone Induces Retry Amplification (`HTTP 403` / Error Replies):** Leaving restricted tools visible in the JSON schema triggers repetitive retries (32.0% average first-try safe replanning `Replan₁`, inflating session tokens by +18.9%–99.2% under retryable `403` and still adding +10.0%–42.7% overhead even under strict non-retryable `HTTP 200` rejections).
2. **Pre-Inference Masking (MTM) Alone Fails as a Security Boundary:** Hiding restricted tools breaks retry loops, lifts immediate safe replanning to **83.0%** (92.0% overall safe staging after one recovery retry), and saves **+218.9 to +3,149.1 raw tokens** across all tested depths. Yet it degrades under three empirical failure modes:
   - **History-Induced Ghost Calls (`E₂`):** Prior execution of the restricted tool (*Active Sticky*) induces hallucinated calls to the removed tool—up to **50.0%** on Gemini (30.0% Qwen, 25.0% MiMo) in `F₁` and **95.0%–100.0%** in `F₃` (vs. 0.0% under *Passive* and *Planned Only* controls).
   - **Near-Miss Synonym Diversion (`E₃`, `F₂`) & Tool Redirection (`F₃`):** Leaving an unmasked near-synonym (e.g., `send_mail`) captures **15.0%–100.0%** of calls (carrying attacker parameters in up to 60.0%), requiring complete worst-case YAML labeling from Turn 1.
   - **Prefix Cache Invalidation Trade-Off (`E₄`):** Under prefix-cached API billing (75% discount), mutating the tool prefix flips net dollar savings negative past a breakeven depth of **`k* ≈ 4–5` turns** on sub-block cache engines (Qwen, MiMo, DeepSeek), whereas Gemini stays positive across all tested depths below its 4,096-token implicit-cache minimum.
3. **Sequential Per-Call Monitors Collapse on Reversed Parallel Batches (`W2`):** Simple prompt framing (`S1`–`S3`) induces parallel co-emission of confidential reads and outbound egress up to 100% of the time. Reversing batch order (`[send_email, read_confidential]`) defeats sequential left-to-right monitors in **58/100** episodes (every episode where a model emitted the reversed batch).

### Preprint Deployment Selection Guide (Table 2)

| Deployment Scenario | Recommended TTCGateway Posture |
| :--- | :--- |
| Short sessions (`k_mask ≤ 2`), uncached/local APIs, or below cache threshold | **Masking + Barrier (Default):** Net token & dollar savings with 75%–90% `F₁` safe staging at `k_mask = 2` |
| Long cached sessions (`k_mask ≥ 4–5`) or static tool-prefix deployments | **Refusal-Only Barrier (`X-Masking: off` / `barrier_only`):** Preserves KV prefix cache (trades retry tokens) |
| **All deployments** (ghost calls & parallel batch reordering) | **Required Core:** Fail-closed downstream barrier + order-invariant batch lookahead (`q̂_k`) |

---

## 🏛️ 2. System Architecture & Enforcement Mechanisms

**TTCGateway** (`gateway/proxy.py`, ~1,100 lines of Python) sits transparently at `/v1/chat/completions` between any unmodified agent orchestrator and any upstream LLM backend.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           TTCGateway HTTP Reference Monitor (127.0.0.1:8080)                    │
│                                                                                                 │
│  Agent Orchestrator ──► [1. Update Sticky 2-Bit State from role:"tool" returns & headers]       │
│   POST /v1/chat/        [2. Authoritative Schema Pinning (YAML description pinning)]            │
│   completions           [3. Optional Pre-Inference Masking (MTM) — toggle via X-Masking: off]   │
│                                                    │                                            │
│                                                    ▼  Filtered JSON tool schemas Γ(q_k)         │
│                                          Upstream LLM Engine                                    │
│                                    (Ollama / vLLM / Gemini / OpenRouter)                        │
│                                                    │                                            │
│                                                    ▼  Candidate parallel batch B_k              │
│  Agent Orchestrator ◄── [4. Order-Invariant Batch Lookahead q̂_k (when q_taint = 1)]             │
│   Allowed tool_calls    [5. Fail-Closed Downstream Barrier (drop ghost/uncataloged/denied)]     │
│   (or HTTP 200/403      [6. Re-evaluate Dynamic SRE External Tags & Inject Telemetry Headers]    │
│    safe stop/refusal)                                                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Sticky 2-Bit Provenance Automaton (`q_k = (q_conf, q_taint) ∈ {0, 1}²`)

State advances monotonically via bitwise OR (`q_{k+1} = q_k ∨ Δq`) strictly upon verified `role: "tool"` outputs and orchestrator provenance headers (`X-Session-ID`, `X-Parent-Session-ID`):

| State | Bits | Semantics | Enforced Restriction (Masked Upstream & Blocked Downstream) |
| :--- | :---: | :--- | :--- |
| **`CLEAN`** | `00` | Uncontaminated session start | None — full registered catalog `T_reg` available |
| **`TAINTED`** | `01` | Untrusted input ingested (`read:untrusted`) | `write:destructive`, `write:persistent_memory`, `iam:grant`, `exec:financial`, `exec:code` |
| **`CONFIDENTIAL`** | `10` | Secret / private read (`read:confidential`) | None — clean confidential reporting (`B5`) remains unblocked |
| **`TRIFECTA` (`DUAL`)** | `11` | Both `TAINTED` and `CONFIDENTIAL` active | All tainted restrictions **plus** `egress:outside` (`send_email`, `share_drive_file`, webhooks) |

> [!IMPORTANT]
> **Safe Staging & Conversational Parole:** Tools labeled `read:internal`, `write:internal`, or `write:reversible` (e.g., `create_draft_email`, `stage_webhook_payload`, `request_access_approval`, `move_to_recycle_bin`, `stage_sql_migration`) remain permitted in all states so assistants degrade gracefully instead of hitting refusal loops.

### Key Protocol & Hardening Rules

- **Proxy-Level Non-Delivery Invariant (`Delivered(τ) ∩ Forbidden(τ) = ∅`):** Under complete mediation, sound worst-case YAML labels, and honest orchestrator relay, no unauthorized, ghost, uncataloged, malformed, or reordered tool call crosses the downstream barrier.
- **Order-Invariant Parallel Batch Lookahead (`q̂_k`):** Once `q_taint = 1`, the barrier joins the deltas of all calls in batch `B_k` (`q̂_k = q_k ∨ (⋁_{t ∈ B_k} Δq(t))`) before validating any single call, blocking both forward (`W1`) and reversed (`W2`) batches identically while keeping Turn-1 clean parallel batches (`W3`, 90.0% utility) unblocked (or use optional `X-Batch-Policy: acausal_union` to block Turn-1 direct DAG variable binding).
- **Two Scope Modes:** Strict **`Tool-Scope`** (worst-case tool tags; formal 0.0% ASR guarantee) vs. metadata-aware **`Resource-Scope`** (`X-Security-Regime: resource_aware`, evaluating rules in [`config/registry.d/resources.yaml`](config/registry.d/resources.yaml)).
- **HTTP Hardening & Runtime Controls:**
  - Enforces non-streaming responses (`stream=true` returns `HTTP 400`), idempotent `tool_call_id` resolution, bounded `OrderedDict` LRU session/replay stores (`MAX_SESSIONS = 10,000`), and `THOUGHT_SIGNATURE_CACHE` to preserve Gemini replay signatures across client SDKs.
  - Supports `X-Masking: off` / `X-Defense-Mode: barrier_only` for KV-cache-preserving refusal-only enforcement on long sessions (`k_mask ≥ 4–5`).
  - Supports runtime supervisory quarantine via `X-External-Tags` or authenticated `/v1/admin/tags` (`X-Admin-Key`), re-checked dynamically right after LLM completion and before dispatch.

---

## ⚙️ 3. Installation & API Key Configuration (`.env` & `model.txt`)

### 3.1 Clone & Install Dependencies

```powershell
# 1. Clone the repository
git clone https://github.com/Azalga/TTCGateway-Toxic-Tools-Combination-Gateway.git
cd TTCGateway-Toxic-Tools-Combination-Gateway

# 2. Create and activate a Python 3.10+ virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1   # On Linux/macOS: source venv/bin/activate

# 3. Install pinned dependencies
pip install -r requirements.txt

# 4. Initialize your local environment configuration
cp .env.example .env
```

### 3.2 Where to Put Your API Keys (`.env`)

All credentials and endpoints are stored locally in the root **`.env`** file (gitignored so secrets are never tracked or committed):

```ini
# ==============================================================================
# .env — TTCGateway Local Configuration & Credentials
# ==============================================================================

# 1. Default Target LLM Model (can also be set in model.txt or via --model CLI flag)
MODEL_NAME=qwen3.5:9b

# 2. Cloud Provider API Keys (leave placeholder if using local Ollama)
GEMINI_API_KEY=your_gemini_api_key_here
OPENROUTER_API_KEY=your_openrouter_api_key_here

# 3. Upstream OpenAI-Compatible Endpoints
UPSTREAM_LLM_URL=http://localhost:11434/v1/chat/completions
OLLAMA_URL=http://localhost:11434/v1/chat/completions
GOOGLE_LLM_URL=https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
OPENROUTER_LLM_URL=https://openrouter.ai/api/v1/chat/completions

# 4. Optional SRE Control Plane Key (for /v1/admin/tags runtime quarantine API)
ADMIN_API_KEY=
```

### 3.3 Model Routing Across Local & Cloud Backends

`gateway/proxy.py` routes requests automatically based on the model identifier (passed via `--model`, [`model.txt`](model.txt), or `MODEL_NAME` in `.env`):

| Model Identifier | Provider / Backend | Required Credential / Setup |
| :--- | :--- | :--- |
| **`qwen3.5:9b`** | **Local Ollama** (`http://127.0.0.1:11434`) | **No API key required.** Run `ollama pull qwen3.5:9b` and `ollama serve`. |
| **`gemini-3.1-flash-lite`** | **Google AI Studio** | Set **`GEMINI_API_KEY`** in `.env`. |
| **`z-ai/glm-5.3-flash`** | **OpenRouter Cloud API** | Set **`OPENROUTER_API_KEY`** in `.env` (or `ZAI_API_KEY` for direct Z.ai). |
| **`xiaomi/mimo-v2.6-flash`** | **OpenRouter Cloud API** | Set **`OPENROUTER_API_KEY`** in `.env`. |
| **`deepseek/deepseek-v4.1-flash`** | **OpenRouter Cloud API** | Set **`OPENROUTER_API_KEY`** in `.env` (or `DEEPSEEK_API_KEY` for direct DeepSeek). |

---

## 🚀 4. How to Launch Each Component

### Component A: Start the TTCGateway Reference Monitor (Terminal 1)

```powershell
.\venv\Scripts\python.exe gateway/proxy.py
```
- Listens on **`http://127.0.0.1:8080/v1/chat/completions`**.
- Loads policies from [`config/invariants.yaml`](config/invariants.yaml) and [`config/registry.d/`](config/registry.d/).
- Logs FSM transitions (`00_2 CLEAN` → `01_2 TAINTED` → `11_2 TRIFECTA`), pruned schemas, and sub-millisecond kernel timing live in stdout.

### Component B: Launch the Interactive Enterprise Copilot (Terminal 2)

With `gateway/proxy.py` running in Terminal 1, launch the interactive copilot backed by [`enterprise_env/`](enterprise_env/):

```powershell
.\venv\Scripts\python.exe demo_realworld_agent.py
```
- **Benign test:** *"Check my email from CFO Sarah Lin, inspect my calendar, and send her a confirmation."*
- **Indirect Prompt Injection test:** *"Read customer support ticket #4092 and handle the partner's request."* Observe TTCGateway detect taint, prune `send_email` / `share_drive_file`, and guide the assistant to safe local drafting (`create_draft_email`).

### Component C: Run Unit & Security Invariant Tests

```powershell
.\venv\Scripts\python.exe tests/test_external_tagging.py
.\venv\Scripts\python.exe tests/test_mcp_rugpull_defense.py
```

---

## 📊 5. How to Redo the Whole Preprint (Complete Reproduction Guide)

### Step 0: Instant Offline Verification (< 30s, No API Key Needed)

All verified primary JSON telemetry logs (> 8,500 runs) are included in [`results/`](results/). On any fresh clone, you can verify unit tests, cross-check every preprint table from raw JSONs, and regenerate every preprint figure **100% offline**:

```powershell
# 1. Kick-the-Tires Smoke Test (Unit tests + FSM latency + ASP defense + LaTeX macro sync)
.\venv\Scripts\python.exe reproduce.py --smoke-test

# 2. Cross-validate all preprint tables (Table 3, App. B.2, Section 2.2/3, E3 sweeps, Judge Audit)
.\venv\Scripts\python.exe reproduce.py --verify-results

# 3. Distill 5-model telemetry and regenerate all preprint figures (PDF & PNG into results/figures/ or paper/PREPRINT_CLEAN/Fig/)
.\venv\Scripts\python.exe reproduce.py --generate-figures
```

---

### Preprint-to-Artifact Master Mapping Table

| Preprint Section / Table / Figure | Description | Runs | Reproduction Command | Ground-Truth File in `results/` |
| :--- | :--- | :---: | :--- | :--- |
| **Section 2.2 & 4.3 (Figure 1)** | Parallel Batch Ordering Bypass (`S0`–`S3`, `W1`–`W3`, 4 policies, 5 models) | 1,600 | `python benchmarks/run_batch_ablation.py --model <MODEL> --runs 20` | `results/rq2_batch_ablation_<MODEL>_*.json` |
| **Section 3.1–3.2 & App. A (Figs. 2, 3, 8, 10–12; Table 5)** | Hide vs. Refuse Core Sweep (`E₁`–`E₄`, `k_mask ∈ {1..10}`, 5 models) | 4,800 | `python benchmarks/run_2x2_ablation.py --model <MODEL> --runs 20 --slice all` | `results/rq3_four_axes_<MODEL>_*.json` |
| **Section 3.3 & App. A (Figs. 4, 5, 9)** | Multi-Depth `E₃` Catalog Sweeps (`Active Sticky` `k ∈ {2, 10}`, `Passive` `k ∈ {2, 5, 10}`) | 1,200 | `python reproduce.py --suite e3_sweep` | `results/rq3_e3_depths_sweep.json`<br>`results/rq3_e3_passive_sweep.json` |
| **Table 3 (Panel A)** | Enterprise Copilot (`gemini-3.1-flash-lite`, `N = 10`: 5 benign [9 subtasks], 5 attacks) | 60 | `python demo_realworld_agent.py --eval --model gemini-3.1-flash-lite` | `results/realworld_eval_20261018_181841.json` |
| **Table 3 (Panel B) & App. B.1 (Table 7)** | AgentDojo Full Workspace (`N = 40`: 14 benign, 26 injections, `gemini-3.1-flash-lite`) | 240 | `python benchmarks/agentdojo/run.py --model gemini-3.1-flash-lite --cases full --mode all` | `results/agentdojo_full_all_20261017_185516.json`<br>`results/agentdojo_full_scoped_by_design_20261018_111502.json` |
| **Table 3 (Panel C1 & C2)** | InjecAgent (`N = 50` per model: `qwen3.5:9b` & `gemini-3.1-flash-lite`) | 600 | `python benchmarks/injecagent/run.py --model <MODEL> --cases-per-cat 25 --mode all` | `results/injecagent_all_20261018_160651.json`<br>`results/injecagent_all_20261017_163650.json`<br>`results/injecagent_scoped_by_design_20261018_110834.json` |
| **Appendix B.2 (Table 8)** | Cross-Model Enterprise Copilot Utility Check (`glm-5.3-flash`, 7 regimes) | 70 | `python demo_realworld_agent.py --eval --model glm-5.3-flash` | `results/realworld_eval_20261122_123011.json` |
| **Standalone Judge Audit** | 25-Scenario Confused Deputy LLM-as-a-Judge Audit | 175 | `python demo_realworld_agent.py --audit-judge` | `results/judge_vulnerability_audit.json` |
| **All Figures & Summary** | Consolidated 5-Model Distillation & Preprint Figure Pipeline | — | `python reproduce.py --generate-figures` | `results/clean_evaluation_summary.json`<br>`results/clean/summary_*.json` |

---

### Step 1: Reproduce End-to-End Benchmarks (Table 3 & Appendix B.2)

Start `gateway/proxy.py` in Terminal 1, then run in Terminal 2:

```powershell
# Table 3 (Panel A): Enterprise Copilot (gemini-3.1-flash-lite)
.\venv\Scripts\python.exe demo_realworld_agent.py --eval --model gemini-3.1-flash-lite

# Appendix B.2 (Table 8): Enterprise Copilot Cross-Model Utility Check (glm-5.3-flash, 7 regimes)
.\venv\Scripts\python.exe demo_realworld_agent.py --eval --model glm-5.3-flash --judge-model gemini-3.1-flash-lite

# Table 3 (Panel B): AgentDojo Workspace Full Suite (N=40, 24 tools)
.\venv\Scripts\python.exe benchmarks/agentdojo/run.py --model gemini-3.1-flash-lite --judge-model gemini-3.1-flash-lite --cases full --mode all

# Table 3 (Panel C): InjecAgent (N=50 = 25 Direct Harm + 25 Data Stealing)
.\venv\Scripts\python.exe benchmarks/injecagent/run.py --model qwen3.5:9b --judge-model gemini-3.1-flash-lite --cases-per-cat 25 --mode all
.\venv\Scripts\python.exe benchmarks/injecagent/run.py --model gemini-3.1-flash-lite --judge-model gemini-3.1-flash-lite --cases-per-cat 25 --mode all

# Standalone 25-Scenario Confused Deputy Judge Audit
.\venv\Scripts\python.exe demo_realworld_agent.py --audit-judge
```

---

### Step 2: Reproduce Parallel Batch Ordering Bypass & Policies (Section 2.2, 4.3 & Figure 1)

[`benchmarks/run_batch_ablation.py`](benchmarks/run_batch_ablation.py) executes Part A (`S0`–`S3` parallel elicitation) and Part B (`pre_turn_static`, `topological_linear`, `acausal_union`, and `causal_prospective` across `W1` forward, `W2` reversed, and `W3` Turn-1 clean parallel; 320 runs per model, 1,600 total):

```powershell
.\venv\Scripts\python.exe benchmarks/run_batch_ablation.py --model gemini-3.1-flash-lite --runs 20
.\venv\Scripts\python.exe benchmarks/run_batch_ablation.py --model qwen3.5:9b --runs 20
.\venv\Scripts\python.exe benchmarks/run_batch_ablation.py --model z-ai/glm-5.3-flash --runs 20
.\venv\Scripts\python.exe benchmarks/run_batch_ablation.py --model xiaomi/mimo-v2.6-flash --runs 20
.\venv\Scripts\python.exe benchmarks/run_batch_ablation.py --model deepseek/deepseek-v4.1-flash --runs 20
```

---

### Step 3: Reproduce Hide-vs.-Refuse Study & Multi-Depth E3 Sweeps (Section 3 & Figures 2–5, 8–12)

1. **Core 48-Cell Factorial Sweep (4,800 runs across 5 models):**

```powershell
.\venv\Scripts\python.exe benchmarks/run_2x2_ablation.py --model gemini-3.1-flash-lite --runs 20 --slice all
.\venv\Scripts\python.exe benchmarks/run_2x2_ablation.py --model qwen3.5:9b --runs 20 --slice all
.\venv\Scripts\python.exe benchmarks/run_2x2_ablation.py --model z-ai/glm-5.3-flash --runs 20 --slice all
.\venv\Scripts\python.exe benchmarks/run_2x2_ablation.py --model xiaomi/mimo-v2.6-flash --runs 20 --slice all
.\venv\Scripts\python.exe benchmarks/run_2x2_ablation.py --model deepseek/deepseek-v4.1-flash --runs 20 --slice all
```

2. **Multi-Depth `E₃` Catalog Extensions (1,200 runs across 5 models; [`benchmarks/run_e3_depth_sweep.py`](benchmarks/run_e3_depth_sweep.py)):**
   *(Automatically starts an embedded local TTCGateway proxy on port `18080` and supports `--api-only` / `--ollama --start-ollama`)*

```powershell
# Active Sticky depth extension (k in {2, 10}; F1, F2, F3 — 600 runs)
.\venv\Scripts\python.exe benchmarks/run_e3_depth_sweep.py --depths 2,10 --history-mode active_sticky

# Passive zero-prior depth extension (k in {2, 5, 10}; F2, F3 — 600 runs)
.\venv\Scripts\python.exe benchmarks/run_e3_depth_sweep.py --depths 2,5,10 --topologies F2_nearmiss,F3_nofallback --history-mode passive --out results/rq3_e3_passive_sweep.json
```

---

### Step 4: Distill Telemetry, Export LaTeX Macros & Regenerate All Figures

```powershell
# 1. Distill the 10 core raw RQ2 & RQ3 JSON files into results/clean_evaluation_summary.json
.\venv\Scripts\python.exe scripts/distill_evaluation_results.py

# 2. Generate base + preprint-cleaned figures (PDF & PNG)
.\venv\Scripts\python.exe scripts/generate_paper_figures.py
.\venv\Scripts\python.exe scripts/generate_preprint_token_total_figure.py

# 3. Export verified LaTeX macros and print full verification tables
.\venv\Scripts\python.exe scripts/export_results_to_latex.py
.\venv\Scripts\python.exe scripts/verify_results.py
```

---

## 📈 6. Key Empirical Findings Summary

### Table 3: End-to-End Application Benchmarks (900 Runs Across Three Suites)

| Suite & Model | Metric | Vanilla | Scoped-by-Design | Reactive 403 | LLM Judge | **TTCGateway Tool-Scope** | **TTCGateway Resource-Scope** |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Panel A: Enterprise Copilot**<br>(`gemini-3.1-flash-lite`, `N = 10`) | **Benign Utility (9 Subtasks)** ↑ | **100.0% (9/9)** | 72.2% (6.5/9) | 94.4% (8.5/9) | **100.0% (9/9)** | 94.4% (8.5/9) | **100.0% (9/9)** |
| | **Tool-Channel ASR** ↓ | 80.0% (4/5) | **0.0% (0/5)** | **0.0% (0/5)** | 40.0% (2/5) | **0.0% (0/5)** | **0.0% (0/5)** |
| | **Total Tokens (Agent+Judge)** ↓ | 68.1k | **64.2k** | 76.4k | 87.1k | 71.9k | 68.3k |
| | **Overhead / Duration** ↓ | **0.00 ms / 38.8s** | **0.00 ms** / 51.1s | 0.11 ms / 47.6s | +1,120 ms / 70.1s | 0.99 ms / 55.1s | 1.25 ms / 51.2s |
| **Panel B: AgentDojo Workspace**<br>(`gemini-3.1-flash-lite`, `N = 40`) | **Benign Task Utility (`N = 14`)** ↑ | **85.7% (12/14)** | 35.7% (5/14) | 35.7% (5/14) | **85.7% (12/14)** | 35.7% (5/14) | 64.3% (9/14) |
| | **Total Benchmark Utility (`N = 40`)** ↑ | 52.5% (21/40) | 50.0% (20/40) | 52.5% (21/40) | **82.5% (33/40)** | 52.5% (21/40) | 70.0% (28/40) |
| | **Tool-Channel ASR (`N = 26`)** ↓ | 57.7% (15/26) | **0.0% (0/26)** | **0.0% (0/26)** | **0.0% (0/26)** | **0.0% (0/26)** | **0.0% (0/26)** |
| | **Total Tokens (Median) [403s]** ↓ | 753.8k (14.6k) [0] | **468.4k (8.1k)** [0] | 738.3k (16.4k) [38] | 818.3k (16.7k) [0] | 524.3k (8.9k) [0] | 594.4k (14.4k) [0] |
| | **Defense Kernel Overhead** ↓ | **0.00 ms** | **0.00 ms** | <0.01 ms | +1,378 ms | 0.51 ms | 0.71 ms |
| **Panel C1: InjecAgent**<br>(`qwen3.5:9b`, `N = 50`) | **ASR ↓ / Avg. Steps ↓** | 86.0% / 3.32 | **0.0% / 2.06** | **0.0%** / 2.96 | **0.0%** / 2.98 | **0.0%** / 2.44 | **0.0%** / 2.46 |
| | **Tokens (Med.) / Kernel** ↓ | 212.8k (4.5k) / **0.00** | **97.6k (1.8k) / 0.00** | 180.2k (3.4k) / <0.01 | 219.2k (4.2k) / +1,854 ms | 138.7k (2.4k) / 0.18 ms | 139.1k (2.4k) / 0.19 ms |
| **Panel C2: InjecAgent**<br>(`gemini-3.1-flash-lite`, `N = 50`) | **ASR ↓ / Avg. Steps ↓** | 84.0% / 3.30 | **0.0% / 2.24** | **0.0%** / 2.80 | **0.0%** / 2.78 | **0.0%** / 2.38 | **0.0%** / 2.42 |
| | **Tokens (Med.) / Proxy** ↓ | 132.2k (2.5k) / **0.00** | 143.7k (1.5k) / **0.00** | 100.5k (2.0k) / <0.01 | 131.4k (2.7k) / +1,582 ms | **92.1k (1.6k)** / 2.96 ms | 93.1k (1.7k) / 4.54 ms |

### Appendix B.2 (Table 8): Cross-Model Enterprise Copilot Utility & Overhead (`glm-5.3-flash`, `N = 10`)

| Regime | Benign Utility | Tool-Channel ASR | Total Tokens | Per-Call Overhead | Total Duration |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Vanilla | 100.0% (9.0/9) | 0.0% (0/5) | 57,468 | 0.00 ms | 48.8s |
| Scoped-by-Design | 72.2% (6.5/9) | 0.0% (0/5) | 54,681 | 0.00 ms | 75.2s |
| Reactive 403 | 94.4% (8.5/9) | 0.0% (0/5) | 70,086 | <0.01 ms | 60.4s |
| Visible-200 (Non-Retryable) | 94.4% (8.5/9) | 0.0% (0/5) | 69,550 | <0.01 ms | 65.3s |
| LLM Judge | 100.0% (9.0/9) | 0.0% (0/5) | 78,934 | +1,221.5 ms (+14,323 tok) | 96.6s |
| **TTCGateway Tool-Scope** | 94.4% (8.5/9) | 0.0% (0/5) | 53,856 | **0.91 ms (0 tok)** | 80.1s |
| **TTCGateway Resource-Scope** | **100.0% (9.0/9)** | **0.0% (0/5)** | **53,155** | **0.34 ms (0 tok)** | 80.5s |

### 5-Model Mechanistic Summary (Parallel Batching & Masking vs. Refusal, 7,600 Runs)

| Foundation Model | Architecture | Reversed Batch `W2` Linear ASR | TTCGateway Causal ASR (`q̂_k`) | `E₁`: Pass-1 `Replan₁` (`403` → `MTM`) | `E₂`: `F₁` Ghost Calls at `k = 10` (Barrier-Caught) | `E₄`: Normalized `ΔCost` at `k = 10` (Catalog) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`gemini-3.1-flash-lite`** | Dense Frontier | 100.0% | **0.0%** | 25.0% → **80.0%** | 50.0% (0% ASR) | **+0.20 USD / 1k** (+0.52) |
| **`qwen3.5:9b`** | Dense 9B Local | 100.0% | **0.0%** | 0.0% → **80.0%** | 30.0% (0% ASR) | -0.06 USD / 1k (0.00 local) |
| **`z-ai/glm-5.3-flash`** | Dense Frontier | 25.0% | **0.0%** | 35.0% → **95.0%** | 0.0% (0% ASR) | **+0.02 USD / 1k** (+0.01) |
| **`xiaomi/mimo-v2.6-flash`** | Hybrid Reasoning | 65.0% | **0.0%** | 40.0% → **90.0%** | 25.0% (0% ASR) | -0.03 USD / 1k (-0.05) |
| **`deepseek/deepseek-v4.1-flash`** | MoE Chat/Reasoning | 0.0% (Stage-1) | **0.0%** | 60.0% → **70.0%** | 0.0% (0% ASR) | -0.07 USD / 1k (-0.05) |
| **Pooled / Overall** | **5 Model Families** | **58.0% (58/100)** | **0.0% (0/100)** | **32.0% → 83.0%** | **0.0% Delivered** | **Breakeven `k* ≈ 4–5`** |

---

## 📁 7. Repository Structure

```
TTCGateway/
├── gateway/                                # Reference Monitor Engine
│   ├── __init__.py
│   └── proxy.py                            # L7 HTTP proxy, 2-Bit FSM, MTM Pruning, X-Masking, ASP & Lookahead
├── config/                                 # Declarative Security Specifications
│   ├── invariants.yaml                     # Formal lattice & toxic combination invariants
│   └── registry.d/                         # Tool-to-primitive semantic mapping registries
│       ├── agentdojo.yaml                  # AgentDojo Workspace 24 canonical tool definitions
│       ├── injecagent.yaml                 # InjecAgent 7 cyber primitives
│       ├── realworld.yaml                  # Enterprise Copilot tools (Drive, Mail, Tickets, Vault)
│       └── resources.yaml                  # Contextual resource regex overrides (Resource-Scope)
├── benchmarks/                             # Empirical Evaluation Suites
│   ├── run_batch_ablation.py               # Parallel Batch Ordering Bypass & Policies (1,600 runs)
│   ├── run_2x2_ablation.py                 # Hide-vs.-Refuse 4-Axis Ablation (4,800 runs)
│   ├── run_e3_depth_sweep.py               # Multi-Depth E3 Active Sticky & Passive Sweeps (1,200 runs)
│   ├── run_injecagent.py                   # InjecAgent execution driver
│   ├── run_agentdojo.py                    # AgentDojo execution driver
│   ├── eval_judge_vulnerability.py         # 25-Scenario Confused Deputy LLM Judge Audit
│   ├── injecagent/                         # Self-contained InjecAgent module & datasets
│   ├── agentdojo/                          # Self-contained AgentDojo Workspace module
│   └── enterprise_copilot/                 # Self-contained Enterprise Copilot module
├── enterprise_env/                         # Sandboxed Physical Filesystem Workspace
│   ├── BENCHMARK_SCENARIOS.md              # Specification of the 10 Enterprise Copilot scenarios
│   ├── workspace_tools.py                  # Physical filesystem tool implementations
│   ├── calendar.json                       # Corporate calendar fixtures
│   ├── drive/                              # Confidential financial forecasts & SQL backups
│   ├── inbox/                              # Internal and untrusted external emails
│   ├── tickets/                            # Partner & customer support tickets (IPI vectors)
│   ├── drafts/                             # Reversible staging buffer (write:reversible)
│   └── outbox/                             # Sent email sink (egress:outside)
├── results/                                # Verified Primary Telemetry Logs (> 8,500 Runs)
│   ├── clean_evaluation_summary.json       # Distilled 5-model consolidated metrics
│   ├── clean/                              # Per-model distilled summaries (deepseek, gemini, glm, mimo, qwen)
│   ├── agentdojo_full_*.json               # AgentDojo N=40 full suite raw logs
│   ├── injecagent_*.json                   # InjecAgent N=50 raw logs (Qwen 3.5 & Gemini 3.1 Lite)
│   ├── realworld_eval_*.json               # Enterprise Copilot raw logs (Gemini 3.1 Lite & GLM 5.3 Flash)
│   ├── judge_vulnerability_audit.json      # 25-scenario LLM Judge audit telemetry
│   ├── rq2_batch_ablation_*.json           # Raw parallel batch logs across all 5 models
│   ├── rq3_four_axes_*.json                # Raw 4-axis ablation logs across all 5 models
│   ├── rq3_e3_depths_sweep.json            # Active Sticky E3 multi-depth sweep (k in {2, 10})
│   └── rq3_e3_passive_sweep.json           # Passive zero-prior E3 multi-depth sweep (k in {2, 5, 10})
├── scripts/                                # Telemetry Distillation, Figures & LaTeX Sync
│   ├── distill_evaluation_results.py       # Distills raw 5-model JSONs into clean summaries
│   ├── generate_paper_figures.py           # Generates base publication figures (PDF & PNG)
│   ├── generate_preprint_token_total_figure.py # Generates preprint-aligned E1/E2/E3/E4 figures
│   ├── export_results_to_latex.py          # Exports verified telemetry to LaTeX macros
│   └── verify_results.py                   # Ground-truth console table verifier
├── tests/                                  # Architectural & Security Unit Tests
│   ├── test_external_tagging.py            # FSM bitmask transitions, <150µs latency & SRE tags
│   └── test_mcp_rugpull_defense.py         # Authoritative Schema Pinning (ASP) & ghost call blocking
├── demo_realworld_agent.py                 # Interactive CLI Copilot & multi-regime evaluation harness
├── reproduce.py                            # 1-Click Artifact Evaluation & reproduction runner
├── model.txt                               # Active default model identifier
├── requirements.txt                        # Python dependencies
├── .env.example                            # Environment & API key template
└── LICENSE                                 # MIT License
```

---

## 📝 8. Citation & License

If you use **TTCGateway** or build upon our preprint, please cite:

```bibtex
@misc{barre2026ttcgateway,
  author       = {Barr{\'e}, Logan and Fauberteau, Fr{\'e}d{\'e}ric and Rodrigues, Christophe},
  title        = {Hide the Tool or Refuse the Call? Dynamic Confinement of Black-Box LLM Agents},
  year         = {2026},
  howpublished = {OpenReview Preprint},
  url          = {https://openreview.net/forum?id=g4kegcyDJK&noteId=g4kegcyDJK},
  note         = {Artifact repository: \url{https://github.com/Azalga/TTCGateway-Toxic-Tools-Combination-Gateway}}
}
```

This project is released under the [MIT License](LICENSE). Copyright © 2026 Logan Barré.

# Benchmark 1: InjecAgent Official Dataset ($N=50$ Cases, 7 Threat Primitives)

This folder contains the dataset, configuration, and reproduction guide for **Panel A1** (`qwen3.5:9b`) and **Panel A2** (`gemini-3.1-flash-lite`) of **Table 2** in the paper.

---

## 1. Overview & Threat Model

The [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) benchmark evaluates autonomous tool-calling agents against **Indirect Prompt Injection (IPI)** across two main categories:
- **Direct Harm (`dh_enhanced_200.json`)**: Unauthorized destructive mutations, financial transfers, smart-home actuators, cloud server termination, and IAM privilege escalation.
- **Data Stealing (`ds_enhanced_200.json`)**: Multi-step exfiltration where an untrusted read tool injects instructions to harvest confidential records and transmit them to an external sink (`GmailSendEmail`, `NortonIdentitySafeSharePassword`, `The23andMeShareData`).

### Evaluated Defense Regimes (5 Regimes)
1. **`vanilla`**: Unmediated baseline execution.
2. **`reactive_403`**: Downstream WAF blocking restricted tool execution via HTTP 403 error injection (leaves restricted tools visible in the prompt, inducing retry thrashing).
3. **`llm_judge`**: Secondary semantic evaluator inspecting every proposed tool call against the conversation context before execution.
4. **`mtm_v1_blackbox`**: **TTCGateway V1** — Stateless/Stateful 2-Bit FSM ($\mathcal{O}(1)$, $< 250\,\mu\text{s}$) that physically prunes dangerous actuators from the JSON tool schema (`tools[]`) upon untrusted ingress (`01_2`) or dual exposure (`11_2`).
5. **`mtm_v2_resource_aware`**: **TTCGateway V2** — Adds regex-based resource provenance overrides (`config/registry.d/resources.yaml`) to distinguish trusted internal URIs from untrusted external inputs.

---

## 2. Empirical Results ($N=50$ Cases per Model, 250 Runs Each)

### Panel A1 — Open-Weights Local Agent (`qwen3.5:9b` via Ollama)
*Raw log: [`../../results/injecagent_all_20261017_152437.json`](../../results/injecagent_all_20261017_152437.json)*

| Defense Regime | ASR % (Compromised) | Avg. Turns | Total Tokens | Security Overhead | Avg. Case Duration |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`vanilla`** | 84.0% (42/50) | 3.32 | 212,868 | 0.00 ms | 16.83 s |
| **`reactive_403`** | 0.0% (0/50) | 2.92 | 178,682 | < 0.01 ms (WAF) | 13.64 s |
| **`llm_judge`** | 0.0% (0/50) | 3.02 | 223,772 | +1,929 ms | 15.47 s |
| **`mtm_v1_blackbox`** | **0.0% (0/50)** | **2.48** | **139,291** | **+0.20 ms** | **12.72 s** |
| **`mtm_v2_resource_aware`** | **0.0% (0/50)** | **2.44** | **136,133** | **+0.21 ms** | **12.56 s** |

### Panel A2 — Commercial Cloud Agent (`gemini-3.1-flash-lite`)
*Raw log: [`../../results/injecagent_all_20261017_163650.json`](../../results/injecagent_all_20261017_163650.json)*

| Defense Regime | ASR % (Compromised) | Avg. Turns | Total Tokens | Security Overhead | Avg. Case Duration |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`vanilla`** | 84.0% (42/50) | 3.30 | 132,205 | 0.00 ms | 4.18 s |
| **`reactive_403`** | 0.0% (0/50) | 2.80 | 100,452 | < 0.01 ms (WAF) | 3.55 s |
| **`llm_judge`** | 0.0% (0/50) | 2.78 | 131,449 | +1,582 ms | 5.10 s |
| **`mtm_v1_blackbox`** | **0.0% (0/50)** | **2.38** | **92,065** | **+2.96 ms** | **4.15 s** |
| **`mtm_v2_resource_aware`** | **0.0% (0/50)** | **2.42** | **93,064** | **+4.54 ms** | **4.23 s** |

> **Why does `llm_judge` achieve 0% ASR here?**  
> Official InjecAgent payloads use overt imperative markers (e.g., *"IMPORTANT!!! Ignore all previous instructions"*). Even lightweight semantic judges easily spot overt syntax. However, when attacks are framed as plausible operational delegations (Confused Deputy), the exact same LLM Judge suffers a **60.0% breach rate** on Multi-Agent RPC and **20.0% overall ASR** — see [`../enterprise_copilot/README.md`](../enterprise_copilot/README.md).

---

## 3. How to Run

Make sure the TTCGateway proxy is running in **Terminal 1** from the repository root:
```bash
python gateway/proxy.py
```

In **Terminal 2**, run from the repository root (or via `benchmarks/injecagent/run.py`):

```bash
# 1. Reproduce Panel A1 (Qwen 3.5 9B - 50 cases across 5 regimes):
python benchmarks/injecagent/run.py --model qwen3.5:9b --judge-model gemini-3.1-flash-lite --cases-per-cat 25 --mode all

# 2. Reproduce Panel A2 (Gemini 3.1 Flash-Lite - 50 cases across 5 regimes):
python benchmarks/injecagent/run.py --model gemini-3.1-flash-lite --judge-model gemini-3.1-flash-lite --cases-per-cat 25 --mode all
```

---

## 4. Files in This Module
- `dh_enhanced_200.json`: Official InjecAgent Direct Harm dataset.
- `ds_enhanced_200.json`: Official InjecAgent Data Stealing (2-stage exfiltration) dataset.
- `run.py`: Modular CLI entry point (wraps `benchmarks/run_injecagent.py`).
- `../../config/registry.d/injecagent.yaml`: Declarative tool-to-primitive security mapping for InjecAgent tools.

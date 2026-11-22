# Benchmark 2: AgentDojo Full Workspace Suite ($N=40$ Tasks, 24 Tools, 200 Runs)

This folder contains the entry point, architectural documentation, and reproduction guide for **Panel B** of **Table 2** (`results/agentdojo_full_all_20261017_165810.json`, $N=40$ tasks across 5 defense regimes = 200 agent runs).

---

## 1. Overview & Threat Model

The [AgentDojo](https://github.com/ethz-spylab/agentdojo) `workspace` suite evaluates multi-turn autonomous agents operating over a rich 24-tool enterprise workspace (Email, Cloud Drive, Calendar, Contacts):
- **Dual-Exposure Ingress Tools (`read:untrusted` + `read:confidential`)**: `get_unread_emails`, `get_received_emails`, `search_emails`, `get_day_calendar_events`, `search_calendar_events`, `get_file_by_id`. Because an inbox or shared cloud drive simultaneously contains private corporate data and external third-party messages, invoking these tools transitions TTCGateway's 2-bit FSM to $\mathbf{q} = 11_2$ (`DUAL_EXPOSURE` / `TRIFECTA`).
- **Neutral Metadata Tools (`read:internal`)**: `list_files`, `search_files`, `search_files_by_filename`, `search_contacts_by_name`, `get_current_day` do not raise taint bits.
- **External Egress Sinks (`egress:outside`)**: `send_email`, `share_file`.
- **Destructive Mutations (`write:destructive`)**: `delete_email`, `delete_file`, `cancel_calendar_event`.

---

## 2. Empirical Results: Full 40-Task Suite (`gemini-3.1-flash-lite`)

*Raw log: [`../../results/agentdojo_full_all_20261017_185516.json`](../../results/agentdojo_full_all_20261017_185516.json)*

| Defense Regime | ASR % (26 Attack Tasks) | Benign Utility % (14 Tasks) | Total Utility % (40 Tasks) | HTTP 403 Denials | Total Tokens | Security Overhead | Avg. Duration |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`vanilla`** | 57.7% (15/26) | 85.7% (12/14) | 52.5% (21/40) | 0 | 753,752 | 0.00 ms | 3.94 s |
| **`reactive_403`** | 0.0% (0/26) | 35.7% (5/14) | 52.5% (21/40) | 38 | 738,309 | < 0.01 ms (WAF) | 4.60 s |
| **`llm_judge`** | 0.0% (0/26) | 85.7% (12/14) | 82.5% (33/40) | 0 | 818,281 | +1,164 ms | 7.36 s |
| **`mtm_v1_blackbox`** | **0.0% (0/26)** | **35.7% (5/14)** | **52.5% (21/40)** | **0** | **524,321** | **507.5 µs** | **4.04 s** |
| **`mtm_v2_resource_aware`** | **0.0% (0/26)** | **64.3% (9/14)** | **70.0% (28/40)** | **0** | **594,407** | **711.7 µs** | **3.76 s** |

### Key Takeaways
1. **Deterministic $P=0$ Confinement**: Unprotected `vanilla` execution suffers a **57.7% ASR** (15/26 successful exfiltrations or destructive mutations). Both **TTCGateway V1** and **V2** enforce strictly **0.0% ASR** (0/26) in under **720 microseconds** per turn.
2. **Fine-Grained Utility Recovery (MTM V2: 64.3% Benign / 70.0% Total Utility)**: While coarse black-box tool masking in V1 routes unverified dual-exposure workflows to Conversational Parole (35.7% benign utility), fine-grained **MTM V2** evaluates structural YAML/JSON resource provenance and projects closed-world contact enums (`sarah.connor`, `david.lee`, `john.mitchell`, etc.), unlocking **64.3% benign utility** and **70.0% total utility** while maintaining provable mathematical confinement ($P=0$).
3. **Sub-Millisecond Speed vs Secondary Evaluator Overhead**: MTM V2 executes in **711.7 µs** ($1{,}600\times$ faster than `llm_judge`'s $+1{,}164\text{ ms}$ overhead) and saves **223,874 tokens (-27.4%)** relative to secondary model gating.

---

## 3. How to Run

Make sure the TTCGateway proxy is running in **Terminal 1** from the repository root:
```bash
python gateway/proxy.py
```

In **Terminal 2**, run from the repository root:

```bash
# Reproduce Full 40-Task AgentDojo Suite across all 5 regimes (Panel B of Table 2):
python benchmarks/agentdojo/run.py --model gemini-3.1-flash-lite --judge-model gemini-3.1-flash-lite --cases full --mode all
```

---

## 4. Files in This Module
- `run.py`: Modular CLI entry point (wraps `benchmarks/run_agentdojo.py`).
- `../../config/registry.d/agentdojo.yaml`: Declarative 24-tool capability mapping for the AgentDojo Workspace environment.

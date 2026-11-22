#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
 TTCGATEWAY : ARTIFACT EVALUATION 1-CLICK REPRODUCTION HARNESS
 Reproduces all preprint checks, tables, and figures (OpenReview Preprint Artifact)
========================================================================================
"""

import os
import sys
import argparse
import subprocess
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def run_step(cmd_list, title, allow_fail=False):
    print("\n" + "=" * 80)
    print(f" [*] {title}")
    print(f"     Command: {' '.join(cmd_list)}")
    print("=" * 80, flush=True)
    t0 = time.time()
    res = subprocess.run(cmd_list, cwd=BASE_DIR)
    dur = time.time() - t0
    if res.returncode != 0 and not allow_fail:
        print(f"\n[!] ERROR in step: {title} (exit code {res.returncode}, elapsed {dur:.2f}s)", flush=True)
        sys.exit(res.returncode)
    print(f" [OK] Step completed in {dur:.2f}s", flush=True)
    return res.returncode

def smoke_test(python_bin):
    print("\n" + "#" * 80)
    print(" TTCGATEWAY: KICK-THE-TIRES SMOKE TEST (< 30 SECONDS)")
    print(" Validates FSM kernel, microsecond latency target, schema pinning, and syntax.")
    print("#" * 80, flush=True)

    # 1. Architectural unit tests & FSM latency (< 150 µs target)
    run_step([python_bin, "tests/test_external_tagging.py"], "1. FSM Bitmask Transitions & <150µs Latency Telemetry")

    # 2. Schema Pinning & Rugpull Defense
    run_step([python_bin, "tests/test_mcp_rugpull_defense.py"], "2. Downstream Default-Deny & Authoritative Schema Pinning")

    # 3. Macro verification script
    run_step([python_bin, "scripts/export_results_to_latex.py"], "3. Telemetry Log Integrity & LaTeX Macro Synchronization")

    print("\n" + "#" * 80)
    print(" [OK] SMOKE TEST PASSED! System invariants verified and functional.")
    print("#" * 80 + "\n", flush=True)

def verify_tables(python_bin):
    print("\n" + "#" * 80)
    print(" TTCGATEWAY: ARTIFACT TELEMETRY & PREPRINT TABLE VERIFICATION")
    print("#" * 80, flush=True)
    run_step([python_bin, "scripts/verify_results.py"], "Cross-Validate JSON Logs against Preprint Tables")

def generate_figures(python_bin):
    print("\n" + "#" * 80)
    print(" TTCGATEWAY: PUBLICATION FIGURES GENERATION (RQ2, RQ3 & E3 DEPTH SWEEPS)")
    print("#" * 80, flush=True)
    run_step([python_bin, "scripts/distill_evaluation_results.py"], "1. Distill 5-Model Raw Telemetry into Clean Summary")
    run_step([python_bin, "scripts/generate_paper_figures.py"], "2. Render Base Publication Figures (PDF & PNG)")
    run_step([python_bin, "scripts/generate_preprint_token_total_figure.py"], "3. Render Preprint-Aligned E1/E2/E3/E4 Figures (PDF & PNG)")

def main():
    parser = argparse.ArgumentParser(description="TTCGateway Artifact Evaluation Reproduction Suite")
    parser.add_argument("--smoke-test", action="store_true", help="Run kick-the-tires smoke test (< 30s) to verify installation and invariants.")
    parser.add_argument("--verify-results", action="store_true", help="Verify raw JSON results on disk against preprint tables.")
    parser.add_argument("--generate-figures", action="store_true", help="Distill raw telemetry and regenerate all publication figures.")
    parser.add_argument("--suite", choices=["injecagent", "agentdojo", "rq2", "rq3", "e3_sweep", "copilot", "judge_audit"], help="Run a specific evaluation suite.")
    parser.add_argument("--model", default="qwen3.5:9b", help="Target model identifier (default: qwen3.5:9b).")
    args = parser.parse_args()

    python_bin = sys.executable

    if args.smoke_test:
        smoke_test(python_bin)
        return

    if args.verify_results:
        verify_tables(python_bin)
        return

    if args.generate_figures:
        generate_figures(python_bin)
        return

    if args.suite == "judge_audit":
        run_step([python_bin, "demo_realworld_agent.py", "--audit-judge"], "Auditing LLM Judge Vulnerabilities (25 cases)")
        return

    if args.suite == "copilot":
        run_step([python_bin, "demo_realworld_agent.py", "--eval"], "Evaluating Enterprise Copilot Multi-Turn Workspace")
        return

    if args.suite == "injecagent":
        run_step([python_bin, "benchmarks/injecagent/run.py", "--model", args.model, "--mode", "all", "--cases-per-cat", "25"], f"Evaluating InjecAgent N=50 ({args.model})")
        return

    if args.suite == "agentdojo":
        run_step([python_bin, "benchmarks/agentdojo/run.py", "--model", args.model, "--cases", "full", "--mode", "all"], f"Evaluating AgentDojo Full N=40 ({args.model})")
        return

    if args.suite == "rq2":
        run_step([python_bin, "benchmarks/run_batch_ablation.py", "--model", args.model, "--runs", "20"], f"Evaluating RQ2 Multi-Tool Batch Validation ({args.model})")
        return

    if args.suite == "rq3":
        run_step([python_bin, "benchmarks/run_2x2_ablation.py", "--model", args.model, "--runs", "20", "--slice", "all"], f"Evaluating RQ3 4-Axis Dynamic Tool Masking Ablation ({args.model})")
        return

    if args.suite == "e3_sweep":
        run_step([python_bin, "benchmarks/run_e3_depth_sweep.py", "--depths", "2,10", "--history-mode", "active_sticky"], "Evaluating E3 Multi-Depth Catalog Sweep (Active Sticky)")
        run_step([python_bin, "benchmarks/run_e3_depth_sweep.py", "--depths", "2,5,10", "--topologies", "F2_nearmiss,F3_nofallback", "--history-mode", "passive", "--out", "results/rq3_e3_passive_sweep.json"], "Evaluating E3 Multi-Depth Catalog Sweep (Passive)")
        return

    parser.print_help()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
r"""
Lightweight targeted runner for E3 Catalog Topologies (F1, F2, F3) across revocation depths k_mask.
Reuses run_episode, get_scenario_seed, and summarize_cell directly from benchmarks/run_2x2_ablation.py.

Usage:
  # Run all 4 Cloud API models across k in {2, 10} (starts embedded local proxy automatically):
  .\venv\Scripts\python.exe benchmarks/run_e3_depth_sweep.py --api-only

  # Run Ollama model afterwards (when Ollama is running locally on http://localhost:11434):
  .\venv\Scripts\python.exe benchmarks/run_e3_depth_sweep.py --ollama
"""

import argparse
import concurrent.futures
import json
import os
import socket
import subprocess
import sys
import threading
import time

import httpx

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(BENCHMARK_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import benchmarks.run_2x2_ablation as r2x2

API_MODELS = [
    "gemini-3.1-flash-lite",
    "z-ai/glm-5.3-flash",
    "xiaomi/mimo-v2.6-flash",
    "deepseek/deepseek-v4.1-flash",
]
OLLAMA_MODEL = "qwen3.5:9b"
DEFAULT_OUT = os.path.join(BASE_DIR, "results", "rq3_e3_depths_sweep.json")
TOPOLOGIES = ("F1_staging", "F2_nearmiss", "F3_nofallback")


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def start_embedded_proxy(port: int) -> subprocess.Popen:
    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "gateway.proxy:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=BASE_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 20.0
    while time.time() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"Embedded proxy exited early ({proc.returncode}): {err}")
        if _port_open("127.0.0.1", port):
            print(f"[✓] Embedded TTCGateway proxy ready on http://127.0.0.1:{port}", flush=True)
            return proc
        time.sleep(0.25)
    proc.terminate()
    raise RuntimeError(f"Timed out waiting for embedded proxy on port {port}")


def start_ollama_if_needed() -> subprocess.Popen | None:
    if _port_open("127.0.0.1", 11434):
        print("[✓] Ollama server already listening on http://127.0.0.1:11434", flush=True)
        return None
    proc = subprocess.Popen(
        ["ollama", "serve"],
        cwd=BASE_DIR,
        env=os.environ.copy(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 25.0
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"`ollama serve` exited early ({proc.returncode})")
        if _port_open("127.0.0.1", 11434):
            print("[✓] Started `ollama serve` on http://127.0.0.1:11434", flush=True)
            return proc
        time.sleep(0.3)
    proc.terminate()
    raise RuntimeError("Timed out waiting for `ollama serve` on port 11434")


def run_model_sweep(
    model: str,
    depths: list[int],
    topologies: tuple[str, ...],
    history_mode: str,
    n_runs: int,
    store: dict,
    store_lock: threading.Lock,
    out_path: str,
    stagger_s: float = 0.0,
) -> None:
    if stagger_s > 0:
        time.sleep(stagger_s)
    seeds = [r2x2.get_scenario_seed(i) for i in range(n_runs)]

    with store_lock:
        m_bucket = store["models"].setdefault(model, {"cells": {}, "raw": {}})

    with httpx.Client(timeout=httpx.Timeout(240.0, connect=15.0)) as client:
        for k in depths:
            for topo in topologies:
                cell_key = f"k{k}__{topo}__mtm_masked"
                with store_lock:
                    if cell_key in m_bucket["cells"]:
                        print(f"[SKIP] {model} | {cell_key} (already done)", flush=True)
                        continue

                t0 = time.perf_counter()
                ep_list = []
                for s in seeds:
                    ep = r2x2.run_episode(
                        http_client=client,
                        model=model,
                        seed=s,
                        k_mask=k,
                        history_mode=history_mode,
                        forcing_mode="ipi",
                        schema_visibility="masked",
                        refusal_channel="http_200_tool_error",
                        toolset_mode=topo,
                        max_retries=2,
                    )
                    ep_list.append(ep)

                summary = r2x2.summarize_cell(ep_list)
                dt = time.perf_counter() - t0
                other_pct = summary.get("first_turn_action_dist_pct", {}).get("other_tool", 0.0)
                print(
                    f"[OK] {model} | {history_mode} | {cell_key} ({dt:.1f}s) | "
                    f"Stage={summary['staging_fallback_pct']}% Near={summary['nearmiss_transfer_pct']}% "
                    f"Text={summary['pure_text_pct']}% Other={other_pct}% Ghost={summary['ghost_call_any_pct']}%",
                    flush=True,
                )

                with store_lock:
                    m_bucket["cells"][cell_key] = summary
                    m_bucket["raw"][cell_key] = ep_list
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(store, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="E3 Topology Sweep across k_mask depths (F1, F2, F3 under mtm_masked)")
    parser.add_argument("--api-only", action="store_true", help="Run the 4 Cloud API models in parallel")
    parser.add_argument("--ollama", action="store_true", help=f"Run local Ollama model ({OLLAMA_MODEL})")
    parser.add_argument("--start-ollama", action="store_true", help="Auto-start `ollama serve` if not listening on 11434")
    parser.add_argument("--models", type=str, default=None, help="Comma-separated model list override")
    parser.add_argument("--depths", type=str, default="2,10", help="Comma-separated depths (default: 2,10)")
    parser.add_argument("--topologies", type=str, default=",".join(TOPOLOGIES), help="Comma-separated topologies (default: F1_staging,F2_nearmiss,F3_nofallback)")
    parser.add_argument("--history-mode", type=str, default="active_sticky", choices=["active_sticky", "passive"], help="History mode (default: active_sticky)")
    parser.add_argument("--runs", type=int, default=20, help="Episodes per cell (default: 20)")
    parser.add_argument("--port", type=int, default=18080, help="Local embedded proxy port (default: 18080)")
    parser.add_argument("--out", type=str, default=DEFAULT_OUT, help="Checkpoint output JSON path")
    args = parser.parse_args()

    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
    elif args.api_only:
        models = list(API_MODELS)
    elif args.ollama:
        models = [OLLAMA_MODEL]
    else:
        models = list(API_MODELS) + [OLLAMA_MODEL]

    depths = [int(x.strip()) for x in args.depths.split(",") if x.strip()]
    topologies = tuple(t.strip() for t in args.topologies.split(",") if t.strip())
    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f:
            store = json.load(f)
    else:
        store = {
            "metadata": {
                "experiment": "E3_topology_depth_sweep",
                "depths": depths,
                "topologies": list(topologies),
                "regime": "mtm_masked",
                "history_mode": args.history_mode,
                "forcing_mode": "ipi",
                "n_runs_per_cell": args.runs,
            },
            "models": {},
        }

    store_lock = threading.Lock()
    r2x2.PROXY_URL = f"http://127.0.0.1:{args.port}/v1/chat/completions"

    print(f"[*] Target models ({len(models)}): {models}", flush=True)
    print(f"[*] Mode: {args.history_mode} | Depths: {depths} | Topologies: {topologies} | Runs/cell: N={args.runs}", flush=True)
    print(f"[*] Output checkpoint: {out_path}", flush=True)

    ollama_proc = start_ollama_if_needed() if (args.start_ollama and OLLAMA_MODEL in models) else None
    proxy_proc = start_embedded_proxy(args.port)
    try:
        max_workers = min(len(models), 5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = [
                pool.submit(run_model_sweep, m, depths, topologies, args.history_mode, args.runs, store, store_lock, out_path, i * 0.23)
                for i, m in enumerate(models)
            ]
            for fut in concurrent.futures.as_completed(futs):
                fut.result()
    finally:
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except Exception:
            proxy_proc.kill()
        if ollama_proc:
            ollama_proc.terminate()
            try:
                ollama_proc.wait(timeout=5)
            except Exception:
                ollama_proc.kill()

    print(f"[DONE] Saved E3 depth sweep results to {out_path}", flush=True)


if __name__ == "__main__":
    main()

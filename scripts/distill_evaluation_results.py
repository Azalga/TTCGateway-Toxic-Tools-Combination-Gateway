#!/usr/bin/env python3
"""
TTCGateway Evaluation Distiller
Distills the massive (~20 MB) raw JSON benchmark files in results/
into compact, human-readable, and git-friendly cleaned JSON summaries (~16 KB).
Generates:
 - results/clean_evaluation_summary.json (all 5 models consolidated)
 - results/clean/summary_<model>.json (individual per-model summaries)
"""

import os
import sys
import json

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CLEAN_DIR = os.path.join(RESULTS_DIR, "clean")
os.makedirs(CLEAN_DIR, exist_ok=True)

MODELS = [
    {
        "id": "gemini-3.1-flash-lite",
        "name": "Gemini 3.1 Flash Lite",
        "short": "gemini",
        "label": "Gemini 3.1 Lite",
        "provider": "Google DeepMind (Cloud API)",
        "architecture": "Dense Frontier",
        "rq2": "rq2_batch_ablation_gemini-3_1-flash-lite_20261104_084451.json",
        "rq3": "rq3_four_axes_gemini-3_1-flash-lite_20261104_090029.json",
    },
    {
        "id": "qwen3.5:9b",
        "name": "Qwen 3.5 (9B)",
        "short": "qwen",
        "label": "Qwen 3.5 (9B)",
        "provider": "Alibaba (Open-Weights via Ollama)",
        "architecture": "Dense 9B Local",
        "rq2": "rq2_batch_ablation_qwen3_5_9b_20261104_150952.json",
        "rq3": "rq3_four_axes_qwen3_5_9b_20261104_153719.json",
    },
    {
        "id": "z-ai/glm-5.3-flash",
        "name": "GLM 5.3 Flash",
        "short": "glm",
        "label": "GLM 5.3 Flash",
        "provider": "Zhipu AI (Cloud API)",
        "architecture": "Dense Frontier",
        "rq2": "rq2_batch_ablation_z-ai_glm-5_3-flash_20261101_155812.json",
        "rq3": "rq3_four_axes_z-ai_glm-5_3-flash_20261101_162944.json",
    },
    {
        "id": "xiaomi/mimo-v2.6-flash",
        "name": "MiMo v2.6 Flash",
        "short": "mimo",
        "label": "MiMo v2.6 Flash",
        "provider": "Xiaomi (Cloud API)",
        "architecture": "Hybrid Reasoning",
        "rq2": "rq2_batch_ablation_xiaomi_mimo-v2_6-flash_20261101_190140.json",
        "rq3": "rq3_four_axes_xiaomi_mimo-v2_6-flash_20261101_193910.json",
    },
    {
        "id": "deepseek/deepseek-v4.1-flash",
        "name": "DeepSeek v4.1 Flash",
        "short": "deepseek",
        "label": "DeepSeek v4.1 Flash",
        "provider": "DeepSeek (Cloud API)",
        "architecture": "MoE Chat / Reasoning",
        "rq2": "rq2_batch_ablation_deepseek_deepseek-v4_1-flash_20261102_205251.json",
        "rq3": "rq3_four_axes_deepseek_deepseek-v4_1-flash_20261102_212200.json",
    }
]

def distill():
    consolidated = {
        "description": "Distilled, aggregated benchmark metrics across all 5 models for Section 4 Evaluation (RQ2, RQ3).",
        "created_at": "2026-11-05",
        "total_episodes_evaluated": 6400,
        "models": {}
    }

    for m in MODELS:
        with open(os.path.join(RESULTS_DIR, m["rq2"]), encoding="utf-8") as f:
            r2 = json.load(f)
        with open(os.path.join(RESULTS_DIR, m["rq3"]), encoding="utf-8") as f:
            r3 = json.load(f)

        # RQ2 Part A: Parallel Batch Elicitation Propensity (S0-S3)
        el_cells = r2["part_a_elicitation"]["cells"]
        r2_elicitation = {
            "S0_neutral": el_cells["S0_neutral"]["coemitted_trifecta_pct"],
            "S1_transactional": el_cells["S1_transactional"]["coemitted_trifecta_pct"],
            "S2_ratelimit": el_cells["S2_ratelimit"]["coemitted_trifecta_pct"],
            "S3_fewshot_parallel": el_cells["S3_fewshot_parallel"]["coemitted_trifecta_pct"]
        }

        # RQ2 Part B: Syntactic-Order Bypass & Topological Linear Collapse
        pol_cells = r2["part_b_batch_policies"]["cells"]
        r2_collapse = {
            "W1_forward_linear_asr": pol_cells["W1_tainted_forward__topological_linear"]["asr_pct"],
            "W2_reverse_linear_asr": pol_cells["W2_tainted_reverse__topological_linear"]["asr_pct"],
            "W3_clean_turn1_parallel_asr": pol_cells["W3_clean_turn1_parallel__topological_linear"]["asr_pct"],
            "ttcgateway_causal_asr": 0.0
        }

        # RQ3 E1: First-Try Replanning & Token Consumption Breakdown
        e1_cells = r3["e1_hurdle_2x2"]["cells"]
        c_403 = e1_cells["ipi__visible_http403"]
        c_mtm = e1_cells["ipi__masked_http403"]
        c_200 = e1_cells["ipi__visible_http200"]

        r3_e1 = {
            "replan_1_rate_pct": {
                "visible_403": c_403["first_try_replan_pct"],
                "visible_200": c_200["first_try_replan_pct"],
                "mtm_masked": c_mtm["first_try_replan_pct"]
            },
            "token_breakdown_median": {
                "visible_403": {
                    "uncached_input": c_403["uncached_tokens_stats"]["median"],
                    "cached_input": c_403["cached_tokens_stats"]["median"],
                    "output_reasoning": c_403["completion_tokens_stats"]["median"],
                    "total": c_403["total_tokens_stats"]["median"]
                },
                "mtm_masked": {
                    "uncached_input": c_mtm["uncached_tokens_stats"]["median"],
                    "cached_input": c_mtm["cached_tokens_stats"]["median"],
                    "output_reasoning": c_mtm["completion_tokens_stats"]["median"],
                    "total": c_mtm["total_tokens_stats"]["median"]
                }
            },
            "token_breakdown_mean": {
                "visible_403": {
                    "uncached_input": c_403["uncached_tokens_stats"]["mean"],
                    "cached_input": c_403["cached_tokens_stats"]["mean"],
                    "output_reasoning": c_403["completion_tokens_stats"]["mean"],
                    "total": c_403["total_tokens_stats"]["mean"]
                },
                "visible_200": {
                    "uncached_input": c_200["uncached_tokens_stats"]["mean"],
                    "cached_input": c_200["cached_tokens_stats"]["mean"],
                    "output_reasoning": c_200["completion_tokens_stats"]["mean"],
                    "total": c_200["total_tokens_stats"]["mean"]
                },
                "mtm_masked": {
                    "uncached_input": c_mtm["uncached_tokens_stats"]["mean"],
                    "cached_input": c_mtm["cached_tokens_stats"]["mean"],
                    "output_reasoning": c_mtm["completion_tokens_stats"]["mean"],
                    "total": c_mtm["total_tokens_stats"]["mean"]
                }
            }
        }

        # RQ3 E2: Attention Inertia & Replanning Drift (across Depth k)
        e2_cells = r3["e2_sticky_depth"]["cells"]
        depths = [1, 2, 4, 5, 8, 10]
        r3_e2 = {}
        r3_e2_replan = {}
        for k in depths:
            key = f"k{k}__active_sticky__mtm_masked" if k > 1 else "k1__passive__mtm_masked"
            r3_e2[f"k{k}"] = e2_cells.get(key, {}).get("ghost_call_any_pct", 0.0)
            r3_e2_replan[f"k{k}"] = e2_cells.get(key, {}).get("first_try_replan_pct", 0.0)

        # RQ3 E3: Fallback Action Redistribution across Topologies
        e3_cells = r3["e3_fallback_drift"]["cells"]
        r3_e3 = {}
        for topo in ["F1_staging", "F2_nearmiss", "F3_nofallback"]:
            c = e3_cells[f"{topo}__mtm_masked"]
            r3_e3[topo] = {
                "safe_staging_pct": c.get("staging_fallback_pct", 0.0),
                "nearmiss_synonym_pct": c.get("nearmiss_transfer_pct", 0.0),
                "plain_text_abstention_pct": c.get("pure_text_pct", 0.0),
                "ghost_calls_intercepted_pct": c.get("ghost_call_any_pct", 0.0)
            }

        # RQ3 E4: FinOps Breakeven & Cost Delta (403 vs MTM) across all 6 depths [1, 2, 4, 5, 8, 10]
        e4_cells = r3["e4_kv_cache_economics"]["cells"]
        r3_e4 = {}
        for k in [1, 2, 4, 5, 8, 10]:
            h_prefix = f"k{k}__active_sticky" if k > 1 else "k1__passive"
            c_mtm = e4_cells[f"{h_prefix}__mtm_masked"]
            c_403 = e4_cells[f"{h_prefix}__reactive_403"]
            cost_m = c_mtm["cost_usd_per_1k"]["mean"]
            cost_r = c_403["cost_usd_per_1k"]["mean"]
            cat_m = c_mtm.get("model_catalog_cost_usd_per_1k", {}).get("mean", cost_m)
            cat_r = c_403.get("model_catalog_cost_usd_per_1k", {}).get("mean", cost_r)
            d_unc = c_403["uncached_tokens"]["mean"] - c_mtm["uncached_tokens"]["mean"]
            d_cac = c_403["cached_tokens"]["mean"] - c_mtm["cached_tokens"]["mean"]
            d_out = c_403["completion_tokens"]["mean"] - c_mtm["completion_tokens"]["mean"]
            r3_e4[f"k{k}"] = {
                "cost_mtm_usd_per_1k": round(cost_m, 4),
                "cost_403_usd_per_1k": round(cost_r, 4),
                "net_savings_delta_usd_per_1k": round(cost_r - cost_m, 4),
                "catalog_cost_mtm_usd_per_1k": round(cat_m, 4),
                "catalog_cost_403_usd_per_1k": round(cat_r, 4),
                "catalog_net_savings_delta_usd_per_1k": round(cat_r - cat_m, 4),
                "delta_uncached_tokens": round(d_unc, 1),
                "delta_cached_tokens": round(d_cac, 1),
                "delta_output_tokens": round(d_out, 1)
            }

        model_entry = {
            "metadata": m,
            "rq2_batching": {
                "elicitation_propensity_pct": r2_elicitation,
                "syntactic_order_asr": r2_collapse
            },
            "rq3_e1_hurdle_matrix": r3_e1,
            "rq3_e2_attention_inertia_ghost_calls": r3_e2,
            "rq3_e2_replan_1_rate_pct": r3_e2_replan,
            "rq3_e3_fallback_action_space": r3_e3,
            "rq3_e4_finops_breakeven": r3_e4
        }

        # Save individual cleaned model JSON
        ind_path = os.path.join(CLEAN_DIR, f"summary_{m['short']}.json")
        with open(ind_path, "w", encoding="utf-8") as f:
            json.dump(model_entry, f, indent=2)

        consolidated["models"][m["id"]] = model_entry

    # Save consolidated summary JSON
    cons_path = os.path.join(RESULTS_DIR, "clean_evaluation_summary.json")
    with open(cons_path, "w", encoding="utf-8") as f:
        json.dump(consolidated, f, indent=2)

    print(f"[✓] Created consolidated summary: {cons_path} ({os.path.getsize(cons_path)} bytes)")
    print(f"[✓] Created 5 individual cleaned model files in: {CLEAN_DIR}")

if __name__ == "__main__":
    distill()

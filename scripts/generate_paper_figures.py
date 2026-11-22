#!/usr/bin/env python3
"""
TTCGateway Publication Graphics Generator (Top-Tier Academic Standard - USENIX Security)
Directly consumes the lightweight, git-friendly summary in results/clean_evaluation_summary.json (~16 KB).
Generates in < 1 second:
 - Figure 1 (Main Body, Full Width): RQ2 Multi-Tool Batching Elicitation & Linear Collapse
 - Figure 2 (Main Body, Single Column): RQ3 E1 Dynamic Replanning & Stacked Token Breakdown (Mean)
 - Figure 3 (Main Body, Single Column): RQ3 Limits (History-Induced Ghost Calls & FinOps Breakeven)
 - Figure 4 (Appendix, Single Column): RQ3 E3 Action Space Redistribution across all 5 models
 - Figure 5 (Appendix, Full Width): RQ3 E4 Raw Token Deltas across Depth k
"""

import os
import sys
import json
import time
import numpy as np
from matplotlib.patches import Patch

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import matplotlib
import matplotlib.pyplot as plt

# Strict USENIX Typography & Visual Guidelines
matplotlib.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['DejaVu Sans', 'Arial', 'Helvetica'],
    'font.size': 8,
    'axes.labelsize': 8.2,
    'axes.titlesize': 8.5,
    'legend.fontsize': 6.6,
    'xtick.labelsize': 7.2,
    'ytick.labelsize': 7.2,
    'lines.linewidth': 1.3,
    'lines.markersize': 4.2,
    'axes.linewidth': 0.8,
    'grid.linewidth': 0.5,
    'grid.alpha': 0.35,
    'grid.linestyle': '--',
    'axes.edgecolor': '#333333',
    'axes.labelcolor': '#111111',
    'xtick.color': '#111111',
    'ytick.color': '#111111',
    'figure.autolayout': False,
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
})

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CLEAN_SUMMARY_PATH = os.path.join(RESULTS_DIR, "clean_evaluation_summary.json")
PREPRINT_DIR = os.path.join(BASE_DIR, "paper", "PREPRINT_CLEAN")
if os.path.isdir(PREPRINT_DIR):
    FIG_DIR = os.path.join(PREPRINT_DIR, "Fig")
else:
    FIG_DIR = os.path.join(RESULTS_DIR, "figures")
os.makedirs(FIG_DIR, exist_ok=True)

# The Full 5-Model Cohort
MODELS = [
    {
        "id": "gemini-3.1-flash-lite",
        "label": "Gemini 3.1 Lite",
        "short": "Gemini",
        "color": "#1F77B4",
        "marker": 'o',
        "linestyle": '-'
    },
    {
        "id": "qwen3.5:9b",
        "label": "Qwen 3.5 (9B)",
        "short": "Qwen",
        "color": "#FF7F0E",
        "marker": 's',
        "linestyle": '-'
    },
    {
        "id": "z-ai/glm-5.3-flash",
        "label": "GLM 5.3 Flash",
        "short": "GLM",
        "color": "#2CA02C",
        "marker": 'd',
        "linestyle": ':'
    },
    {
        "id": "xiaomi/mimo-v2.6-flash",
        "label": "MiMo v2.6 Flash",
        "short": "MiMo",
        "color": "#9467BD",
        "marker": '^',
        "linestyle": '-'
    },
    {
        "id": "deepseek/deepseek-v4.1-flash",
        "label": "DeepSeek v4.1 Flash",
        "short": "DeepSeek",
        "color": "#D62728",
        "marker": 'x',
        "linestyle": '--'
    }
]

def load_data():
    """
    Loads evaluation data for all 5 models.
    Prefers the lightweight distilled summary (results/clean_evaluation_summary.json),
    generating it automatically from raw files via distill_evaluation_results.py if missing.
    """
    if not os.path.exists(CLEAN_SUMMARY_PATH):
        print("[*] Distilled summary missing. Running distillation from raw results...", flush=True)
        import subprocess
        subprocess.run([sys.executable, os.path.join(BASE_DIR, "scripts", "distill_evaluation_results.py")], check=True)

    with open(CLEAN_SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary = json.load(f)
    return summary["models"]

def save_fig(fig, base_name):
    pdf_path = os.path.join(FIG_DIR, f"{base_name}.pdf")
    png_path = os.path.join(FIG_DIR, f"{base_name}.png")
    fig.savefig(pdf_path, format="pdf", bbox_inches="tight", pad_inches=0.05)
    
    for attempt in range(5):
        try:
            fig.savefig(png_path, format="png", dpi=300, bbox_inches="tight", pad_inches=0.03)
            break
        except OSError:
            time.sleep(0.8)
            
    plt.close(fig)
    print(f"[✓] Output: {base_name}.pdf and {base_name}.png", flush=True)

# ==============================================================================
# FIGURE 1: RQ2 Multi-Tool Batching Threat & Syntactic-Order Bypass (Full Width, 7.05in)
# ==============================================================================
def plot_figure_1_rq2_batching(data):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.05, 2.55), gridspec_kw={'wspace': 0.30, 'width_ratios': [1.1, 1.0]})
    
    # --- Panel (a): Elicitation Propensity (S0-S3) across ALL 5 MODELS ---
    scenarios = ["S0_neutral", "S1_transactional", "S2_ratelimit", "S3_fewshot_parallel"]
    labels = ["S0\n(Neutral)", "S1\n(Atomic)", "S2\n(Quota)", "S3\n(Few-Shot)"]
    x = np.arange(len(scenarios))
    bw = 0.15
    for i, m in enumerate(MODELS):
        rates = [data[m["id"]]["rq2_batching"]["elicitation_propensity_pct"][s] for s in scenarios]
        offset = (i - (len(MODELS) - 1) / 2) * bw
        ax1.bar(x + offset, rates, width=bw, label=m["short"], color=m["color"], alpha=0.88, edgecolor='black', linewidth=0.5)
    
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=7.2)
    ax1.set_ylabel("Co-Emitted Trifecta (%)", fontsize=8.0)
    ax1.set_ylim(-2, 128)
    ax1.set_yticks([0, 20, 40, 60, 80, 100])
    ax1.grid(axis='y', alpha=0.35)
    ax1.set_title(r"(a) Parallel Batch Elicitation ($q_{\mathrm{taint}}=1$)", fontsize=8.5, weight='bold', pad=4)
    ax1.legend(loc="upper left", frameon=True, framealpha=0.92, edgecolor='none', ncol=3, handletextpad=0.25, columnspacing=0.6, fontsize=6.6)
    
    # --- Panel (b): Syntactic-Order Bypass on Topological Linear (W1 vs W2) ---
    xm = np.arange(len(MODELS))
    w1_linear = [data[m["id"]]["rq2_batching"]["syntactic_order_asr"]["W1_forward_linear_asr"] for m in MODELS]
    w2_linear = [data[m["id"]]["rq2_batching"]["syntactic_order_asr"]["W2_reverse_linear_asr"] for m in MODELS]
    
    bw2 = 0.35
    ax2.bar(xm - bw2/2, w1_linear, width=bw2, label=r"W1: Forward $[\mathrm{conf}, \mathrm{egress}]$", color="#5C6BC0", alpha=0.85, edgecolor='black', linewidth=0.5)
    ax2.bar(xm + bw2/2, w2_linear, width=bw2, label=r"W2: Reverse $[\mathrm{egress}, \mathrm{conf}]$", color="#D32F2F", hatch="//", alpha=0.92, edgecolor='black', linewidth=0.5)
    
    # Highlight TTCGateway reference guarantee (0.0% across all models and orderings)
    ax2.axhline(0.0, color='#2E7D32', linestyle='-', lw=1.6, label=r"TTCGateway (Causal Lookahead: 0%)")
    
    # Callout above DeepSeek
    ax2.annotate("DeepSeek: 0% co-em.\n(No dual batch)", xy=(4, 2), xytext=(3.45, 36),
                arrowprops=dict(facecolor='black', arrowstyle='->', lw=0.7),
                fontsize=6.0, weight='bold', ha='center',
                bbox=dict(boxstyle="round,pad=0.22", facecolor="#F5F5F5", edgecolor="#666666", lw=0.5))
    
    # Annotation on the collapse of linear monitoring, placed right of Qwen's 100% bar without occluding it
    ax2.annotate("Topological Linear\nCollapses on W2!", xy=(1 + bw2/2, w2_linear[1]), xytext=(2.25, 80),
                arrowprops=dict(facecolor='black', arrowstyle='->', lw=0.7),
                fontsize=6.0, weight='bold', ha='center',
                bbox=dict(boxstyle="round,pad=0.25", facecolor="#FFEBEE", edgecolor="#D32F2F", lw=0.6))
    
    ax2.set_xticks(xm)
    ax2.set_xticklabels([m["short"] for m in MODELS], fontsize=7.2)
    ax2.set_ylabel("Dual-Exposure ASR (%)", fontsize=8.0)
    ax2.set_ylim(-2, 128)
    ax2.set_yticks([0, 20, 40, 60, 80, 100])
    ax2.grid(axis='y', alpha=0.35)
    ax2.set_title(r"(b) Syntactic-Order Bypass (Linear Collapse)", fontsize=8.5, weight='bold', pad=4)
    ax2.legend(loc="upper right", frameon=True, framealpha=0.92, edgecolor='none', fontsize=6.3, handletextpad=0.25)
    
    for a in [ax1, ax2]:
        a.spines['top'].set_visible(False)
        a.spines['right'].set_visible(False)
    
    fig.subplots_adjust(left=0.08, right=0.98, top=0.88, bottom=0.16, wspace=0.30)
    save_fig(fig, "fig_rq2_batch_mechanisms")

# ==============================================================================
# FIGURE 2: RQ3 Slice E1 - Replanning Hurdle & Stacked Token Breakdown (Single Column, 3.33in)
# ==============================================================================
def plot_figure_2_rq3_e1_hurdle(data):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(3.33, 3.35), sharex=True)
    
    xm = np.arange(len(MODELS))
    bw = 0.34
    
    # --- (a) Replan_1 (%) across ALL 5 MODELS: Visible (403) vs MTM Masked ---
    y_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["replan_1_rate_pct"]["visible_403"] for m in MODELS]
    y_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["replan_1_rate_pct"]["mtm_masked"] for m in MODELS]
    
    ax1.bar(xm - bw/2, y_403, width=bw, label="Visible Schema (403)", color="#D32F2F", hatch="//", alpha=0.88, edgecolor='black', linewidth=0.5)
    ax1.bar(xm + bw/2, y_mtm, width=bw, label="MTM Masked (Pruned)", color="#2E7D32", alpha=0.88, edgecolor='black', linewidth=0.5)
    
    ax1.set_ylabel(r"Pass-1 $\mathrm{Replan}_1$ (%)", fontsize=7.8)
    ax1.set_ylim(-2, 134)
    ax1.set_yticks([0, 20, 40, 60, 80, 100])
    ax1.grid(axis='y', alpha=0.35)
    ax1.set_title(r"(a) Pass-1 Replanning ($\mathrm{Replan}_1, R=0$)", fontsize=7.4, weight='bold', pad=3)
    ax1.legend(loc="upper right", frameon=True, framealpha=0.92, edgecolor='none', fontsize=5.8, ncol=2, handletextpad=0.25, columnspacing=0.5)
    
    # Merged centered annotation with two arrows to Gemini and Qwen
    x_mid = 0.5 + bw/2
    ax1.annotate("+20% Ghost recovery\n(100% staging)", xy=(0 + bw/2, 82), xytext=(x_mid + 0.18, 96),
                fontsize=5.0, ha='center', weight='bold', color='#1B5E20',
                arrowprops=dict(arrowstyle="->", lw=0.6, color='#2E7D32'))
    ax1.annotate("", xy=(1 + bw/2, 82), xytext=(x_mid + 0.18, 96),
                arrowprops=dict(arrowstyle="->", lw=0.6, color='#2E7D32'))
    
    # --- (b) Token Consumption by Category (Mean Stacked Sub-bars: Additivity Preserved) ---
    bw_b = 0.34
    c_403_unc = '#EF9A9A'
    c_403_cac = '#FFCDD2'
    c_403_out = '#C62828'
    
    c_mtm_unc = '#A5D6A7'
    c_mtm_cac = '#C8E6C9'
    c_mtm_out = '#2E7D32'
    
    unc_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["visible_403"]["uncached_input"] for m in MODELS]
    cac_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["visible_403"]["cached_input"] for m in MODELS]
    out_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["visible_403"]["output_reasoning"] for m in MODELS]
    
    unc_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["mtm_masked"]["uncached_input"] for m in MODELS]
    cac_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["mtm_masked"]["cached_input"] for m in MODELS]
    out_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["mtm_masked"]["output_reasoning"] for m in MODELS]
    
    # 403 Stacked Bar (Left)
    ax2.bar(xm - bw_b/2, unc_403, width=bw_b, color=c_403_unc, edgecolor='black', linewidth=0.45)
    ax2.bar(xm - bw_b/2, cac_403, width=bw_b, bottom=unc_403, color=c_403_cac, edgecolor='black', linewidth=0.45, hatch='...')
    bot_403 = [u + c for u, c in zip(unc_403, cac_403)]
    ax2.bar(xm - bw_b/2, out_403, width=bw_b, bottom=bot_403, color=c_403_out, edgecolor='black', linewidth=0.45, hatch='//')
    
    # MTM Stacked Bar (Right)
    ax2.bar(xm + bw_b/2, unc_mtm, width=bw_b, color=c_mtm_unc, edgecolor='black', linewidth=0.45)
    ax2.bar(xm + bw_b/2, cac_mtm, width=bw_b, bottom=unc_mtm, color=c_mtm_cac, edgecolor='black', linewidth=0.45, hatch='...')
    bot_mtm = [u + c for u, c in zip(unc_mtm, cac_mtm)]
    ax2.bar(xm + bw_b/2, out_mtm, width=bw_b, bottom=bot_mtm, color=c_mtm_out, edgecolor='black', linewidth=0.45, hatch='//')
    
    ax2.set_xticks(xm)
    ax2.set_xticklabels([m["short"] for m in MODELS], fontsize=7.2, rotation=20, ha='right')
    ax2.set_ylabel("Tokens / Episode (Mean)", fontsize=7.8)
    ax2.set_ylim(0, 3550)
    ax2.grid(axis='y', alpha=0.35)
    ax2.set_title("(b) Token Consumption by Category (Mean)", fontsize=8.2, weight='bold', pad=3)
    
    legend_elements = [
        Patch(facecolor='#D32F2F', edgecolor='black', lw=0.45, label='403 (Refusal)'),
        Patch(facecolor='#2E7D32', edgecolor='black', lw=0.45, label='MTM (Pruned)'),
        Patch(facecolor='#B0BEC5', edgecolor='black', lw=0.45, label='Uncached In'),
        Patch(facecolor='#ECEFF1', hatch='....', edgecolor='black', lw=0.45, label='Cached In (KV)'),
        Patch(facecolor='#546E7A', hatch='///', edgecolor='black', lw=0.45, label='Output / Reasoning')
    ]
    ax2.legend(handles=legend_elements, loc='upper right', ncol=2, fontsize=5.9,
               handleheight=1.15, handlelength=1.8, handletextpad=0.35, columnspacing=0.6,
               frameon=True, framealpha=0.92, edgecolor='none')
    
    for a in [ax1, ax2]:
        a.spines['top'].set_visible(False)
        a.spines['right'].set_visible(False)
    
    fig.tight_layout()
    save_fig(fig, "fig_rq3_e1_hurdle")

# ==============================================================================
# FIGURE 3: RQ3 Limits & Systems FinOps across ALL 5 MODELS (Double Column, 7.05in)
# ==============================================================================
def plot_figure_3_rq3_limits_and_tradeoffs(data):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(7.05, 2.45), sharex=True)
    depths = [1, 2, 4, 5, 8, 10]
    
    # --- (a) First-Pass Safe Staging Replanning (Replan_1) across Depth k ---
    for m in MODELS:
        replan_rates = [data[m["id"]]["rq3_e2_replan_1_rate_pct"][f"k{k}"] for k in depths]
        ax1.plot(depths, replan_rates, marker=m["marker"], linestyle=m["linestyle"],
                 label=f"{m['short']}", color=m["color"], lw=1.2, markersize=3.8)
    
    ax1.set_ylabel(r"Pass-1 $\mathrm{Replan}_1$ (%)", fontsize=7.6)
    ax1.set_xlabel(r"Revocation Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.6)
    ax1.set_xticks(depths)
    ax1.set_ylim(-2, 105)
    ax1.grid(True, alpha=0.35)
    ax1.set_title(r"(a) Pass-1 Staging ($\mathrm{Replan}_1$)", fontsize=7.2, weight='bold', pad=3)
    
    # Subtle annotation on Gemini's inertia erosion
    ax1.annotate("Gemini: 100% -> 50%\n(Inertia erosion)", xy=(10, 50), xytext=(5.8, 28),
                 arrowprops=dict(facecolor='#1f77b4', arrowstyle='->', lw=0.6),
                 fontsize=5.2, weight='bold', color='#1f77b4',
                 bbox=dict(boxstyle="round,pad=0.18", facecolor="#E3F2FD", edgecolor="#1f77b4", lw=0.4))
    
    # --- (b) Out-of-Schema Ghost Calls Induced by Prior Context History ---
    for m in MODELS:
        ghost_rates = [data[m["id"]]["rq3_e2_attention_inertia_ghost_calls"][f"k{k}"] for k in depths]
        ax2.plot(depths, ghost_rates, marker=m["marker"], linestyle=m["linestyle"],
                 label=f"{m['short']}", color=m["color"], lw=1.2, markersize=3.8)
    
    ax2.axhline(0.0, color='black', linestyle='-', lw=1.1, label=r"$\mathcal{V}_{\mathrm{chk}}$ Barrier ($0\%$)")
    ax2.set_ylabel("Ghost Calls (%)", fontsize=7.6)
    ax2.set_xlabel(r"Revocation Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.6)
    ax2.set_xticks(depths)
    ax2.set_ylim(-2, 72)
    ax2.grid(True, alpha=0.35)
    ax2.set_title(r"(b) History Ghost Calls", fontsize=7.2, weight='bold', pad=3)
    ax2.legend(loc="upper left", frameon=True, framealpha=0.92, edgecolor='none', fontsize=5.4, ncol=2, handletextpad=0.25, columnspacing=0.45)
    
    # --- (c) FinOps Net Cost Delta: Cost_403 - Cost_MTM across ALL 5 MODELS & ALL 6 DEPTHS ---
    ax3.axhline(0.0, color='black', linestyle='-', lw=1.0)
    ax3.axhspan(0, 0.35, color='#E8F5E9', alpha=0.45)
    ax3.axhspan(-0.20, 0, color='#FFEBEE', alpha=0.45)
    
    for m in MODELS:
        diffs = [data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["net_savings_delta_usd_per_1k"] for k in depths]
        ax3.plot(depths, diffs, marker=m["marker"], linestyle=m["linestyle"],
                 label=f"{m['short']}", color=m["color"], lw=1.2, markersize=3.8)
    
    ax3.set_xlabel(r"Revocation Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.6)
    ax3.set_ylabel(r"Net Savings: $\Delta \mathrm{Cost}$ (\$ / 1k Ep.)", fontsize=7.6)
    ax3.set_xticks(depths)
    ax3.set_ylim(-0.19, 0.34)
    ax3.grid(True, alpha=0.35)
    ax3.set_title(r"(c) FinOps Net Delta ($\Delta\mathrm{Cost}$)", fontsize=7.2, weight='bold', pad=3)
    
    # Subtle caption clarifying token cost basis
    ax3.text(0.98, 0.03, "Includes: Uncached + Cached + Output", transform=ax3.transAxes,
             fontsize=5.0, ha='right', va='bottom', color='#444444',
             bbox=dict(boxstyle='round,pad=0.14', facecolor='white', alpha=0.90, edgecolor='#CCCCCC', lw=0.4))
    
    for a in [ax1, ax2, ax3]:
        a.spines['top'].set_visible(False)
        a.spines['right'].set_visible(False)
    
    fig.subplots_adjust(left=0.07, right=0.98, top=0.88, bottom=0.18, wspace=0.40)
    save_fig(fig, "fig_rq3_limits_and_tradeoffs")

# ==============================================================================
# FIGURE 4 (APPENDIX): RQ3 Slice E3 - Action Redistribution across ALL 5 MODELS
# ==============================================================================
def plot_figure_appendix_fallbacks(data):
    fig, axes = plt.subplots(3, 1, figsize=(3.33, 5.2), sharex=True)
    
    topologies = [
        ("F1_staging", r"(a) Topology $F_1$: Safe Staging Available"),
        ("F2_nearmiss", r"(b) Topology $F_2$: Near-Miss Synonym (Assumption $\mathcal{L}$)"),
        ("F3_nofallback", r"(c) Topology $F_3$: No Fallback Actuators Available")
    ]
    
    models_rev = list(reversed(MODELS))
    model_names = [m["short"] for m in models_rev]
    y_pos = np.arange(len(models_rev))
    bh = 0.62
    
    for idx, (topo_key, title) in enumerate(topologies):
        ax = axes[idx]
        staging_vals = [data[m["id"]]["rq3_e3_fallback_action_space"][topo_key]["safe_staging_pct"] for m in models_rev]
        nearmiss_vals = [data[m["id"]]["rq3_e3_fallback_action_space"][topo_key]["nearmiss_synonym_pct"] for m in models_rev]
        text_vals = [data[m["id"]]["rq3_e3_fallback_action_space"][topo_key]["plain_text_abstention_pct"] for m in models_rev]
        ghost_vals = [data[m["id"]]["rq3_e3_fallback_action_space"][topo_key]["ghost_calls_intercepted_pct"] for m in models_rev]
        
        s = np.array(staging_vals)
        nm = np.array(nearmiss_vals)
        txt = np.array(text_vals)
        gh = np.array(ghost_vals)
        
        ax.barh(y_pos, s, height=bh, label=r"Safe Staging ($t_{\mathrm{stage}}$)" if idx == 0 else "",
                color="#2E7D32", alpha=0.88, edgecolor='black', linewidth=0.5)
        ax.barh(y_pos, nm, height=bh, left=s, label=r"Near-Miss Synonym ($t_{\mathrm{nearmiss}}$)" if idx == 0 else "",
                color="#D32F2F", hatch="//", alpha=0.88, edgecolor='black', linewidth=0.5)
        ax.barh(y_pos, txt, height=bh, left=s+nm, label="Plain-Text Abstention" if idx == 0 else "",
                color="#1976D2", alpha=0.85, edgecolor='black', linewidth=0.5)
        ax.barh(y_pos, gh, height=bh, left=s+nm+txt, label=r"Ghost Call ($\mathcal{V}_{\mathrm{chk}}$ Intercepted)" if idx == 0 else "",
                color="#78909C", alpha=0.8, edgecolor='black', linewidth=0.5)
        
        ax.set_yticks(y_pos)
        ax.set_yticklabels(model_names, fontsize=7.2)
        ax.set_xlim(0, 105)
        ax.grid(axis='x', alpha=0.35)
        ax.set_title(title, fontsize=7.2, weight='bold', pad=3)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
    
    axes[2].set_xlabel("Probability Mass (%)", fontsize=8.0)
    
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='lower center', bbox_to_anchor=(0.5, 0.94),
               ncol=2, frameon=True, framealpha=0.92, edgecolor='none', fontsize=6.6)
    
    fig.subplots_adjust(top=0.86, bottom=0.07, hspace=0.38, left=0.22, right=0.96)
    save_fig(fig, "fig_app_e3_fallbacks")

# ==============================================================================
# FIGURE 5 (APPENDIX): RQ3 Slice E4 - Raw Token Deltas across ALL 6 Depths k
# Decomposes Net Savings into: Uncached In, Cached In (KV), Output / Reasoning
# ==============================================================================
def plot_figure_appendix_token_deltas(data):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(7.05, 2.50), gridspec_kw={'wspace': 0.28})
    k_vals = [1, 2, 4, 5, 8, 10]
    
    for m in MODELS:
        m_id = m["id"]
        d_unc = [data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_uncached_tokens"] for k in k_vals]
        d_cac = [data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_cached_tokens"] for k in k_vals]
        d_out = [data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_output_tokens"] for k in k_vals]
        
        ax1.plot(k_vals, d_unc, marker=m["marker"], linestyle=m["linestyle"], color=m["color"], lw=1.2, label=m["short"])
        ax2.plot(k_vals, d_cac, marker=m["marker"], linestyle=m["linestyle"], color=m["color"], lw=1.2, label=m["short"])
        ax3.plot(k_vals, d_out, marker=m["marker"], linestyle=m["linestyle"], color=m["color"], lw=1.2, label=m["short"])
    
    # Subplot 1: Uncached In Delta
    ax1.axhline(0, color='black', lw=0.9)
    ax1.axhspan(0, 2100, color='#E8F5E9', alpha=0.35)
    ax1.axhspan(-2400, 0, color='#FFEBEE', alpha=0.35)
    ax1.set_title(r'(a) $\Delta$ Uncached In Tokens', fontsize=8.2, weight='bold', pad=3)
    ax1.set_ylabel(r'Token Delta ($N_{403} - N_{\mathrm{MTM}}$)', fontsize=7.8)
    ax1.set_xlabel(r'Depth $k_{\mathrm{mask}}$ (Turns)', fontsize=7.6)
    ax1.set_xticks(k_vals)
    ax1.set_ylim(-2350, 2050)
    ax1.grid(True, alpha=0.3)
    ax1.text(0.04, 0.06, 'MTM uses more uncached\n(Prefix cache invalidated)', transform=ax1.transAxes, fontsize=5.5,
             bbox=dict(boxstyle='round,pad=0.2', facecolor='white', alpha=0.88, edgecolor='#CCCCCC', lw=0.4))
    
    # Subplot 2: Cached In (KV) Delta
    ax2.axhline(0, color='black', lw=0.9)
    ax2.axhspan(0, 5600, color='#E8F5E9', alpha=0.35)
    ax2.set_title(r'(b) $\Delta$ Cached In (KV) Tokens', fontsize=8.2, weight='bold', pad=3)
    ax2.set_xlabel(r'Depth $k_{\mathrm{mask}}$ (Turns)', fontsize=7.6)
    ax2.set_xticks(k_vals)
    ax2.set_ylim(-200, 5550)
    ax2.grid(True, alpha=0.3)
    ax2.text(0.04, 0.80, '403 burns more cached\n(Retries on intact cache)', transform=ax2.transAxes, fontsize=5.5,
             bbox=dict(boxstyle='round,pad=0.2', facecolor='white', alpha=0.88, edgecolor='#CCCCCC', lw=0.4))
    
    # Subplot 3: Output / Reasoning Delta
    ax3.axhline(0, color='black', lw=0.9)
    ax3.axhspan(0, 260, color='#E8F5E9', alpha=0.35)
    ax3.axhspan(-190, 0, color='#FFEBEE', alpha=0.35)
    ax3.set_title(r'(c) $\Delta$ Output / Reasoning Tokens', fontsize=8.2, weight='bold', pad=3)
    ax3.set_xlabel(r'Depth $k_{\mathrm{mask}}$ (Turns)', fontsize=7.6)
    ax3.set_xticks(k_vals)
    ax3.set_ylim(-185, 255)
    ax3.grid(True, alpha=0.3)
    ax3.text(0.04, 0.05, '403 burns output decode\n(Retry explanations)', transform=ax3.transAxes, fontsize=5.5,
             bbox=dict(boxstyle='round,pad=0.2', facecolor='white', alpha=0.88, edgecolor='#CCCCCC', lw=0.4))
    ax3.legend(loc='upper right', fontsize=6.0, ncol=2, handletextpad=0.3, columnspacing=0.5, frameon=True, framealpha=0.92, edgecolor='none')
    
    for a in [ax1, ax2, ax3]:
        a.spines['top'].set_visible(False)
        a.spines['right'].set_visible(False)
    
    fig.subplots_adjust(left=0.08, right=0.98, top=0.88, bottom=0.18, wspace=0.28)
    save_fig(fig, "fig_app_e4_token_deltas")

# ==============================================================================
# FIGURE 6 (APPENDIX): RQ3 Slice E4 - Standardized vs Live Catalog FinOps
# ==============================================================================
def plot_figure_appendix_catalog_finops(data):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.05, 2.50), sharex=True)
    depths = [1, 2, 4, 5, 8, 10]

    # --- (a) Normalized Reference Tier ($c_in = $0.10/M) ---
    ax1.axhline(0.0, color='black', linestyle='-', lw=1.0)
    ax1.axhspan(0, 0.35, color='#E8F5E9', alpha=0.45)
    ax1.axhspan(-0.20, 0, color='#FFEBEE', alpha=0.45)

    for m in MODELS:
        diffs = [data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["net_savings_delta_usd_per_1k"] for k in depths]
        ax1.plot(depths, diffs, marker=m["marker"], linestyle=m["linestyle"],
                 label=f"{m['short']}", color=m["color"], lw=1.2, markersize=3.8)

    ax1.set_xlabel(r"Revocation Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.6)
    ax1.set_ylabel(r"Net Savings: $\Delta \mathrm{Cost}$ (\$ / 1k Ep.)", fontsize=7.6)
    ax1.set_xticks(depths)
    ax1.set_ylim(-0.19, 0.34)
    ax1.grid(True, alpha=0.35)
    ax1.set_title(r"(a) Standardized Reference Tier ($c_{\mathrm{in}}=\$0.10/\mathrm{M}$)", fontsize=8.0, weight='bold', pad=3)
    ax1.text(0.98, 0.04, "Crossover at $k^\\star \\approx 4$\u2013$5$", transform=ax1.transAxes,
             fontsize=5.2, ha='right', va='bottom', color='#333333',
             bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.90, edgecolor='#CCCCCC', lw=0.4))

    # --- (b) Live Commercial Provider Catalog Pricing ---
    ax2.axhline(0.0, color='black', linestyle='-', lw=1.0)
    ax2.axhspan(0, 0.65, color='#E8F5E9', alpha=0.45)
    ax2.axhspan(-0.20, 0, color='#FFEBEE', alpha=0.45)

    for m in MODELS:
        diffs_cat = [data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["catalog_net_savings_delta_usd_per_1k"] for k in depths]
        ax2.plot(depths, diffs_cat, marker=m["marker"], linestyle=m["linestyle"],
                 label=f"{m['short']}", color=m["color"], lw=1.2, markersize=3.8)

    ax2.set_xlabel(r"Revocation Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.6)
    ax2.set_ylabel(r"Net Savings: $\Delta \mathrm{Cost}$ (\$ / 1k Ep.)", fontsize=7.6)
    ax2.set_xticks(depths)
    ax2.set_ylim(-0.19, 0.60)
    ax2.grid(True, alpha=0.35)
    ax2.set_title(r"(b) Live Provider Catalog Billing (Cloud APIs & Edge)", fontsize=8.0, weight='bold', pad=3)
    ax2.legend(loc="upper left", frameon=True, framealpha=0.92, edgecolor='none', fontsize=5.8, ncol=2)

    # Annotations on Gemini & Qwen
    ax2.annotate("Gemini: +$0.27 \u2192 +$0.52/1k\n(2.7x amplified savings)", xy=(10, 0.52), xytext=(5.6, 0.44),
                 parse_math=False,
                 arrowprops=dict(facecolor='#1f77b4', arrowstyle='->', lw=0.6),
                 fontsize=5.2, weight='bold', color='#1f77b4',
                 bbox=dict(boxstyle="round,pad=0.18", facecolor="#E3F2FD", edgecolor="#1f77b4", lw=0.4))

    ax2.annotate("Qwen: $0.00 (Local)", xy=(10, 0.0), xytext=(6.5, -0.12),
                 arrowprops=dict(facecolor='#ff7f0e', arrowstyle='->', lw=0.6),
                 fontsize=5.2, weight='bold', color='#ff7f0e',
                 bbox=dict(boxstyle="round,pad=0.18", facecolor="#FFF3E0", edgecolor="#ff7f0e", lw=0.4))

    for a in [ax1, ax2]:
        a.spines['top'].set_visible(False)
        a.spines['right'].set_visible(False)

    fig.subplots_adjust(left=0.08, right=0.98, top=0.88, bottom=0.18, wspace=0.28)
    save_fig(fig, "fig_app_e4_catalog_finops")

def _wilson_ci(k, n, z=1.96):
    import math
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + (z * z) / (4.0 * n)) / n)) / denom
    return max(0.0, center - half), min(1.0, center + half)

def _newcombe_wilson_diff_ci(k1, n1, k2, n2, z=1.96):
    import math
    p1, p2 = k1 / n1, k2 / n2
    l1, u1 = _wilson_ci(k1, n1, z)
    l2, u2 = _wilson_ci(k2, n2, z)
    diff = p1 - p2
    lo = diff - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    hi = diff + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return diff * 100.0, lo * 100.0, hi * 100.0

def plot_figure_appendix_forest():
    import glob
    import json
    from matplotlib.patches import Patch

    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    rq3_files = sorted(glob.glob(os.path.join(results_dir, "rq3_four_axes_*.json")))
    if not rq3_files:
        print("[!] Skipping fig_app_e1_forest: no rq3_four_axes_*.json found", flush=True)
        return

    archetypes = [
        ("sql_execution", "SQL Injection / Exec\n(exec:code)  (n=20)"),
        ("file_destruction", "Data Destruction\n(write:destructive)  (n=20)"),
        ("cloud_iam_share", "Cloud IAM Escalation\n(iam:grant)  (n=20)"),
        ("webhook_egress", "Webhook Exfiltration\n(egress:outside)  (n=20)"),
        ("smtp_egress", "SMTP Exfiltration\n(egress:outside)  (n=20)"),
    ]

    counts = {aid: {"k1": 0, "n1": 0, "k2": 0, "n2": 0} for aid, _ in archetypes}
    for fp in rq3_files:
        with open(fp, encoding="utf-8") as f:
            raw = json.load(f)["e1_hurdle_2x2"]["raw"]
        for r in raw["ipi__masked_http403"]:
            aid = r["archetype_id"]
            if aid in counts:
                counts[aid]["n1"] += 1
                counts[aid]["k1"] += 1 if r["first_try_replan"] else 0
        for r in raw["ipi__visible_http403"]:
            aid = r["archetype_id"]
            if aid in counts:
                counts[aid]["n2"] += 1
                counts[aid]["k2"] += 1 if r["first_try_replan"] else 0

    rows = []
    for aid, label in archetypes:
        c = counts[aid]
        diff, lo, hi = _newcombe_wilson_diff_ci(c["k1"], c["n1"], c["k2"], c["n2"])
        rows.append((label, diff, lo, hi, False))

    tot_k1 = sum(c["k1"] for c in counts.values())
    tot_n1 = sum(c["n1"] for c in counts.values())
    tot_k2 = sum(c["k2"] for c in counts.values())
    tot_n2 = sum(c["n2"] for c in counts.values())
    p_diff, p_lo, p_hi = _newcombe_wilson_diff_ci(tot_k1, tot_n1, tot_k2, tot_n2)
    rows.append(("POOLED OVERALL\n(N=100, 5 Models)", p_diff, p_lo, p_hi, True))

    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    ax.axvspan(-22, 0, color="#FFEBEE", alpha=0.45, zorder=0)
    ax.axvspan(0, 102, color="#E8F5E9", alpha=0.35, zorder=0)
    ax.axvline(0, color="#424242", linestyle="--", linewidth=0.9, zorder=1)

    y_pos = list(range(len(rows)))
    for i, (label, diff, lo, hi, is_pooled) in enumerate(rows):
        color = "#1B5E20" if is_pooled else "#1f77b4"
        marker = "D" if is_pooled else "o"
        ms = 5.5 if is_pooled else 4.5
        lw = 2.0 if is_pooled else 1.2
        ax.errorbar(
            diff, i, xerr=[[diff - lo], [hi - diff]],
            fmt=marker, color=color, ecolor=color,
            elinewidth=lw, capsize=3.0, markersize=ms, zorder=3
        )
        ci_txt = f"{diff:+.1f}% [{lo:+.1f}%, {hi:+.1f}%]"
        ax.text(104, i, ci_txt, va="center", ha="left",
                fontsize=6.5, weight="bold" if is_pooled else "normal",
                color="#1B5E20" if is_pooled else "#222222")

    ax.axhline(len(rows) - 1.5, color="#BDBDBD", linestyle=":", linewidth=0.8, zorder=1)
    ax.set_yticks(y_pos)
    ax.set_yticklabels([r[0] for r in rows], fontsize=6.5)
    for ticklabel, r in zip(ax.get_yticklabels(), rows):
        if r[4]:
            ticklabel.set_fontweight("bold")
            ticklabel.set_color("#1B5E20")

    ax.set_xlim(-22, 148)
    ax.set_xticks([-20, 0, 20, 40, 60, 80, 100])
    ax.set_xlabel(r"Preserved Replan Rate Delta: $\mathrm{Replan}_1(\mathrm{MTM}) - \mathrm{Replan}_1(\mathrm{HTTP\ 403})$ (%) [95% Wilson CI]", fontsize=7.0)
    ax.set_title(r"Forest Plot: First-Turn Utility Advantage by Cyber Primitive ($N=100$)", fontsize=8.0, weight="bold", pad=22)
    ax.text(104, len(rows) - 0.58, r"$\Delta$ [95% Wilson CI]", va="bottom", ha="left", fontsize=6.5, weight="bold", color="#333333")

    legend_handles = [
        Patch(facecolor="#FFEBEE", edgecolor="#CCCCCC", label="Favors Visible 403 (<0%)"),
        Patch(facecolor="#E8F5E9", edgecolor="#CCCCCC", label="Favors MTM Masking (>0%)"),
    ]
    ax.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(0.36, 1.12),
              ncol=2, frameon=False, fontsize=6.5, handlelength=1.4, columnspacing=1.5)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="x", linestyle=":", alpha=0.4)
    fig.subplots_adjust(left=0.27, right=0.98, top=0.84, bottom=0.17)
    save_fig(fig, "fig_app_e1_forest")

def main():
    print("=" * 80, flush=True)
    print(" TTCGateway Publication Graphics Generator (USENIX Security Standard)".center(80), flush=True)
    print("=" * 80, flush=True)
    
    print("[*] Ingesting distilled evaluation metrics across ALL 5 MODELS...", flush=True)
    data = load_data()
    print("[✓] Successfully loaded distilled data across all 5 models.", flush=True)
    
    print("\n[*] Generating [MAIN BODY] Figure 1 (RQ2: Batch Elicitation & Linear Collapse)...", flush=True)
    plot_figure_1_rq2_batching(data)
    
    print("\n[*] Generating [MAIN BODY] Figure 2 (RQ3 E1: Hurdle Matrix & Token Inflation)...", flush=True)
    plot_figure_2_rq3_e1_hurdle(data)
    
    print("\n[*] Generating [MAIN BODY] Figure 3 (RQ3 Limits: Attention Inertia & KV-Cache Breakeven)...", flush=True)
    plot_figure_3_rq3_limits_and_tradeoffs(data)
    
    print("\n[*] Generating [APPENDIX] Figure 4 (RQ3 E3: Action Space Redistribution)...", flush=True)
    plot_figure_appendix_fallbacks(data)
    
    print("\n[*] Generating [APPENDIX] Figure 5 (RQ3 E4: Token Breakdown Deltas across Depth k)...", flush=True)
    plot_figure_appendix_token_deltas(data)
    
    print("\n[*] Generating [APPENDIX] Figure 6 (RQ3 E4: Normalized vs Live Catalog FinOps)...", flush=True)
    plot_figure_appendix_catalog_finops(data)

    print("\n[*] Generating [APPENDIX] Figure E1 Forest Plot...", flush=True)
    plot_figure_appendix_forest()
    
    print("\n" + "=" * 80, flush=True)
    print(f" ALL PUBLICATION FIGURES READY IN: {FIG_DIR}".center(80), flush=True)
    print("=" * 80, flush=True)

if __name__ == "__main__":
    main()

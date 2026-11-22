#!/usr/bin/env python3
"""
Generate ALL custom / fixed PREPRINT_CLEAN figures cleanly into paper/PREPRINT_CLEAN/Fig/
without modifying paper/CURRENT WORK/Fig/:
  1) fig_app_e4_total_tokens.{pdf,png}      — Aggregate Input & Overall Token Deltas (for Appendix)
  2) fig_app_e3_fallbacks_depths.{pdf,png}  — Complete 100%-stacked 3x3 Topologies x Depths {2, 5, 10} (clean KISS legend)
  3) fig_rq3_e1_hurdle.{pdf,png}            — E1 Pass-1 Replanning & Token Breakdown (fixed Panel b headroom ylim=3950)
  4) fig_app_e4_token_deltas.{pdf,png}      — E4 Split Token Deltas across Depth k (fixed top legend, zero MiMo k=4 overlap)
"""

import json
import os
import sys
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

matplotlib.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "font.size": 8.0,
    "axes.labelsize": 8.0,
    "axes.titlesize": 8.2,
    "legend.fontsize": 6.4,
    "xtick.labelsize": 7.0,
    "ytick.labelsize": 7.0,
    "lines.linewidth": 1.25,
    "lines.markersize": 4.0,
    "axes.linewidth": 0.8,
    "grid.linewidth": 0.5,
    "grid.alpha": 0.35,
    "grid.linestyle": "--",
    "axes.edgecolor": "#333333",
    "axes.labelcolor": "#111111",
    "xtick.color": "#111111",
    "ytick.color": "#111111",
    "figure.autolayout": False,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
SUMMARY_PATH = os.path.join(RESULTS_DIR, "clean_evaluation_summary.json")
PREPRINT_DIR = os.path.join(BASE_DIR, "paper", "PREPRINT_CLEAN")
if os.path.isdir(PREPRINT_DIR):
    FIG_DIR = os.path.join(PREPRINT_DIR, "Fig")
else:
    FIG_DIR = os.path.join(RESULTS_DIR, "figures")
os.makedirs(FIG_DIR, exist_ok=True)

MODELS = [
    {"id": "gemini-3.1-flash-lite", "short": "Gemini", "color": "#1F77B4", "marker": "o", "linestyle": "-"},
    {"id": "qwen3.5:9b", "short": "Qwen", "color": "#FF7F0E", "marker": "s", "linestyle": "-"},
    {"id": "z-ai/glm-5.3-flash", "short": "GLM", "color": "#2CA02C", "marker": "d", "linestyle": ":"},
    {"id": "xiaomi/mimo-v2.6-flash", "short": "MiMo", "color": "#9467BD", "marker": "^", "linestyle": "-"},
    {"id": "deepseek/deepseek-v4.1-flash", "short": "DeepSeek", "color": "#D62728", "marker": "x", "linestyle": "--"},
]


def save_both(fig, base_name):
    for ext, kwargs in [("pdf", {}), ("png", {"dpi": 300})]:
        out_path = os.path.join(FIG_DIR, f"{base_name}.{ext}")
        fig.savefig(out_path, format=ext, bbox_inches="tight", pad_inches=0.04, **kwargs)
    plt.close(fig)
    print(f"[OK] Saved {base_name}.pdf/.png", flush=True)


def plot_total_tokens(data):
    """Single-column Appendix figure for Total Input Token Savings (Overall is in main Fig. 3c)."""
    k_vals = [1, 2, 4, 5, 8, 10]
    fig, ax = plt.subplots(figsize=(3.55, 2.35))

    ylo, yhi = -150.0, 3550.0
    ax.axhline(0, color="black", lw=0.9)
    ax.axhspan(0, yhi + 50, color="#E8F5E9", alpha=0.35)
    ax.axhspan(ylo - 50, 0, color="#FFEBEE", alpha=0.35)

    for m in MODELS:
        m_id = m["id"]
        d_in = [
            float(data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_uncached_tokens"])
            + float(data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_cached_tokens"])
            for k in k_vals
        ]
        ax.plot(k_vals, d_in, marker=m["marker"], linestyle=m["linestyle"],
                color=m["color"], label=m["short"], lw=1.25, markersize=3.8)

    ax.set_title("Total Input Token Savings (Uncached + Cached)", fontsize=7.8, weight="bold", pad=4)
    ax.set_xlabel(r"Revocation Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.6)
    ax.set_ylabel(r"Input Token Delta ($N_{403} - N_{\mathrm{MTM}}$, Mean)", fontsize=7.6)
    ax.set_xticks(k_vals)
    ax.set_ylim(ylo, yhi)
    ax.grid(True, alpha=0.35)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper left", frameon=True, framealpha=0.92, edgecolor="none", fontsize=5.8, ncol=2)
    ax.text(
        0.03, 0.62, "Saves +202 to +3,080 input tok.\nacross all depths",
        transform=ax.transAxes, fontsize=5.3, weight="bold", color="#2E7D32",
        bbox=dict(boxstyle="round,pad=0.18", facecolor="white", alpha=0.92, edgecolor="#A5D6A7", lw=0.4),
    )

    fig.subplots_adjust(left=0.17, right=0.98, top=0.88, bottom=0.18)
    save_both(fig, "fig_app_e4_total_tokens")


def plot_e1_hurdle_fixed(data):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(3.38, 3.65), sharex=True, gridspec_kw={"hspace": 0.25})
    xm = np.arange(len(MODELS))
    bw = 0.36

    y_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["replan_1_rate_pct"]["visible_403"] for m in MODELS]
    y_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["replan_1_rate_pct"]["mtm_masked"] for m in MODELS]

    ax1.bar(xm - bw / 2, y_403, width=bw, label="Visible Schema (403)", color="#D32F2F", hatch="//", alpha=0.88, edgecolor="black", linewidth=0.5)
    ax1.bar(xm + bw / 2, y_mtm, width=bw, label="Tool Masking (MTM)", color="#2E7D32", alpha=0.88, edgecolor="black", linewidth=0.5)

    ax1.set_ylabel(r"First-Try Replan ($\mathrm{Replan}_1$, %)", fontsize=7.6)
    ax1.set_ylim(-2, 134)
    ax1.set_yticks([0, 20, 40, 60, 80, 100])
    ax1.grid(axis="y", alpha=0.35)
    ax1.set_title(r"(a) First-Try Safe Replanning ($k_{\mathrm{mask}}=2$, $R=0$)", fontsize=7.4, weight="bold", pad=3)
    ax1.legend(loc="upper right", frameon=True, framealpha=0.92, edgecolor="none", fontsize=5.8, ncol=2, handletextpad=0.25, columnspacing=0.5)

    x_mid = 0.5 + bw / 2
    ax1.annotate("+20% after 1 retry\n(100% staging)", xy=(0 + bw / 2, 82), xytext=(x_mid + 0.18, 96),
                 fontsize=5.0, ha="center", weight="bold", color="#1B5E20",
                 arrowprops=dict(arrowstyle="->", lw=0.6, color="#2E7D32"))
    ax1.annotate("", xy=(1 + bw / 2, 82), xytext=(x_mid + 0.18, 96),
                 arrowprops=dict(arrowstyle="->", lw=0.6, color="#2E7D32"))

    bw_b = 0.34
    unc_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["visible_403"]["uncached_input"] for m in MODELS]
    cac_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["visible_403"]["cached_input"] for m in MODELS]
    out_403 = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["visible_403"]["output_reasoning"] for m in MODELS]
    unc_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["mtm_masked"]["uncached_input"] for m in MODELS]
    cac_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["mtm_masked"]["cached_input"] for m in MODELS]
    out_mtm = [data[m["id"]]["rq3_e1_hurdle_matrix"]["token_breakdown_mean"]["mtm_masked"]["output_reasoning"] for m in MODELS]

    ax2.bar(xm - bw_b / 2, unc_403, width=bw_b, color="#EF9A9A", edgecolor="black", linewidth=0.45)
    ax2.bar(xm - bw_b / 2, cac_403, width=bw_b, bottom=unc_403, color="#FFCDD2", edgecolor="black", linewidth=0.45, hatch="...")
    ax2.bar(xm - bw_b / 2, out_403, width=bw_b, bottom=[u + c for u, c in zip(unc_403, cac_403)], color="#C62828", edgecolor="black", linewidth=0.45, hatch="//")

    ax2.bar(xm + bw_b / 2, unc_mtm, width=bw_b, color="#A5D6A7", edgecolor="black", linewidth=0.45)
    ax2.bar(xm + bw_b / 2, cac_mtm, width=bw_b, bottom=unc_mtm, color="#C8E6C9", edgecolor="black", linewidth=0.45, hatch="...")
    ax2.bar(xm + bw_b / 2, out_mtm, width=bw_b, bottom=[u + c for u, c in zip(unc_mtm, cac_mtm)], color="#2E7D32", edgecolor="black", linewidth=0.45, hatch="//")

    ax2.set_xticks(xm)
    ax2.set_xticklabels([m["short"] for m in MODELS], fontsize=7.0, rotation=18, ha="right")
    ax2.set_ylabel("Tokens / Episode (Mean)", fontsize=7.6)
    ax2.set_ylim(0, 3950)
    ax2.set_yticks([0, 1000, 2000, 3000])
    ax2.grid(axis="y", alpha=0.35)
    ax2.set_title("(b) Mean Token Consumption by Category", fontsize=7.6, weight="bold", pad=3)

    legend_elements = [
        Patch(facecolor="#D32F2F", edgecolor="black", lw=0.45, label="403 (Refusal)"),
        Patch(facecolor="#2E7D32", edgecolor="black", lw=0.45, label="MTM (Masking)"),
        Patch(facecolor="#B0BEC5", edgecolor="black", lw=0.45, label="Uncached In"),
        Patch(facecolor="#ECEFF1", hatch="....", edgecolor="black", lw=0.45, label="Cached In (KV)"),
        Patch(facecolor="#546E7A", hatch="///", edgecolor="black", lw=0.45, label="Output / Reasoning"),
    ]
    ax2.legend(handles=legend_elements, loc="upper right", ncol=2, fontsize=5.7,
               handleheight=1.1, handlelength=1.7, handletextpad=0.35, columnspacing=0.6,
               frameon=True, framealpha=0.92, edgecolor="none")

    for a in [ax1, ax2]:
        a.spines["top"].set_visible(False)
        a.spines["right"].set_visible(False)

    fig.subplots_adjust(left=0.16, right=0.98, top=0.92, bottom=0.14, hspace=0.25)
    save_both(fig, "fig_rq3_e1_hurdle")


def plot_split_token_deltas_fixed(data):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(7.05, 2.55), gridspec_kw={"wspace": 0.28})
    k_vals = [1, 2, 4, 5, 8, 10]

    for m in MODELS:
        m_id = m["id"]
        d_unc = [data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_uncached_tokens"] for k in k_vals]
        d_cac = [data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_cached_tokens"] for k in k_vals]
        d_out = [data[m_id]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_output_tokens"] for k in k_vals]
        ax1.plot(k_vals, d_unc, marker=m["marker"], linestyle=m["linestyle"], color=m["color"], label=m["short"])
        ax2.plot(k_vals, d_cac, marker=m["marker"], linestyle=m["linestyle"], color=m["color"], label=m["short"])
        ax3.plot(k_vals, d_out, marker=m["marker"], linestyle=m["linestyle"], color=m["color"], label=m["short"])

    ax1.axhline(0, color="black", lw=0.9)
    ax1.axhspan(0, 2100, color="#E8F5E9", alpha=0.35)
    ax1.axhspan(-2400, 0, color="#FFEBEE", alpha=0.35)
    ax1.set_title(r"(a) $\Delta$ Uncached In Tokens", fontsize=8.0, weight="bold", pad=4)
    ax1.set_ylabel(r"Token Delta ($N_{403} - N_{\mathrm{MTM}}$)", fontsize=7.6)
    ax1.set_xlabel(r"Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.4)
    ax1.set_xticks(k_vals)
    ax1.set_ylim(-2350, 2050)
    ax1.grid(True, alpha=0.3)
    ax1.text(0.04, 0.06, "MTM uses more uncached\n(Prefix cache invalidated)", transform=ax1.transAxes, fontsize=5.4,
             bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.90, edgecolor="#CCCCCC", lw=0.4))

    ax2.axhline(0, color="black", lw=0.9)
    ax2.axhspan(0, 5600, color="#E8F5E9", alpha=0.35)
    ax2.set_title(r"(b) $\Delta$ Cached In (KV) Tokens", fontsize=8.0, weight="bold", pad=4)
    ax2.set_xlabel(r"Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.4)
    ax2.set_xticks(k_vals)
    ax2.set_ylim(-200, 5550)
    ax2.grid(True, alpha=0.3)
    ax2.text(0.04, 0.78, "403 burns more cached\n(Retries on intact cache)", transform=ax2.transAxes, fontsize=5.4,
             bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.90, edgecolor="#CCCCCC", lw=0.4))

    ax3.axhline(0, color="black", lw=0.9)
    ax3.axhspan(0, 260, color="#E8F5E9", alpha=0.35)
    ax3.axhspan(-190, 0, color="#FFEBEE", alpha=0.35)
    ax3.set_title(r"(c) $\Delta$ Output / Reasoning Tokens", fontsize=8.0, weight="bold", pad=4)
    ax3.set_xlabel(r"Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.4)
    ax3.set_xticks(k_vals)
    ax3.set_ylim(-185, 245)
    ax3.grid(True, alpha=0.3)
    ax3.text(0.04, 0.78, "403 burns output decode\n(Retry explanations)", transform=ax3.transAxes, fontsize=5.4,
             bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.90, edgecolor="#CCCCCC", lw=0.4))

    for a in [ax1, ax2, ax3]:
        a.spines["top"].set_visible(False)
        a.spines["right"].set_visible(False)

    handles, labels = ax1.get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.53, 0.995),
               ncol=5, fontsize=6.4, handlelength=1.6, handletextpad=0.35, columnspacing=0.9,
               frameon=True, framealpha=0.94, edgecolor="#CCCCCC").get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.08, right=0.98, top=0.80, bottom=0.18, wspace=0.28)
    save_both(fig, "fig_app_e4_token_deltas")


def plot_fallbacks_multi_depth(data):
    sweep_path = os.path.join(RESULTS_DIR, "rq3_e3_depths_sweep.json")
    sweep = json.load(open(sweep_path, "r", encoding="utf-8"))["models"]

    raw_by_id = {}
    for m in MODELS:
        fname = data[m["id"]]["metadata"]["rq3"]
        with open(os.path.join(RESULTS_DIR, fname), "r", encoding="utf-8") as f:
            raw_by_id[m["id"]] = json.load(f)["e3_fallback_drift"]["cells"]

    depths = [2, 5, 10]
    topologies = [
        ("F1_staging", "Topology $F_1$\nSafe Staging"),
        ("F2_nearmiss", "Topology $F_2$\nNear-Miss"),
        ("F3_nofallback", "Topology $F_3$\nNo Fallback"),
    ]
    models_rev = list(reversed(MODELS))
    model_names = [m["short"] for m in models_rev]
    y_pos = np.arange(len(models_rev))
    bh = 0.66

    fig, axes = plt.subplots(3, 3, figsize=(7.05, 3.70), sharex=True, sharey=True)
    for r_idx, (topo_key, row_title) in enumerate(topologies):
        for c_idx, k in enumerate(depths):
            ax = axes[r_idx, c_idx]
            cells = [
                raw_by_id[m["id"]][f"{topo_key}__mtm_masked"] if k == 5
                else sweep[m["id"]]["cells"][f"k{k}__{topo_key}__mtm_masked"]
                for m in models_rev
            ]
            s = np.array([c["staging_fallback_pct"] for c in cells])
            nm = np.array([c["nearmiss_transfer_pct"] for c in cells])
            txt = np.array([c["pure_text_pct"] for c in cells])
            oth = np.array([c["first_turn_action_dist_pct"]["other_tool"] for c in cells])
            gh = np.array([c["ghost_call_any_pct"] for c in cells])

            for c_val, m_obj in zip(zip(s, nm, txt, oth, gh), models_rev):
                assert abs(sum(c_val) - 100.0) < 0.2, f"Sum mismatch {m_obj['short']} k={k} {topo_key}: {sum(c_val)}"

            lbl = (r_idx == 0 and c_idx == 0)
            ax.barh(y_pos, s, height=bh, label="Safe Staging" if lbl else "",
                    color="#2E7D32", alpha=0.88, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, nm, height=bh, left=s, label="Near-Miss Synonym" if lbl else "",
                    color="#D32F2F", hatch="//", alpha=0.88, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, txt, height=bh, left=s + nm, label="Plain-Text Abstention" if lbl else "",
                    color="#1976D2", alpha=0.85, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, oth, height=bh, left=s + nm + txt, label="Other Benign Tool" if lbl else "",
                    color="#E5C494", alpha=0.92, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, gh, height=bh, left=s + nm + txt + oth, label="Ghost Call (Barrier-caught)" if lbl else "",
                    color="#78909C", alpha=0.82, edgecolor="black", linewidth=0.45)

            ax.set_xlim(0, 102)
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.grid(axis="x", alpha=0.35)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            if r_idx == 0:
                ax.set_title(rf"Active Sticky $k_{{\mathrm{{mask}}}} = {k}$", fontsize=8.0, weight="bold", pad=5)
            if c_idx == 0:
                ax.set_yticks(y_pos)
                ax.set_yticklabels(model_names, fontsize=6.8)
                ax.set_ylabel(row_title, fontsize=7.0, weight="bold", labelpad=5, multialignment="center")
            if r_idx == 2:
                ax.set_xlabel("Action Share (%)", fontsize=7.2)

    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.54, 0.995),
        ncol=5, frameon=True, framealpha=0.94, edgecolor="#CCCCCC", fontsize=6.2,
        handlelength=1.4, handletextpad=0.35, columnspacing=0.80,
    ).get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.14, right=0.99, top=0.84, bottom=0.11, wspace=0.09, hspace=0.17)
    save_both(fig, "fig_app_e3_fallbacks_depths")


def plot_e2_modes_multi_depth(data):
    raw_by_id = {}
    for m in MODELS:
        fname = data[m["id"]]["metadata"]["rq3"]
        with open(os.path.join(RESULTS_DIR, fname), "r", encoding="utf-8") as f:
            raw_by_id[m["id"]] = json.load(f)["e2_sticky_depth"]["cells"]

    depths = [2, 5, 10]
    modes = [
        ("active_sticky", "Active Sticky\n(Prior Calls)"),
        ("passive", "Passive\n(No Prior Calls)"),
        ("planned_commitment", "Planned Only\n(Text Plan)"),
    ]
    models_rev = list(reversed(MODELS))
    model_names = [m["short"] for m in models_rev]
    y_pos = np.arange(len(models_rev))
    bh = 0.66

    fig, axes = plt.subplots(3, 3, figsize=(7.05, 3.70), sharex=True, sharey=True)
    for r_idx, (mode_key, row_title) in enumerate(modes):
        for c_idx, k in enumerate(depths):
            ax = axes[r_idx, c_idx]
            cells = [raw_by_id[m["id"]][f"k{k}__{mode_key}__mtm_masked"] for m in models_rev]
            s = np.array([c["staging_fallback_pct"] for c in cells])
            txt = np.array([c["pure_text_pct"] for c in cells])
            oth = np.array([c["first_turn_action_dist_pct"]["other_tool"] for c in cells])
            gh = np.array([c["ghost_call_any_pct"] for c in cells])

            for c_val, m_obj in zip(zip(s, txt, oth, gh), models_rev):
                assert abs(sum(c_val) - 100.0) < 0.2, f"Sum mismatch {m_obj['short']} k={k} {mode_key}: {sum(c_val)}"

            lbl = (r_idx == 0 and c_idx == 0)
            ax.barh(y_pos, s, height=bh, label="Safe Staging" if lbl else "",
                    color="#2E7D32", alpha=0.88, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, txt, height=bh, left=s, label="Plain-Text Abstention" if lbl else "",
                    color="#1976D2", alpha=0.85, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, oth, height=bh, left=s + txt, label="Other Benign Tool" if lbl else "",
                    color="#E5C494", alpha=0.92, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, gh, height=bh, left=s + txt + oth, label="Ghost Call (Barrier-caught)" if lbl else "",
                    color="#78909C", alpha=0.82, edgecolor="black", linewidth=0.45)

            ax.set_xlim(0, 102)
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.grid(axis="x", alpha=0.35)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            if r_idx == 0:
                ax.set_title(rf"Depth $k_{{\mathrm{{mask}}}} = {k}$ ($F_1$ Only)", fontsize=7.8, weight="bold", pad=5)
            if c_idx == 0:
                ax.set_yticks(y_pos)
                ax.set_yticklabels(model_names, fontsize=6.8)
                ax.set_ylabel(row_title, fontsize=7.0, weight="bold", labelpad=5, multialignment="center")
            if r_idx == 2:
                ax.set_xlabel("Action Share (%)", fontsize=7.2)

    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.54, 0.995),
        ncol=4, frameon=True, framealpha=0.94, edgecolor="#CCCCCC", fontsize=6.4,
        handlelength=1.4, handletextpad=0.35, columnspacing=0.90,
    ).get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.14, right=0.99, top=0.84, bottom=0.11, wspace=0.09, hspace=0.17)
    save_both(fig, "fig_app_e2_modes_depths")


def plot_passive_fallbacks_multi_depth(data):
    psweep_path = os.path.join(RESULTS_DIR, "rq3_e3_passive_sweep.json")
    if not os.path.exists(psweep_path):
        print("[WARN] rq3_e3_passive_sweep.json missing; skipping passive 3x3 figure", flush=True)
        return
    psweep = json.load(open(psweep_path, "r", encoding="utf-8"))["models"]

    e2_by_id = {}
    for m in MODELS:
        fname = data[m["id"]]["metadata"]["rq3"]
        with open(os.path.join(RESULTS_DIR, fname), "r", encoding="utf-8") as f:
            e2_by_id[m["id"]] = json.load(f)["e2_sticky_depth"]["cells"]

    depths = [2, 5, 10]
    topologies = [
        ("F1_staging", "Topology $F_1$\nSafe Staging"),
        ("F2_nearmiss", "Topology $F_2$\nNear-Miss"),
        ("F3_nofallback", "Topology $F_3$\nNo Fallback"),
    ]
    models_rev = list(reversed(MODELS))
    model_names = [m["short"] for m in models_rev]
    y_pos = np.arange(len(models_rev))
    bh = 0.66

    fig, axes = plt.subplots(3, 3, figsize=(7.05, 3.70), sharex=True, sharey=True)
    for r_idx, (topo_key, row_title) in enumerate(topologies):
        for c_idx, k in enumerate(depths):
            ax = axes[r_idx, c_idx]
            cells = [
                e2_by_id[m["id"]][f"k{k}__passive__mtm_masked"] if topo_key == "F1_staging"
                else psweep[m["id"]]["cells"][f"k{k}__{topo_key}__mtm_masked"]
                for m in models_rev
            ]
            s = np.array([c["staging_fallback_pct"] for c in cells])
            nm = np.array([c["nearmiss_transfer_pct"] for c in cells])
            txt = np.array([c["pure_text_pct"] for c in cells])
            oth = np.array([c["first_turn_action_dist_pct"]["other_tool"] for c in cells])
            gh = np.array([c["ghost_call_any_pct"] for c in cells])

            for c_val, m_obj in zip(zip(s, nm, txt, oth, gh), models_rev):
                assert abs(sum(c_val) - 100.0) < 0.2, f"Sum mismatch passive {m_obj['short']} k={k} {topo_key}: {sum(c_val)}"

            lbl = (r_idx == 0 and c_idx == 0)
            ax.barh(y_pos, s, height=bh, label="Safe Staging" if lbl else "",
                    color="#2E7D32", alpha=0.88, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, nm, height=bh, left=s, label="Near-Miss Synonym" if lbl else "",
                    color="#D32F2F", hatch="//", alpha=0.88, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, txt, height=bh, left=s + nm, label="Plain-Text Abstention" if lbl else "",
                    color="#1976D2", alpha=0.85, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, oth, height=bh, left=s + nm + txt, label="Other Benign Tool" if lbl else "",
                    color="#E5C494", alpha=0.92, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, gh, height=bh, left=s + nm + txt + oth, label="Ghost Call (Barrier-caught)" if lbl else "",
                    color="#78909C", alpha=0.82, edgecolor="black", linewidth=0.45)

            ax.set_xlim(0, 102)
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.grid(axis="x", alpha=0.35)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            if r_idx == 0:
                ax.set_title(rf"Passive $k_{{\mathrm{{mask}}}} = {k}$", fontsize=8.0, weight="bold", pad=5)
            if c_idx == 0:
                ax.set_yticks(y_pos)
                ax.set_yticklabels(model_names, fontsize=6.8)
                ax.set_ylabel(row_title, fontsize=7.0, weight="bold", labelpad=5, multialignment="center")
            if r_idx == 2:
                ax.set_xlabel("Action Share (%)", fontsize=7.2)

    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.54, 0.995),
        ncol=5, frameon=True, framealpha=0.94, edgecolor="#CCCCCC", fontsize=6.2,
        handlelength=1.4, handletextpad=0.35, columnspacing=0.80,
    ).get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.14, right=0.99, top=0.84, bottom=0.11, wspace=0.09, hspace=0.17)
    save_both(fig, "fig_app_e3_passive_depths")


def plot_compact_f2_f3_comparison(data):
    asweep = json.load(open(os.path.join(RESULTS_DIR, "rq3_e3_depths_sweep.json"), "r", encoding="utf-8"))["models"]
    psweep = json.load(open(os.path.join(RESULTS_DIR, "rq3_e3_passive_sweep.json"), "r", encoding="utf-8"))["models"]

    cols = [
        ("F2_nearmiss", 2, r"$\mathbf{F_2}$ Near-Miss ($k=2$)"),
        ("F2_nearmiss", 10, r"$\mathbf{F_2}$ Near-Miss ($k=10$)"),
        ("F3_nofallback", 2, r"$\mathbf{F_3}$ No Fallback ($k=2$)"),
        ("F3_nofallback", 10, r"$\mathbf{F_3}$ No Fallback ($k=10$)"),
    ]
    rows = [
        (asweep, "Active Sticky\n(Prior Calls)"),
        (psweep, "Passive\n(No Prior Calls)"),
    ]
    models_rev = list(reversed(MODELS))
    model_names = [m["short"] for m in models_rev]
    y_pos = np.arange(len(models_rev))
    bh = 0.64

    fig, axes = plt.subplots(2, 4, figsize=(7.05, 2.50), sharex=True, sharey=True)
    for r_idx, (src, row_title) in enumerate(rows):
        for c_idx, (topo_key, k, col_title) in enumerate(cols):
            ax = axes[r_idx, c_idx]
            cells = [src[m["id"]]["cells"][f"k{k}__{topo_key}__mtm_masked"] for m in models_rev]
            nm = np.array([c["nearmiss_transfer_pct"] for c in cells])
            txt = np.array([c["pure_text_pct"] for c in cells])
            oth = np.array([c["first_turn_action_dist_pct"]["other_tool"] for c in cells])
            gh = np.array([c["ghost_call_any_pct"] for c in cells])

            for c_val, m_obj in zip(zip(nm, txt, oth, gh), models_rev):
                assert abs(sum(c_val) - 100.0) < 0.2, f"Compact sum mismatch {m_obj['short']} r={r_idx} k={k} {topo_key}: {sum(c_val)}"

            lbl = (r_idx == 0 and c_idx == 0)
            ax.barh(y_pos, nm, height=bh, label="Near-Miss Synonym" if lbl else "",
                    color="#D32F2F", hatch="//", alpha=0.88, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, txt, height=bh, left=nm, label="Plain-Text Abstention" if lbl else "",
                    color="#1976D2", alpha=0.85, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, oth, height=bh, left=nm + txt, label="Other Benign Tool" if lbl else "",
                    color="#E5C494", alpha=0.92, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, gh, height=bh, left=nm + txt + oth, label="Ghost Call (Barrier-caught)" if lbl else "",
                    color="#78909C", alpha=0.82, edgecolor="black", linewidth=0.45)

            ax.set_xlim(0, 102)
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.grid(axis="x", alpha=0.35)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            if r_idx == 0:
                ax.set_title(col_title, fontsize=7.2, weight="bold", pad=4)
            if c_idx == 0:
                ax.set_yticks(y_pos)
                ax.set_yticklabels(model_names, fontsize=6.6)
                ax.set_ylabel(row_title, fontsize=6.8, weight="bold", labelpad=5, multialignment="center")
            if r_idx == 1:
                ax.set_xlabel("Action Share (%)", fontsize=6.8)

    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.55, 0.995),
        ncol=4, frameon=True, framealpha=0.94, edgecolor="#CCCCCC", fontsize=6.1,
        handlelength=1.4, handletextpad=0.35, columnspacing=0.95,
    ).get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.14, right=0.99, top=0.80, bottom=0.16, wspace=0.11, hspace=0.16)
    save_both(fig, "fig_e3_f2_f3_compact")


def plot_compact_f1_active_vs_passive(data):
    asw = json.load(open(os.path.join(RESULTS_DIR, "rq3_e3_depths_sweep.json"), "r", encoding="utf-8"))["models"]
    raw_by_id = {}
    e2_by_id = {}
    for m in MODELS:
        fname = data[m["id"]]["metadata"]["rq3"]
        with open(os.path.join(RESULTS_DIR, fname), "r", encoding="utf-8") as f:
            raw_json = json.load(f)
        raw_by_id[m["id"]] = raw_json["e3_fallback_drift"]["cells"]
        e2_by_id[m["id"]] = raw_json["e2_sticky_depth"]["cells"]

    depths = [2, 5, 10]
    models_rev = list(reversed(MODELS))
    model_names = [m["short"] for m in models_rev]
    y_pos = np.arange(len(models_rev))
    bh = 0.64

    fig, axes = plt.subplots(2, 3, figsize=(7.05, 2.45), sharex=True, sharey=True)
    for r_idx, row_title in enumerate(["Active Sticky\n(Prior Calls)", "Passive\n(No Prior Calls)"]):
        for c_idx, k in enumerate(depths):
            ax = axes[r_idx, c_idx]
            if r_idx == 0:
                cells = [
                    raw_by_id[m["id"]]["F1_staging__mtm_masked"] if k == 5
                    else asw[m["id"]]["cells"][f"k{k}__F1_staging__mtm_masked"]
                    for m in models_rev
                ]
            else:
                cells = [e2_by_id[m["id"]][f"k{k}__passive__mtm_masked"] for m in models_rev]

            s = np.array([c["staging_fallback_pct"] for c in cells])
            txt = np.array([c["pure_text_pct"] for c in cells])
            oth = np.array([c["first_turn_action_dist_pct"]["other_tool"] for c in cells])
            gh = np.array([c["ghost_call_any_pct"] for c in cells])

            for c_val, m_obj in zip(zip(s, txt, oth, gh), models_rev):
                assert abs(sum(c_val) - 100.0) < 0.2, f"F1 sum mismatch {m_obj['short']} r={r_idx} k={k}: {sum(c_val)}"

            lbl = (r_idx == 0 and c_idx == 0)
            ax.barh(y_pos, s, height=bh, label="Safe Staging" if lbl else "",
                    color="#2E7D32", alpha=0.88, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, txt, height=bh, left=s, label="Plain-Text Abstention" if lbl else "",
                    color="#1976D2", alpha=0.85, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, oth, height=bh, left=s + txt, label="Other Benign Tool" if lbl else "",
                    color="#E5C494", alpha=0.92, edgecolor="black", linewidth=0.45)
            ax.barh(y_pos, gh, height=bh, left=s + txt + oth, label="Ghost Call (Barrier-caught)" if lbl else "",
                    color="#78909C", alpha=0.82, edgecolor="black", linewidth=0.45)

            ax.set_xlim(0, 102)
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.grid(axis="x", alpha=0.35)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            if r_idx == 0:
                ax.set_title(rf"$\mathbf{{F_1}}$ Safe Staging ($k={k}$)", fontsize=7.6, weight="bold", pad=4)
            if c_idx == 0:
                ax.set_yticks(y_pos)
                ax.set_yticklabels(model_names, fontsize=6.6)
                ax.set_ylabel(row_title, fontsize=6.8, weight="bold", labelpad=5, multialignment="center")
            if r_idx == 1:
                ax.set_xlabel("Action Share (%)", fontsize=6.8)

    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.55, 0.995),
        ncol=4, frameon=True, framealpha=0.94, edgecolor="#CCCCCC", fontsize=6.1,
        handlelength=1.4, handletextpad=0.35, columnspacing=0.95,
    ).get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.14, right=0.99, top=0.79, bottom=0.16, wspace=0.10, hspace=0.16)
    save_both(fig, "fig_e3_f1_compact")


def plot_rq3_limits_clean(data):
    fig, (ax1, ax2, ax3, ax4) = plt.subplots(1, 4, figsize=(7.05, 2.38), sharex=True)
    depths = [1, 2, 4, 5, 8, 10]

    # (a) Pass-1 Replanning
    for m in MODELS:
        replan_rates = [data[m["id"]]["rq3_e2_replan_1_rate_pct"][f"k{k}"] for k in depths]
        ax1.plot(depths, replan_rates, marker=m["marker"], linestyle=m["linestyle"],
                 label=f"{m['short']}", color=m["color"], lw=1.15, markersize=3.4)
    ax1.set_ylabel(r"Pass-1 $\mathrm{Replan}_1$ (%)", fontsize=7.0)
    ax1.set_ylim(-2, 105)
    ax1.set_title(r"(a) Pass-1 Staging ($\mathrm{Replan}_1$)", fontsize=6.7, weight='bold', pad=4)
    ax1.annotate("Gemini: 100% \u2192 50%", xy=(10, 50), xytext=(3.8, 22),
                 arrowprops=dict(facecolor='#1f77b4', arrowstyle='->', lw=0.6),
                 fontsize=4.9, weight='bold', color='#1f77b4',
                 bbox=dict(boxstyle="round,pad=0.16", facecolor="#E3F2FD", edgecolor="#1f77b4", lw=0.4))

    # (b) History-Induced Ghost Calls
    for m in MODELS:
        ghost_rates = [data[m["id"]]["rq3_e2_attention_inertia_ghost_calls"][f"k{k}"] for k in depths]
        ax2.plot(depths, ghost_rates, marker=m["marker"], linestyle=m["linestyle"],
                 label=f"{m['short']}", color=m["color"], lw=1.15, markersize=3.4)
    ax2.axhline(0.0, color='black', linestyle='-', lw=1.0, label="Gateway Barrier (0%)")
    ax2.set_ylabel("Ghost Calls (%)", fontsize=7.0)
    ax2.set_ylim(-2, 72)
    ax2.set_title("(b) History Ghost Calls", fontsize=6.7, weight='bold', pad=4)

    # (c) Overall Raw Token Savings (Input + Output)
    ax3.axhline(0.0, color='black', linestyle='-', lw=0.9)
    ax3.axhspan(0, 3600, color='#E8F5E9', alpha=0.45)
    ax3.axhspan(-160, 0, color='#FFEBEE', alpha=0.45)
    for m in MODELS:
        d_tot = [
            float(data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_uncached_tokens"])
            + float(data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_cached_tokens"])
            + float(data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["delta_output_tokens"])
            for k in depths
        ]
        ax3.plot(depths, d_tot, marker=m["marker"], linestyle=m["linestyle"],
                 color=m["color"], lw=1.15, markersize=3.4)
    ax3.set_ylabel(r"$\Delta N_{\mathrm{total}}$ (Tok.)", fontsize=7.0)
    ax3.set_ylim(-150, 3550)
    ax3.set_title(r"(c) Overall Token Gain ($\Delta N_{\mathrm{total}}$)", fontsize=6.7, weight='bold', pad=4)
    ax3.text(0.04, 0.80, "All depths positive\n(+219 to +3,149 tok.)", transform=ax3.transAxes,
             fontsize=4.8, weight='bold', color='#2E7D32',
             bbox=dict(boxstyle='round,pad=0.14', facecolor='white', alpha=0.90, edgecolor='#A5D6A7', lw=0.4))

    # (d) Prefix-Cached FinOps Net Delta ($/1k Ep.)
    ax4.axhline(0.0, color='black', linestyle='-', lw=0.9)
    ax4.axhspan(0, 0.35, color='#E8F5E9', alpha=0.45)
    ax4.axhspan(-0.20, 0, color='#FFEBEE', alpha=0.45)
    for m in MODELS:
        diffs = [data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["net_savings_delta_usd_per_1k"] for k in depths]
        ax4.plot(depths, diffs, marker=m["marker"], linestyle=m["linestyle"],
                 color=m["color"], lw=1.15, markersize=3.4)
    ax4.set_ylabel(r"$\Delta \mathrm{Cost}$ (\$ / 1k Ep.)", fontsize=7.0)
    ax4.set_ylim(-0.19, 0.34)
    ax4.set_title(r"(d) Net Cost Savings ($\Delta\mathrm{Cost}$)", fontsize=6.7, weight='bold', pad=4)
    ax4.text(0.97, 0.04, "KV breakeven k* \u2248 4\u20135", transform=ax4.transAxes,
             fontsize=4.8, ha='right', va='bottom', color='#333333',
             bbox=dict(boxstyle='round,pad=0.14', facecolor='white', alpha=0.90, edgecolor='#CCCCCC', lw=0.4))

    for a in [ax1, ax2, ax3, ax4]:
        a.set_xlabel(r"Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=6.8)
        a.set_xticks(depths)
        a.tick_params(axis='x', labelsize=6.0, pad=2)
        a.tick_params(axis='y', labelsize=6.2)
        a.grid(True, alpha=0.35)
        a.spines['top'].set_visible(False)
        a.spines['right'].set_visible(False)

    handles, labels = ax2.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.52, 0.995),
        ncol=6, frameon=True, framealpha=0.94, edgecolor="#CCCCCC", fontsize=5.9,
        handlelength=1.4, handletextpad=0.35, columnspacing=0.80,
    ).get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.055, right=0.99, top=0.79, bottom=0.18, wspace=0.44)
    save_both(fig, "fig_rq3_limits_and_tradeoffs")


def _draw_stacked_bars(ax, y_pos, bh, cells, add_legend_labels=False):
    """Render 100%-stacked horizontal bars across the 5 behavioral categories."""
    s = np.array([c["staging_fallback_pct"] for c in cells])
    nm = np.array([c.get("nearmiss_transfer_pct", 0.0) for c in cells])
    txt = np.array([c["pure_text_pct"] for c in cells])
    oth = np.array([c["first_turn_action_dist_pct"]["other_tool"] for c in cells])
    gh = np.array([c["ghost_call_any_pct"] for c in cells])
    for vals in zip(s, nm, txt, oth, gh):
        assert abs(sum(vals) - 100.0) < 0.2, f"Stacked share sum mismatch: {sum(vals)}"

    ax.barh(y_pos, s, height=bh, label="Safe Staging" if add_legend_labels else "",
            color="#2E7D32", alpha=0.88, edgecolor="black", linewidth=0.45)
    ax.barh(y_pos, nm, height=bh, left=s, label="Near-Miss Synonym" if add_legend_labels else "",
            color="#D32F2F", hatch="//", alpha=0.88, edgecolor="black", linewidth=0.45)
    ax.barh(y_pos, txt, height=bh, left=s + nm, label="Plain-Text Abstention" if add_legend_labels else "",
            color="#1976D2", alpha=0.85, edgecolor="black", linewidth=0.45)
    ax.barh(y_pos, oth, height=bh, left=s + nm + txt, label="Other Benign Tool" if add_legend_labels else "",
            color="#E5C494", alpha=0.92, edgecolor="black", linewidth=0.45)
    ax.barh(y_pos, gh, height=bh, left=s + nm + txt + oth, label="Ghost Call (Barrier-caught)" if add_legend_labels else "",
            color="#78909C", alpha=0.82, edgecolor="black", linewidth=0.45)

    ax.set_xlim(0, 102)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.grid(axis="x", alpha=0.35)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def plot_missing_e2_e3_slices(data):
    """Render only the 7 E2/E3 slices absent from main-body compact figures."""
    psweep = json.load(open(os.path.join(RESULTS_DIR, "rq3_e3_passive_sweep.json"), "r", encoding="utf-8"))["models"]
    raw_e2, raw_e3 = {}, {}
    for m in MODELS:
        with open(os.path.join(RESULTS_DIR, data[m["id"]]["metadata"]["rq3"]), "r", encoding="utf-8") as f:
            rj = json.load(f)
        raw_e2[m["id"]] = rj["e2_sticky_depth"]["cells"]
        raw_e3[m["id"]] = rj["e3_fallback_drift"]["cells"]

    models_rev = list(reversed(MODELS))
    model_names = [m["short"] for m in models_rev]
    y_pos = np.arange(len(models_rev))
    bh = 0.64

    fig = plt.figure(figsize=(7.05, 2.95))
    gs = fig.add_gridspec(2, 12, hspace=0.46, wspace=0.46)

    # Top row: Planned Only (F1, k = 2, 5, 10)
    ax_top_ref = None
    for idx, k in enumerate([2, 5, 10]):
        ax = fig.add_subplot(gs[0, idx * 4:(idx + 1) * 4], sharey=ax_top_ref)
        if ax_top_ref is None:
            ax_top_ref = ax
        cells = [raw_e2[m["id"]][f"k{k}__planned_commitment__mtm_masked"] for m in models_rev]
        _draw_stacked_bars(ax, y_pos, bh, cells, add_legend_labels=(idx == 0))
        ax.set_title(rf"({chr(97 + idx)}) $F_1$ Planned Only ($k={k}$)", fontsize=7.5, weight="bold", pad=4)
        if idx == 0:
            ax.set_yticks(y_pos)
            ax.set_yticklabels(model_names, fontsize=6.6)
            ax.set_ylabel("Planned Only\n($F_1$ Text Plan)", fontsize=6.8, weight="bold", labelpad=5, multialignment="center")
        else:
            ax.tick_params(labelleft=False)
        ax.tick_params(labelbottom=True, labelsize=6.5)

    # Bottom row: Intermediate depth k=5 for F2 & F3 (Active Sticky vs Passive)
    k5_specs = [
        ("F2_nearmiss", "active", r"(d) $F_2$ Active ($k=5$)"),
        ("F2_nearmiss", "passive", r"(e) $F_2$ Passive ($k=5$)"),
        ("F3_nofallback", "active", r"(f) $F_3$ Active ($k=5$)"),
        ("F3_nofallback", "passive", r"(g) $F_3$ Passive ($k=5$)"),
    ]
    for idx, (topo_key, hist_mode, title) in enumerate(k5_specs):
        ax = fig.add_subplot(gs[1, idx * 3:(idx + 1) * 3], sharey=ax_top_ref)
        if hist_mode == "active":
            cells = [raw_e3[m["id"]][f"{topo_key}__mtm_masked"] for m in models_rev]
        else:
            cells = [psweep[m["id"]]["cells"][f"k5__{topo_key}__mtm_masked"] for m in models_rev]
        _draw_stacked_bars(ax, y_pos, bh, cells, add_legend_labels=False)
        ax.set_title(title, fontsize=7.2, weight="bold", pad=4)
        ax.set_xlabel("Action Share (%)", fontsize=6.8)
        if idx == 0:
            ax.set_yticks(y_pos)
            ax.set_yticklabels(model_names, fontsize=6.6)
            ax.set_ylabel("Depth $k=5$\n($F_2$ & $F_3$)", fontsize=6.8, weight="bold", labelpad=5, multialignment="center")
        else:
            ax.tick_params(labelleft=False)
        ax.tick_params(labelsize=6.4)

    handles, labels = ax_top_ref.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.54, 0.995),
        ncol=5, frameon=True, framealpha=0.94, edgecolor="#CCCCCC", fontsize=6.1,
        handlelength=1.4, handletextpad=0.35, columnspacing=0.80,
    ).get_frame().set_linewidth(0.4)
    fig.subplots_adjust(left=0.13, right=0.985, top=0.84, bottom=0.13)
    save_both(fig, "fig_app_e2_e3_missing_slices")


def plot_catalog_finops_only(data):
    """Render single-column Live Provider Catalog Billing chart (no standardized duplicate)."""
    depths = [1, 2, 4, 5, 8, 10]
    fig, ax = plt.subplots(figsize=(3.55, 2.35))

    ax.axhline(0.0, color="black", linestyle="-", lw=1.0)
    ax.axhspan(0, 0.65, color="#E8F5E9", alpha=0.45)
    ax.axhspan(-0.20, 0, color="#FFEBEE", alpha=0.45)

    for m in MODELS:
        diffs_cat = [data[m["id"]]["rq3_e4_finops_breakeven"][f"k{k}"]["catalog_net_savings_delta_usd_per_1k"] for k in depths]
        ax.plot(depths, diffs_cat, marker=m["marker"], linestyle=m["linestyle"],
                label=m["short"], color=m["color"], lw=1.25, markersize=3.8)

    ax.set_xlabel(r"Revocation Depth $k_{\mathrm{mask}}$ (Turns)", fontsize=7.6)
    ax.set_ylabel(r"Net Savings: $\Delta\mathrm{Cost}$ (\$ / 1k Ep.)", fontsize=7.6)
    ax.set_xticks(depths)
    ax.set_ylim(-0.19, 0.60)
    ax.grid(True, alpha=0.35)
    ax.set_title("Live Provider Catalog Billing (Cloud APIs & Edge)", fontsize=7.8, weight="bold", pad=4)
    ax.legend(loc="upper left", frameon=True, framealpha=0.92, edgecolor="none", fontsize=5.8, ncol=2)

    ax.annotate("Gemini: +$0.27 \u2192 +$0.52/1k\n(2.7x amplified savings)", xy=(10, 0.52), xytext=(4.5, 0.21),
                parse_math=False,
                arrowprops=dict(facecolor="#1F77B4", arrowstyle="->", lw=0.6),
                fontsize=5.3, weight="bold", color="#1F77B4",
                bbox=dict(boxstyle="round,pad=0.18", facecolor="#E3F2FD", edgecolor="#1F77B4", lw=0.4))

    ax.annotate("Qwen: $0.00 (Local)", xy=(8, 0.0), xytext=(5.9, 0.085),
                arrowprops=dict(facecolor="#FF7F0E", arrowstyle="->", lw=0.6),
                fontsize=5.3, weight="bold", color="#FF7F0E",
                bbox=dict(boxstyle="round,pad=0.18", facecolor="#FFF3E0", edgecolor="#FF7F0E", lw=0.4))

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.subplots_adjust(left=0.17, right=0.98, top=0.88, bottom=0.18)
    save_both(fig, "fig_app_e4_catalog_finops")


def main():
    with open(SUMMARY_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)["models"]
    plot_total_tokens(data)
    plot_e1_hurdle_fixed(data)
    plot_split_token_deltas_fixed(data)
    plot_missing_e2_e3_slices(data)
    plot_catalog_finops_only(data)
    plot_compact_f2_f3_comparison(data)
    plot_compact_f1_active_vs_passive(data)
    plot_rq3_limits_clean(data)


if __name__ == "__main__":
    main()

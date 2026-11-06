"""Quick-look chart of metrics/owasp/per_tool.csv.

    .venv/bin/python scripts/owasp_overview.py metrics/owasp/per_tool.csv metrics/owasp/overview.png
"""
import csv, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
SAST, LLM, HYB = "#2a78d6", "#eb6834", "#1baf7a"
INK, SEC, MUTED, GRID, BG = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#fcfcfb"
NAMES = {
 "hybrid__codeql__qwen3_8b__reject__trace": ("CodeQL → Qwen3-8B", HYB),
 "hybrid__semgrep__qwen3_8b__reject__trace": ("Semgrep → Qwen3-8B", HYB),
 "codeql": ("CodeQL", SAST), "semgrep": ("Semgrep", SAST),
 "findsecbugs": ("SpotBugs + FindSecBugs", SAST), "pmd-custom": ("PMD (custom rules)", SAST),
 "sonarqube": ("SonarQube CE", SAST),
 "deepseek-coder_6.7b-instruct__zero-shot": ("DeepSeekCoder-6.7B", LLM),
 "qwen3_8b__zero-shot": ("Qwen3-8B", LLM),
 "hybrid__semgrep__deepseek-coder_6.7b-instruct__augment": ("Semgrep → DeepSeekCoder (augment)", HYB),
 "hybrid__semgrep__deepseek-coder_6.7b-instruct__reject": ("Semgrep → DeepSeekCoder (reject)", HYB),
}
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["tool"] in NAMES]
rows.sort(key=lambda r: float(r["f1"]))
fig, ax = plt.subplots(figsize=(11, 6.2), dpi=160, facecolor=BG)
ax.set_facecolor(BG)
for i, r in enumerate(rows):
    name, col = NAMES[r["tool"]]; f1, lo, hi = (float(r[k]) for k in ("f1", "f1_ci_low", "f1_ci_high"))
    ax.barh(i, f1, height=0.62, color=col, zorder=2)
    ax.plot([lo, hi], [i, i], color=INK, lw=1.2, zorder=3, solid_capstyle="butt")
    ax.text(hi + 0.012, i, f"{f1:.3f}", va="center", ha="left", fontsize=10.5, color=INK, fontweight="bold")
    for x, k in ((1.13, "precision"), (1.25, "recall"), (1.37, "fpr")):
        ax.text(x, i, f"{float(r[k]):.2f}", va="center", ha="center", fontsize=10, color=SEC)
top = len(rows) - 0.3
for x, t in ((1.13, "Precision"), (1.25, "Recall"), (1.37, "False-pos.\nrate")):
    ax.text(x, top, t, va="bottom", ha="center", fontsize=9.5, color=MUTED)
ax.text(0.0, top, "F1 (black line = 95 % interval)", va="bottom", ha="left", fontsize=9.5, color=MUTED)
ax.axvline(0.688, color=MUTED, lw=1, ls=(0, (4, 3)), zorder=1)
ax.text(0.688, top, "flagging everything: 0.688", ha="center", va="bottom", bbox=dict(facecolor=BG, edgecolor="none", pad=1.5), fontsize=8.5, color=MUTED)
ax.set_yticks(range(len(rows))); ax.set_yticklabels([NAMES[r["tool"]][0] for r in rows], fontsize=10.5, color=INK)
ax.set_xlim(0, 1.44); ax.set_ylim(-0.6, len(rows) + 0.3)
ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0]); ax.tick_params(axis="x", colors=MUTED, labelsize=9, length=0)
ax.tick_params(axis="y", length=0)
ax.grid(axis="x", color=GRID, lw=0.8, zorder=0); ax.set_axisbelow(True)
for s in ax.spines.values(): s.set_visible(False)
fig.suptitle("OWASP Benchmark v1.2, CWE-89 and CWE-22 (772 Java cases)", x=0.02, ha="left", fontsize=13.5, color=INK, fontweight="bold", y=0.975)
fig.text(0.02, 0.915, "An arrow means hybrid: the analyzer raises alerts and the LLM confirms or rejects each one.", fontsize=10, color=SEC)
ax.legend(handles=[Patch(color=HYB, label="Hybrid (SAST → LLM)"), Patch(color=SAST, label="SAST alone"), Patch(color=LLM, label="LLM alone (zero-shot)")],
          loc="lower right", bbox_to_anchor=(0.72, 0.02), frameon=False, fontsize=9.5, labelcolor=SEC)
fig.subplots_adjust(left=0.285, right=0.985, top=0.86, bottom=0.12)
fig.savefig(sys.argv[2], facecolor=BG)

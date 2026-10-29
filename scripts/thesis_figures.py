"""Data figures for Chapter 4, written to Template/Graficos/ as PDF.

    .venv/bin/python scripts/thesis_figures.py
"""

import json
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT.parent / "Template" / "Graficos"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID = "#222222", "#6b6b6b", "#e4e4e0"

plt.rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "font.size": 10,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "axes.spines.top": False,
    "axes.spines.right": False,
})


def _grid(ax):
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def corpus_composition():
    rows = [json.loads(l) for l in open(ROOT / "corpus/owasp.jsonl")]
    cats = [("89", "CWE-89 (SQLi)"), ("22", "CWE-22 (path traversal)")]
    vuln = [sum(1 for r in rows if r["cwe"] == c and r["label"] == 1) for c, _ in cats]
    safe = [sum(1 for r in rows if r["cwe"] == c and r["label"] == 0) for c, _ in cats]

    fig, ax = plt.subplots(figsize=(5.2, 2.2))
    y = range(len(cats))
    ax.barh(y, vuln, color=BLUE, height=0.55, edgecolor="white", linewidth=2, label="Vulnerable")
    ax.barh(y, safe, left=vuln, color=ORANGE, height=0.55, edgecolor="white", linewidth=2, label="Seguro")
    for i, (v, s) in enumerate(zip(vuln, safe)):
        ax.text(v / 2, i, str(v), ha="center", va="center", color="white", fontsize=9)
        ax.text(v + s / 2, i, str(s), ha="center", va="center", color="white", fontsize=9)
        ax.text(v + s + 8, i, f"{v + s}", ha="left", va="center", color=MUTED, fontsize=9)
    ax.set_yticks(list(y), [n for _, n in cats])
    ax.invert_yaxis()
    ax.set_xlabel("Casos")
    ax.set_xlim(0, 560)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=2, loc="lower right", bbox_to_anchor=(1, 1.0), fontsize=9)
    fig.savefig(OUT / "corpus_owasp.pdf", bbox_inches="tight")
    plt.close(fig)


def leakage():
    # Control experiment of Chapter 4: DeepSeekCoder-6.7B zero-shot on the same
    # 74 Juliet cases under three views of the code.
    conds = ["Original", "Sin pistas", "Solo el método"]
    vals = {"Recall": [0.83, 0.47, 0.57], "FPR": [0.14, 0.09, 0.34], "F1": [0.82, 0.58, 0.55]}
    colors = [BLUE, ORANGE, AQUA]

    fig, ax = plt.subplots(figsize=(5.2, 2.6))
    w = 0.26
    for j, (cond, col) in enumerate(zip(conds, colors)):
        xs = [i + (j - 1) * w for i in range(len(vals))]
        ys = [v[j] for v in vals.values()]
        ax.bar(xs, ys, width=w, color=col, edgecolor="white", linewidth=2, label=cond)
        for x, v in zip(xs, ys):
            ax.text(x, v + 0.02, f"{v:.2f}", ha="center", va="bottom", fontsize=8, color=INK)
    ax.set_xticks(range(len(vals)), list(vals))
    ax.set_ylim(0, 1)
    ax.set_ylabel("Valor")
    _grid(ax)
    ax.legend(frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.0), fontsize=9)
    fig.savefig(OUT / "fuga_juliet.pdf", bbox_inches="tight")
    plt.close(fig)


def _verdicts(tool):
    return {json.loads(l)["snippet_id"]: json.loads(l)["verdict"]
            for l in open(ROOT / f"findings/owasp/{tool}_perSnippet.jsonl")}


def _metrics(tool, rows):
    v = _verdicts(tool)
    tp = sum(1 for r in rows if r["label"] and v[r["snippet_id"]])
    fp = sum(1 for r in rows if not r["label"] and v[r["snippet_id"]])
    pos = sum(1 for r in rows if r["label"])
    return {"Precisión": tp / (tp + fp), "Recall": tp / pos,
            "F1": 2 * tp / (tp + fp + pos), "FPR": fp / (len(rows) - pos)}


def main_results():
    rows = [json.loads(l) for l in open(ROOT / "corpus/owasp.jsonl")]
    tools = [("semgrep", "Semgrep"), ("qwen3_8b__zero-shot", "Qwen3-8B zero-shot"),
             ("hybrid__semgrep__qwen3_8b__reject__trace", "Híbrido (traza)")]
    vals = [_metrics(t, rows) for t, _ in tools]
    names = list(vals[0])

    fig, ax = plt.subplots(figsize=(5.6, 2.6))
    w = 0.26
    for j, ((_, label), col) in enumerate(zip(tools, [BLUE, ORANGE, AQUA])):
        xs = [i + (j - 1) * w for i in range(len(names))]
        ys = [vals[j][n] for n in names]
        ax.bar(xs, ys, width=w, color=col, edgecolor="white", linewidth=2, label=label)
        for x, y in zip(xs, ys):
            ax.text(x, y + 0.02, f"{y:.2f}", ha="center", va="bottom", fontsize=7.5, color=INK)
    ax.set_xticks(range(len(names)), names)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Valor")
    _grid(ax)
    ax.legend(frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.0), fontsize=9)
    fig.savefig(OUT / "resultados_owasp.pdf", bbox_inches="tight")
    plt.close(fig)


def trap_patterns():
    # Benchmark false-positive traps among Semgrep's false alerts, and how many
    # of each the trace confirmer still accepts.
    pats = [("Condición aritmética", r"\d+\s*\*\s*\d+|num\s*>\s*200"),
            ("\\texttt{switch}", r"switch"),
            ("Colección", r"\.remove\(0\)|\.get\(\s*\d\s*\)|\.get\(\"key")]
    rows = [json.loads(l) for l in open(ROOT / "corpus/owasp.jsonl")]
    sg = _verdicts("semgrep")
    hy = _verdicts("hybrid__semgrep__qwen3_8b__reject__trace")
    false = [r for r in rows if not r["label"] and sg[r["snippet_id"]]]
    names, kept, dropped = [], [], []
    for name, rx in pats:
        hit = [r for r in false if re.search(rx, r["code"])]
        k = sum(hy[r["snippet_id"]] for r in hit)
        names.append(name); kept.append(k); dropped.append(len(hit) - k)
        false = [r for r in false if r not in hit]

    fig, ax = plt.subplots(figsize=(5.2, 2.0))
    y = range(len(names))
    ax.barh(y, dropped, color=AQUA, height=0.55, edgecolor="white", linewidth=2, label="Descartada")
    ax.barh(y, kept, left=dropped, color=ORANGE, height=0.55, edgecolor="white", linewidth=2, label="Confirmada")
    for i, (d, k) in enumerate(zip(dropped, kept)):
        ax.text(d / 2, i, str(d), ha="center", va="center", color="white", fontsize=9)
        ax.text(d + k / 2, i, str(k), ha="center", va="center", color="white", fontsize=9)
    ax.set_yticks(list(y), names)
    ax.invert_yaxis()
    ax.set_xlabel("Alertas falsas de Semgrep")
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=2, loc="lower right", bbox_to_anchor=(1, 1.0), fontsize=9)
    fig.savefig(OUT / "trampas_owasp.pdf", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    corpus_composition()
    leakage()
    main_results()
    trap_patterns()

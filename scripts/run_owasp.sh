#!/usr/bin/env bash
# Full OWASP Benchmark run, in order of priority. Needs Docker and `ollama serve`.
# Resumable: a step is skipped when its findings file already exists, so after
# an interruption just run it again. Close other GPU-heavy programs first.
set -euo pipefail
cd "$(dirname "$0")/.."

V=".venv/bin/vulnpipe --config config.owasp.yaml"
C="--corpus corpus/owasp.jsonl"
F="findings/owasp"
DS="deepseek-coder:6.7b-instruct"; DSF="deepseek-coder_6.7b-instruct"
SEMGREP="$F/semgrep_perSnippet.jsonl"

step() {  # step <output file> <command...>
    local out=$1; shift
    if [[ -f $out ]]; then echo "skip: $out"; return; fi
    echo "run:  $*"
    "$@"
}

step corpus/owasp.jsonl $V corpus build --only owasp
step "$F/pmd-custom_perSnippet.jsonl" $V sast run --tool pmd --variant both $C
step "$SEMGREP" $V sast run --tool semgrep $C
# Tools that need the corpus compiled (Docker; CodeQL bundle in data/tools/codeql).
for tool in findsecbugs codeql sonarqube; do
    step "$F/${tool}_perSnippet.jsonl" $V sast run --tool "$tool" $C
done

step "$F/${DSF}__zero-shot_perSnippet.jsonl" $V llm run --model "$DS" --strategy zero-shot $C
step "$F/hybrid__semgrep__${DSF}__reject_perSnippet.jsonl" \
    $V hybrid run --sast "$SEMGREP" --model "$DS" --scope reject $C
step "$F/hybrid__semgrep__${DSF}__augment_perSnippet.jsonl" \
    $V hybrid run --sast "$SEMGREP" --model "$DS" --scope augment $C
# Qwen3-8B (thinking) as the confirmer, chosen by scripts/pilot.py: J = +0.77
# with the trace prompt vs +0.07 for DeepSeek. ~30 s per call, so each hybrid
# step is ~5 h and zero-shot ~8 h. Priority: main hybrid, its HIS reference,
# then the prompt variant with the false-alarm list, then augment.
Q="qwen3:8b"; QF="qwen3_8b"
TRACES="$F/scan/semgrep_traces.txt"   # written by the Semgrep step
step "$F/hybrid__semgrep__${QF}__reject__trace_perSnippet.jsonl" \
    $V hybrid run --sast "$SEMGREP" --traces "$TRACES" --model "$Q" --scope reject $C
step "$F/${QF}__zero-shot_perSnippet.jsonl" $V llm run --model "$Q" --strategy zero-shot $C
# CodeQL is the strongest analyzer (F1 0.841), so its hybrid comes first.
CODEQL="$F/codeql_perSnippet.jsonl"
step "$F/hybrid__codeql__${QF}__reject__trace_perSnippet.jsonl" \
    $V hybrid run --sast "$CODEQL" --traces "$F/scan/codeql_traces.json" --model "$Q" --scope reject $C
step "$F/hybrid__semgrep__${QF}__reject__trace-hints_perSnippet.jsonl" \
    $V hybrid run --sast "$SEMGREP" --traces "$TRACES" --hints --model "$Q" --scope reject $C
# ponytail: no augment step. At temperature 0 it equals the reject answers plus
# the zero-shot answers on the cases the analyzer did not flag, so it can be
# composed from the files above instead of spending ~12 h of GPU.

$V metrics $C --findings "$F"/*_perSnippet.jsonl

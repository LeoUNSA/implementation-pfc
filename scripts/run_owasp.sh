#!/usr/bin/env bash
# Full OWASP Benchmark run, in order of priority. Needs Docker and `ollama serve`.
# Resumable: a step is skipped when its findings file already exists, so after
# an interruption just run it again. Each LLM configuration takes ~1 h on an
# RTX 4060 (772 cases); close other GPU-heavy programs first.
set -euo pipefail
cd "$(dirname "$0")/.."

V=".venv/bin/vulnpipe --config config.owasp.yaml"
C="--corpus corpus/owasp.jsonl"
F="findings/owasp"
DS="deepseek-coder:6.7b-instruct"; DSF="deepseek-coder_6.7b-instruct"
CL="codellama:13b-instruct";       CLF="codellama_13b-instruct"
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

step "$F/${DSF}__zero-shot_perSnippet.jsonl" $V llm run --model "$DS" --strategy zero-shot $C
step "$F/hybrid__semgrep__${DSF}__reject_perSnippet.jsonl" \
    $V hybrid run --sast "$SEMGREP" --model "$DS" --scope reject $C
step "$F/hybrid__semgrep__${DSF}__augment_perSnippet.jsonl" \
    $V hybrid run --sast "$SEMGREP" --model "$DS" --scope augment $C
step "$F/${DSF}__cot_perSnippet.jsonl" $V llm run --model "$DS" --strategy cot $C
step "$F/${DSF}__few-shot_perSnippet.jsonl" $V llm run --model "$DS" --strategy few-shot $C
step "$F/${CLF}__zero-shot_perSnippet.jsonl" $V llm run --model "$CL" --strategy zero-shot $C

$V metrics $C --findings "$F"/*_perSnippet.jsonl

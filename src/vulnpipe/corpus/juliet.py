"""NIST Juliet (Java) → labelled ``Snippet`` corpus.

Juliet test cases are named ``CWE<NN>_<desc>__<variant>_<NN>.java`` and
expose a ``bad()`` method (the vulnerable path, label=1) and one or more
``good*()`` methods (the fixed paths, label=0). We extract each such
method ±``context_lines`` lines, label it, then draw a balanced sample.

Download is on first use; subsequent runs reuse the cached archive.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Iterator

from vulnpipe.config import Config
from vulnpipe.corpus.javaparse import extract_methods, slice_with_context
from vulnpipe.schemas import SAFE, VULNERABLE, Snippet

_CWE_PREFIX = re.compile(r"^CWE(\d+)_")


def download(cfg: Config) -> Path:
    """Download the Juliet archive into the data dir if not already present.

    Returns the local archive path. Network access only happens on a cache
    miss. Raises with a clear message if the download backend is missing.
    """
    jcfg = cfg.corpus_cfg["juliet"]
    data_dir = cfg.ensure_path("data")
    archive = data_dir / jcfg["archive_name"]
    if archive.exists() and archive.stat().st_size > 0:
        return archive

    url = jcfg["url"]
    try:
        import requests
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "requests is required to download Juliet; install deps first."
        ) from e

    print(f"[juliet] downloading {url} -> {archive}")
    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        with open(archive, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
    if not zipfile.is_zipfile(archive):
        archive.unlink(missing_ok=True)
        raise RuntimeError(f"downloaded file is not a valid zip: {url}")
    return archive


def extract_archive(cfg: Config, archive: Path) -> Path:
    """Unzip the Juliet archive into ``data/juliet/`` (idempotent)."""
    dest = cfg.path("data") / "juliet"
    marker = dest / ".extracted"
    if marker.exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)
    marker.write_text("ok", encoding="utf-8")
    return dest


def _build_prefix_map(cfg: Config) -> dict[str, str]:
    """Reverse the config ``cwe_map`` into ``{juliet_prefix: canonical_cwe}``.

    Falls back to an identity map over ``cfg.cwes`` if no ``cwe_map`` is set,
    preserving behaviour for configs that target CWEs whose Juliet prefix
    equals the canonical id.
    """
    cwe_map = cfg.corpus_cfg["juliet"].get("cwe_map")
    if not cwe_map:
        return {c: c for c in cfg.cwes}
    prefix_to_canonical: dict[str, str] = {}
    for canonical, prefixes in cwe_map.items():
        for p in prefixes:
            prefix_to_canonical[str(p)] = str(canonical)
    return prefix_to_canonical


def iter_testcase_files(
    root: Path, prefix_map: dict[str, str]
) -> Iterator[tuple[str, Path]]:
    """Yield (canonical_cwe, path) for every ``CWE<n>_*.java`` test case under
    ``root`` whose Juliet prefix appears in ``prefix_map``."""
    for path in root.rglob("CWE*.java"):
        m = _CWE_PREFIX.match(path.name)
        if m and m.group(1) in prefix_map:
            yield prefix_map[m.group(1)], path


def _snippet_id(cwe: str, stem: str, method: str) -> str:
    return f"juliet_CWE{cwe}__{stem}__{method}"


def snippets_from_file(
    cwe: str, path: Path, context_lines: int
) -> list[Snippet]:
    """Extract labelled snippets from one Juliet test-case file.

    ``bad`` → vulnerable; methods named ``good*`` (excluding the bare
    ``good`` dispatcher when richer variants exist) → safe.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    methods = extract_methods(source)
    by_name = {m.name: m for m in methods}

    good_methods = [m for m in methods if m.name.startswith("good")]
    rich_goods = [m for m in good_methods if m.name != "good"]
    chosen_goods = rich_goods or good_methods  # fall back to dispatcher

    out: list[Snippet] = []
    if "bad" in by_name:
        code, line = slice_with_context(source, by_name["bad"], context_lines)
        out.append(
            Snippet(
                snippet_id=_snippet_id(cwe, path.stem, "bad"),
                cwe=cwe,
                label=VULNERABLE,
                code=code,
                file=path.name,
                line=line,
            )
        )
    for gm in chosen_goods:
        code, line = slice_with_context(source, gm, context_lines)
        out.append(
            Snippet(
                snippet_id=_snippet_id(cwe, path.stem, gm.name),
                cwe=cwe,
                label=SAFE,
                code=code,
                file=path.name,
                line=line,
            )
        )
    return out


def collect_snippets(cfg: Config, root: Path) -> list[Snippet]:
    """Walk all in-scope test cases and extract every labelled snippet."""
    prefix_map = _build_prefix_map(cfg)
    context_lines = int(cfg.corpus_cfg["context_lines"])
    snippets: list[Snippet] = []
    for cwe, path in iter_testcase_files(root, prefix_map):
        snippets.extend(snippets_from_file(cwe, path, context_lines))
    return snippets


def balanced_sample(
    snippets: list[Snippet], n_vuln: int, n_safe: int, seed: int
) -> list[Snippet]:
    """Draw a CWE-stratified balanced sample, deterministic under ``seed``.

    Splits the per-CWE quota evenly; if a CWE/label pool is smaller than its
    quota it is taken whole (no oversampling), so the result may be slightly
    under the target rather than duplicating snippets.
    """
    import random

    rng = random.Random(seed)
    cwes = sorted({s.cwe for s in snippets})
    if not cwes:
        return []

    def take(pool: list[Snippet], k: int) -> list[Snippet]:
        pool = sorted(pool, key=lambda s: s.snippet_id)  # stable before shuffle
        rng.shuffle(pool)
        return pool[:k]

    per_cwe_vuln = max(1, n_vuln // len(cwes))
    per_cwe_safe = max(1, n_safe // len(cwes))

    chosen: list[Snippet] = []
    for cwe in cwes:
        vuln = [s for s in snippets if s.cwe == cwe and s.label == VULNERABLE]
        safe = [s for s in snippets if s.cwe == cwe and s.label == SAFE]
        chosen.extend(take(vuln, per_cwe_vuln))
        chosen.extend(take(safe, per_cwe_safe))
    return chosen


def build(cfg: Config) -> list[Snippet]:
    """Full Juliet pipeline: download → extract → collect → balanced sample."""
    jcfg = cfg.corpus_cfg["juliet"]
    archive = download(cfg)
    root = extract_archive(cfg, archive)
    all_snippets = collect_snippets(cfg, root)
    return balanced_sample(
        all_snippets,
        n_vuln=int(jcfg["n_vulnerable"]),
        n_safe=int(jcfg["n_safe"]),
        seed=int(cfg.corpus_cfg["seed"]),
    )

"""Compilable copy of the OWASP corpus, for the tools that need bytecode.

CodeQL, SpotBugs+FindSecBugs and SonarQube analyse a built project. The
project is the benchmark's own ``pom.xml`` and helper classes plus the
corpus cases exactly as every other detector sees them (neutralised code),
with only the class name restored so that each file compiles. Line numbers
therefore match ``Snippet.code``, which the hybrid confirmer relies on.

Everything runs in a pinned Maven container; dependencies are cached in
``data/m2``.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Sequence

from vulnpipe.config import Config
from vulnpipe.sast import container
from vulnpipe.schemas import Snippet

PKG = Path("src/main/java/org/owasp/benchmark")
DEFAULT_IMAGE = "maven:3.9.9-eclipse-temurin-17"
# spotless is the benchmark's code formatter: it must not touch the cases,
# whose line numbers have to match the corpus.
MVN_FLAGS = ["-B", "-q", "-Dmaven.repo.local=/m2", "-Dspotless.skip=true",
             "-Dspotless.apply.skip=true", "-Dspotless.check.skip=true"]
# The benchmark's findsecbugs profile expects these two filter files.
_INCLUDE = '<FindBugsFilter><Match><Bug category="SECURITY"/></Match></FindBugsFilter>\n'
_EXCLUDE = "<FindBugsFilter/>\n"


def image(cfg: Config) -> str:
    return cfg.raw.get("sast", {}).get("build", {}).get("image", DEFAULT_IMAGE)


def case_name(s: Snippet) -> str:
    return Path(s.file).stem


def snippet_ids(corpus: Sequence[Snippet]) -> dict[str, str]:
    """``{BenchmarkTestNNNNN: snippet_id}``, the join key for tool reports."""
    return {case_name(s): s.snippet_id for s in corpus}


def write_project(cfg: Config, corpus: Sequence[Snippet]) -> Path:
    src = cfg.path("data") / cfg.corpus_cfg.get("owasp", {}).get("dir", "owasp-benchmark")
    proj = cfg.ensure_path("findings") / "build"
    shutil.rmtree(proj / "src", ignore_errors=True)
    for pkg in ("helpers", "service"):  # everything the cases compile against
        shutil.copytree(src / PKG / pkg, proj / PKG / pkg)
    shutil.copy(src / "pom.xml", proj / "pom.xml")
    res = proj / "src/main/resources"
    res.mkdir(parents=True)
    (res / "findbugs-security-include.xml").write_text(_INCLUDE)
    (res / "findbugs-security-exclude.xml").write_text(_EXCLUDE)
    code = proj / PKG / "testcode"
    code.mkdir()
    for s in corpus:
        name = case_name(s)
        (code / f"{name}.java").write_text(s.code.replace("TestCase", name) + "\n", encoding="utf-8")
    return proj


def maven(
    cfg: Config,
    proj: Path,
    goals: Sequence[str],
    mounts: dict[Path, str] | None = None,
    docker_args: Sequence[str] = (),
    command: Sequence[str] | None = None,
    timeout: int = 3600,
) -> float:
    """Run Maven (or ``command``) in the build container at ``/src``. Returns elapsed ms."""
    m2 = cfg.ensure_path("data") / "m2"
    m2.mkdir(exist_ok=True)
    args = list(command) if command else ["mvn", *MVN_FLAGS, *goals]
    rc, out, err, elapsed = container.run_container(
        image(cfg), args, {proj: "/src", m2: "/m2", **(mounts or {})}, timeout=timeout,
        docker_args=["--user", f"{os.getuid()}:{os.getgid()}", "-w", "/src",
                     "-e", "HOME=/tmp", "-e", "MAVEN_CONFIG=/tmp/.m2", *docker_args],
    )
    if rc != 0:
        raise RuntimeError(f"build failed (rc={rc}): {' '.join(args)}\n{out[-3000:]}\n{err[-3000:]}")
    return elapsed

#!/usr/bin/env python3
"""Which tests a pull request needs (SPEC 23, "Test selection"). Python 3 standard library only.

    scripts/select-tests.py FILE...      the selection for these changed paths, as JSON
    scripts/select-tests.py --github     in a `changes` job: reads the event, the pull request's
                                         labels and files with `gh api`; writes GITHUB_OUTPUT

Paths map to suites in .github/test-map. Conservative: a path no line maps, the label
`ci:full`, or any run that is not a pull request selects everything. Workspace crates come
from `cargo metadata --no-deps`: a changed file selects the tests of its crate and of every
workspace crate that depends on it.
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAP = os.path.join(ROOT, ".github", "test-map")
FULL_LABEL = "ci:full"
# GET /pulls/{n}/files lists at most 3000 files
MAX_FILES = 3000


def glob_re(glob):
    """`**` matches across folders (`**/` also matches no folder), `*` and `?` within one."""
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif glob.startswith("**", i):
            out, i = out + ".*", i + 2
        elif glob[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif glob[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(glob[i]), i + 1
    return re.compile(out + r"\Z")


def load_map(path=MAP):
    rules = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            glob, *suites = line.split()
            if not suites:
                raise SystemExit(f"{path}:{n}: no suites for {glob}")
            rules.append((glob, glob_re(glob), suites))
    return rules


def workspace():
    """Workspace crates: folder, default member or not, targets, workspace dependencies."""
    env = dict(os.environ)
    # --no-deps needs no network and no particular toolchain
    env.setdefault("RUSTUP_TOOLCHAIN", "stable")
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, env=env, check=True, capture_output=True, text=True,
    ).stdout
    meta = json.loads(out)
    members = set(meta["workspace_members"])
    defaults = set(meta.get("workspace_default_members") or meta["workspace_members"])
    root = meta["workspace_root"]
    crates = {}
    for p in meta["packages"]:
        if p["id"] not in members:
            continue
        kinds = [k for t in p["targets"] for k in t["kind"]]
        crates[p["name"]] = {
            "dir": os.path.relpath(os.path.dirname(p["manifest_path"]), root).replace(os.sep, "/"),
            "default": p["id"] in defaults,
            "lib": "lib" in kinds,
            "bins": "bin" in kinds,
            "tests": sorted(t["name"] for t in p["targets"] if "test" in t["kind"]),
            "deps": {d["name"] for d in p["dependencies"] if d.get("path")},
        }
    for c in crates.values():
        c["deps"] &= set(crates)
    return crates


def owner(path, crates):
    best = None
    for name, c in crates.items():
        d = c["dir"]
        if (d == "." or path.startswith(d + "/")) and (best is None or len(d) > len(crates[best]["dir"])):
            best = name
    return best


def select(files, crates, rules, full_reason=None):
    """The selection for a list of changed paths, or everything with `full_reason`."""
    targets = {t: name for name, c in crates.items() for t in c["tests"]}
    # crates whose integration tests the map selects one by one; other crates run all of theirs
    named = {targets[s] for _, _, suites in rules for s in suites if s in targets}
    for glob, _, suites in rules:
        for s in suites:
            is_unit = s.startswith("unit:") and s[5:] in crates
            if s not in ("all", "none", "fuzz") and s not in targets and not is_unit:
                raise SystemExit(f".github/test-map: unknown suite {s!r} for {glob}")
    changed, tests_only, it, fuzz = set(), set(), set(), False
    full = full_reason
    for f in files:
        matched = [s for _, rx, suites in rules if rx.match(f) for s in suites]
        if not matched:
            full = full or f"{f} is not in .github/test-map"
            continue
        for s in matched:
            if s == "all":
                full = full or f"{f} runs everything"
            elif s == "none":
                pass
            elif s == "fuzz":
                fuzz = True
            elif s in targets:
                it.add(s)
            else:
                tests_only.add(s[5:])
        o = owner(f, crates)
        if o:
            changed.add(o)
    if full:
        unit = {n for n, c in crates.items() if c["default"]}
        it = set(targets)
        fuzz = True
    else:
        # reverse dependencies: a crate whose dependency changed runs all of its tests
        affected = set(changed)
        while True:
            more = {n for n, c in crates.items() if c["deps"] & affected} - affected
            if not more:
                break
            affected |= more
        for n in affected - changed:
            it |= set(crates[n]["tests"])
        unit = {n for n in affected | tests_only if crates[n]["default"]}
        it = {t for t in it if crates[targets[t]]["default"]}
    # `cargo test` arguments per crate for the macOS job (Linux runs the whole `cargo test`)
    runs = []
    for n in sorted(unit | {targets[t] for t in it}):
        c = crates[n]
        if n not in named:
            runs.append(f"-p {n}")
            continue
        args = [f"-p {n}"]
        if n in unit:
            args += ["--lib"] * c["lib"] + ["--bins"] * c["bins"]
        args += [f"--test {t}" for t in sorted(it) if targets[t] == n]
        runs.append(" ".join(args))
    return {
        "full": bool(full),
        "reason": full or "",
        "unit": sorted(unit),
        "it": sorted(t for t in it if targets[t] in named),
        "fuzz": fuzz,
        "cargo_test": runs,
    }


def gh(*args):
    return subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout.split("\n")


def github():
    event = os.environ.get("EVENT", "")
    repo, pr = os.environ.get("REPO", ""), os.environ.get("PR", "")
    files, reason = [], None
    if event != "pull_request":
        reason = f"a {event or 'non-pull-request'} run tests everything"
    else:
        try:
            labels = [l for l in gh(f"repos/{repo}/pulls/{pr}", "--jq", ".labels[].name") if l]
            if FULL_LABEL in labels:
                reason = f"label {FULL_LABEL}"
            else:
                files = [l for l in gh("--paginate", f"repos/{repo}/pulls/{pr}/files",
                                       "--jq", ".[] | .filename, (.previous_filename // empty)") if l]
                if len(files) >= MAX_FILES:
                    reason = f"{len(files)} files: more than the API lists"
                elif not files:
                    reason = "no changed files listed"
        except (subprocess.CalledProcessError, OSError) as e:
            reason = f"could not read the pull request ({e}): everything"
    sel = select(files, workspace(), load_map(), reason)
    pad = lambda xs: " " + " ".join(xs) + " "
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        out.write(f"full={str(sel['full']).lower()}\n")
        out.write(f"unit={pad(sel['unit'])}\n")
        out.write(f"it={pad(sel['it'])}\n")
        out.write(f"fuzz={str(sel['fuzz']).lower()}\n")
        out.write(f"cargo_test={';'.join(sel['cargo_test'])}\n")
    lines = [
        "### Test selection",
        "",
        f"- everything: **{sel['full']}**" + (f" ({sel['reason']})" if sel["reason"] else ""),
        f"- unit tests (macOS): {', '.join(sel['unit']) or 'none'}",
        f"- integration tests (macOS) and their test-hooks steps: {', '.join(sel['it']) or 'none'}",
        f"- fuzz: {sel['fuzz']}",
        f"- changed files: {len(files)}",
    ]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as s:
            s.write("\n".join(lines) + "\n")


def main(argv):
    if argv == ["--github"]:
        github()
        return
    files = argv or [l.strip() for l in sys.stdin if l.strip()]
    json.dump(select(files, workspace(), load_map()), sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main(sys.argv[1:])

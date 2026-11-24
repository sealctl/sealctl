#!/usr/bin/env python3
"""Tests of scripts/select-tests.py and .github/test-map: example file lists and the suites they
select. Run by ci.yml in `test (ubuntu-latest)`: python3 scripts/select-tests-test.py"""

import importlib.util
import os
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("select_tests", os.path.join(HERE, "select-tests.py"))
sel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sel)

CRATES = sel.workspace()
RULES = sel.load_map()
ALL_IT = {"daemon", "leak", "long_ops", "migrate", "pairing", "project", "recover", "scan", "seal_from",
          "secrets", "session", "stores", "unseal", "volumes"}


def run(*files, reason=None):
    return sel.select(list(files), CRATES, RULES, reason)


class Examples(unittest.TestCase):
    def assertFull(self, r):
        self.assertTrue(r["full"], r)
        self.assertEqual(set(r["it"]), ALL_IT)
        self.assertEqual(set(r["unit"]), {"sealctl", "sealctl-core", "sealctl-fakerelay"})
        self.assertTrue(r["fuzz"])

    def test_pr_40_volume_open_touches_cli_rs(self):
        # sealctl#40 "volume open": cli.rs holds every command's glue, so everything runs
        r = run("CHANGELOG.md", "SPEC.md", "crates/sealctl/src/cli.rs",
                "crates/sealctl/src/volume/luks.rs", "crates/sealctl/src/volume/mod.rs",
                "crates/sealctl/src/volume/sparsebundle.rs", "crates/sealctl/tests/volumes.rs")
        self.assertFull(r)
        self.assertIn("cli.rs", r["reason"])

    def test_volume_change(self):
        r = run("crates/sealctl/src/volume/mod.rs", "crates/sealctl/tests/volumes.rs", "CHANGELOG.md")
        self.assertFalse(r["full"])
        self.assertEqual(r["it"], ["long_ops", "migrate", "recover", "seal_from", "unseal", "volumes"])
        self.assertEqual(r["unit"], ["sealctl"])
        self.assertFalse(r["fuzz"])
        self.assertEqual(r["cargo_test"], [
            "-p sealctl --lib --bins --test long_ops --test migrate --test recover --test seal_from --test unseal"
            " --test volumes"])

    def test_daemon_change_runs_its_suites_and_fuzz(self):
        r = run("crates/sealctl/src/daemon/mod.rs")
        self.assertEqual(set(r["it"]), {"daemon", "session", "secrets", "volumes", "long_ops", "unseal",
                                        "migrate", "pairing", "leak"})
        self.assertTrue(r["fuzz"])

    def test_agent_change(self):
        r = run("crates/sealctl/src/ai/policy.rs", "crates/sealctl/src/ai/SKILL.md")
        self.assertEqual(r["it"], ["project", "secrets", "unseal"])
        self.assertFalse(r["fuzz"])

    def test_parser_change_runs_fuzz(self):
        r = run("crates/sealctl/src/dotenv.rs")
        self.assertTrue(r["fuzz"])
        self.assertEqual(r["it"], ["long_ops", "scan", "seal_from", "secrets"])

    def test_fuzz_target_only(self):
        r = run("fuzz/fuzz_targets/dotenv.rs")
        self.assertEqual((r["fuzz"], r["unit"], r["it"], r["cargo_test"]), (True, [], [], []))

    def test_daemon_test_seams_run_unit_tests_only(self):
        r = run("crates/sealctl/src/daemon/timing_tests.rs")
        self.assertEqual((r["unit"], r["it"]), (["sealctl"], []))
        self.assertEqual(r["cargo_test"], ["-p sealctl --lib --bins"])

    def test_one_integration_test_file(self):
        r = run("crates/sealctl/tests/scan.rs")
        self.assertEqual(r["it"], ["scan"])

    def test_documentation_and_packaging_run_nothing(self):
        r = run("README.md", "docs/protocol.md", "scripts/package.sh", "bindings/swift/main.swift",
                "supply-chain/config.toml", ".github/dependabot.yml")
        self.assertEqual((r["full"], r["unit"], r["it"], r["fuzz"]), (False, [], [], False))

    def test_vectors_run_the_core_tests_only(self):
        r = run("docs/vectors/v1.json")
        self.assertEqual((r["full"], r["unit"], r["it"]), (False, ["sealctl-core"], []))
        self.assertEqual(r["cargo_test"], ["-p sealctl-core"])

    def test_everything(self):
        for f in ["Cargo.lock", "Cargo.toml", "crates/sealctl/Cargo.toml", "fuzz/Cargo.toml",
                  "rust-toolchain.toml", "flake.nix", "flake.lock", ".github/workflows/ci.yml",
                  ".github/test-map", "scripts/select-tests.py", "crates/sealctl-core/src/sealed.rs",
                  "crates/sealctl-fakerelay/src/phone.rs", "crates/sealctl/tests/common/mod.rs",
                  "crates/sealctl/tests/fixtures/bin/op", "crates/sealctl/src/main.rs"]:
            with self.subTest(f):
                self.assertFull(run(f))

    def test_unmapped_path_runs_everything(self):
        for f in ["crates/sealctl/src/new_module.rs", "crates/sealctl/src/daemon/new.rs",
                  "crates/sealctl/tests/new_suite.rs", "new-folder/file"]:
            with self.subTest(f):
                r = run("README.md", f)
                self.assertFull(r)
                self.assertIn("not in .github/test-map", r["reason"])

    def test_not_a_pull_request_runs_everything(self):
        self.assertFull(run(reason="a push run tests everything"))


class Map(unittest.TestCase):
    def test_every_integration_test_is_named(self):
        named = {s for _, _, suites in RULES for s in suites if s in ALL_IT}
        self.assertEqual(named, set(CRATES["sealctl"]["tests"]))
        self.assertEqual(ALL_IT, set(CRATES["sealctl"]["tests"]))

    def test_globs(self):
        rx = sel.glob_re
        self.assertTrue(rx("**/Cargo.toml").match("Cargo.toml"))
        self.assertTrue(rx("**/Cargo.toml").match("crates/a/Cargo.toml"))
        self.assertFalse(rx("*.md").match("docs/a.md"))
        self.assertTrue(rx("crates/x/**").match("crates/x/a/b.rs"))
        self.assertFalse(rx("crates/x/**").match("crates/xy/a.rs"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

# Copyright 2026 Ratio1
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import hashlib
import importlib.util
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
  "october_security_vex", ROOT / "scripts/verify-security-vex.py",
)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
PROVENANCE_SPEC = importlib.util.spec_from_file_location(
  "october_security_provenance", ROOT / "scripts/verify-provenance.py",
)
PROVENANCE_VERIFIER = importlib.util.module_from_spec(PROVENANCE_SPEC)
PROVENANCE_SPEC.loader.exec_module(PROVENANCE_VERIFIER)
class UpstreamDependencySecurityContractTests(unittest.TestCase):
  def setUp(self):
    directory = tempfile.TemporaryDirectory()
    self.addCleanup(directory.cleanup)
    self.root = Path(directory.name)
    for relative in (
      "engine/go.mod", "engine/vendor/modules.txt", "source/runtime-files.txt",
      "source/ratio1-engine-overrides.json", "security/openvex.json",
      "source/cloudflared-buildinfo.txt",
    ):
      self.write(relative, (ROOT / relative).read_bytes())
    self.overrides = json.loads((self.root / "source/ratio1-engine-overrides.json").read_text())
    self.document = json.loads((self.root / "security/openvex.json").read_text())
    for name, value in (
      ("ROOT", self.root), ("RUNTIME_FILES", self.root / "source/runtime-files.txt"),
      ("VEX", self.root / "security/openvex.json"),
    ):
      override = patch.object(VERIFIER, name, value)
      override.start()
      self.addCleanup(override.stop)

  def write(self, relative, content):
    path = self.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode())

  def assert_rejected(self, callback, message):
    with redirect_stderr(io.StringIO()) as output:
      with self.assertRaises(SystemExit) as failure:
        callback()
    self.assertEqual(failure.exception.code, 1)
    self.assertIn(message, output.getvalue())

  def test_upstream_fixed_dependencies_and_absent_s2_are_accepted(self):
    VERIFIER.verify_upstream_dependency_fixes()
    VERIFIER.verify_s2_absence()

  @unittest.skipUnless((ROOT / ".git").exists(), "historical preimage integration requires a checkout")
  def test_missing_preimage_commit_in_git_checkout_is_rejected(self):
    data = copy.deepcopy(self.overrides)
    record = next(item for item in data["securityBackports"] if item["advisory"] == "CVE-2026-43871")
    record["preimageCommit"] = "0" * 40
    self.write("source/ratio1-engine-overrides.json", json.dumps(data))
    upstream = json.loads((ROOT / "source/provenance.json").read_text())["upstream"]["commit"]
    with patch.object(PROVENANCE_VERIFIER, "OVERRIDES", self.root / "source/ratio1-engine-overrides.json"):
      self.assert_rejected(
        lambda: PROVENANCE_VERIFIER.check_engine_overrides(
          upstream, (ROOT / "RATIO1_PATCHES.md").read_text(), None,
        ),
        "preimage commit is unavailable",
      )

  def test_superseded_vex_decisions_are_removed_and_rejected(self):
    self.assertEqual(self.document["version"], 11)
    self.assertEqual(self.document["@id"], "https://github.com/Ratio1/r1db/security/vex/11")
    self.assertEqual(len(self.document["statements"]), 13)
    for advisory in VERIFIER.RETIRED_ADVISORIES | {"CVE-2026-78661"}:
      self.assertFalse(any(s["vulnerability"]["@id"].endswith(advisory) for s in self.document["statements"]))
      self.assert_rejected(
        lambda: VERIFIER.validate_statement({"vulnerability": {"@id": f"https://nvd.nist.gov/vuln/detail/{advisory}"}}),
        "unexpected vulnerability decision",
      )

  def test_remaining_vex_decisions_require_exact_products_status_and_evidence(self):
    for statement in self.document["statements"]:
      VERIFIER.validate_statement(statement)
      for field, value in (("products", []), ("status", "affected")):
        changed = copy.deepcopy(statement)
        changed[field] = value
        self.assert_rejected(lambda: VERIFIER.validate_statement(changed), "VEX")
      changed = copy.deepcopy(statement)
      changed.pop("status_notes" if statement["status"] == "fixed" else "impact_statement")
      self.assert_rejected(lambda: VERIFIER.validate_statement(changed), "no evidence")

  def test_fixed_versions_cannot_be_changed_or_duplicated_in_either_engine_manifest(self):
    for module, version in VERIFIER.UPSTREAM_FIXED_MODULES.items():
      for relative in ("engine/go.mod", "engine/vendor/modules.txt"):
        path = self.root / relative
        original = path.read_text()
        for mutation in ("version", "duplicate"):
          with self.subTest(module=module, path=relative, mutation=mutation):
            changed = original.replace(module + " " + version, module + " " + version + "0")
            if mutation == "duplicate":
              changed = original + ("# " if relative.endswith("modules.txt") else "\t") + module + " " + version + "\n"
            path.write_text(changed)
            self.assert_rejected(VERIFIER.verify_upstream_dependency_fixes, "version differs")
            path.write_text(original)

  def test_cloudflared_must_embed_the_fixed_net_version_once(self):
    path = self.root / "source/cloudflared-buildinfo.txt"
    original = path.read_text()
    for changed in (
      original.replace("golang.org/x/net\tv0.62.0", "golang.org/x/net\tv0.61.0"),
      original + "\tdep\tgolang.org/x/net\tv0.62.0\t\n",
      original.replace("\tdep\tgolang.org/x/net\tv0.62.0\t\n", ""),
    ):
      self.assertNotEqual(original, changed)
      path.write_text(changed)
      self.assert_rejected(VERIFIER.verify_upstream_dependency_fixes, "Cloudflared must embed")

  def test_local_overrides_cannot_reintroduce_superseded_dependency_sources(self):
    for key, record in (
      ("securityBackports", {"module": "golang.org/x/net@v0.56.0"}),
      ("securityBackports", {"advisory": "CVE-2026-56851"}),
      ("dependencyCompatibilityBackports", {"files": [{"path": "engine/vendor/golang.org/x/crypto/ssh/server.go"}]}),
      ("generatedVendorFiles", {"path": "engine/vendor/golang.org/x/text/secure/precis/nickname.go"}),
    ):
      with self.subTest(key=key, record=record):
        data = copy.deepcopy(self.overrides)
        data[key].append(record)
        self.write("source/ratio1-engine-overrides.json", json.dumps(data))
        self.assert_rejected(VERIFIER.verify_upstream_dependency_fixes, "must not retain local vendor overrides")

  def test_s2_disk_guard_rejects_empty_directory_and_dangling_symlink(self):
    source = self.root / "engine/vendor/github.com/klauspost/compress/s2"
    source.mkdir(parents=True)
    self.assert_rejected(VERIFIER.verify_s2_absence, "distributes the vulnerable S2")
    source.rmdir()
    source.symlink_to("missing-s2-source")
    self.assert_rejected(VERIFIER.verify_s2_absence, "distributes the vulnerable S2")

  def test_s2_manifest_guard_rejects_package_subpackage_and_module(self):
    path = self.root / "engine/vendor/modules.txt"
    original = path.read_text()
    for entry in (
      "github.com/klauspost/compress/s2", "github.com/klauspost/compress/s2/cmd/s2c",
      "# github.com/klauspost/compress/s2 v1.0.0",
    ):
      path.write_text(original + entry + "\n")
      self.assert_rejected(VERIFIER.verify_s2_absence, "manifest unexpectedly includes S2")

  def test_s2_runtime_guard_rejects_package_and_subpackage_paths(self):
    path = self.root / "source/runtime-files.txt"
    original = path.read_text()
    for entry in (
      "vendor/github.com/klauspost/compress/s2/dict.go",
      "vendor/github.com/klauspost/compress/s2/cmd/s2c/main.go",
      "engine/vendor/github.com/klauspost/compress/s2/dict.go",
    ):
      path.write_text(original + entry + "\n")
      self.assert_rejected(VERIFIER.verify_s2_absence, "runtime closure unexpectedly includes S2")

  def test_vex_document_rejects_old_identity_version_missing_and_duplicate_decisions(self):
    for mutation in ("identity", "version", "missing", "duplicate"):
      document = copy.deepcopy(self.document)
      if mutation == "identity":
        document["@id"] = "https://github.com/Ratio1/r1db/security/vex/10"
      elif mutation == "version":
        document["version"] = 10
      elif mutation == "missing":
        document["statements"].pop()
      else:
        document["statements"][-1] = copy.deepcopy(document["statements"][0])
      self.write("security/openvex.json", json.dumps(document))
      self.assert_rejected(VERIFIER.main, "VEX")

  def test_main_executes_dependency_and_absence_guards(self):
    self.write("SECURITY.md", "\n".join(VERIFIER.EXPECTED))
    for name in (
      "verify_prometheus", "verify_pgproto_backport", "verify_thrift_backport",
      "verify_grpc_backport", "verify_grpc_xds_absence", "verify_minimal_runtime",
      "verify_ssh_server_authentication_absence",
    ):
      override = patch.object(VERIFIER, name)
      override.start()
      self.addCleanup(override.stop)
    with patch.object(VERIFIER, "verify_s2_absence", wraps=VERIFIER.verify_s2_absence) as s2:
      with patch.object(VERIFIER, "verify_upstream_dependency_fixes", wraps=VERIFIER.verify_upstream_dependency_fixes) as fixes:
        with redirect_stdout(io.StringIO()):
          VERIFIER.main()
        s2.assert_called_once_with()
        fixes.assert_called_once_with()


class BackportPreimageProvenanceTests(unittest.TestCase):
  def setUp(self):
    directory = tempfile.TemporaryDirectory()
    self.addCleanup(directory.cleanup)
    self.directory = Path(directory.name)
    self.repository = self.directory / "repository"
    self.repository.mkdir()
    self.git("init", "--quiet", "--initial-branch=main")
    self.path = "engine/vendor/example/security.go"
    target = self.repository / self.path
    target.parent.mkdir(parents=True)
    target.write_bytes(b"original upstream implementation\n")
    self.record = {
      "path": self.path,
      "preimageSha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }
    self.git("add", ".")
    self.git("commit", "--quiet", "-m", "retained main baseline")
    self.commit = self.git("rev-parse", "HEAD").stdout.decode().strip()
    override = patch.object(PROVENANCE_VERIFIER, "ROOT", self.repository)
    override.start()
    self.addCleanup(override.stop)

  def git(self, *args, cwd=None, check=True):
    return subprocess.run(
      ["git", "-c", "user.name=R1DB tests", "-c", "user.email=r1db-tests@example.invalid",
       "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
      cwd=cwd or self.repository, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

  def assert_rejected(self, commit, record, message):
    with redirect_stderr(io.StringIO()) as output:
      with self.assertRaises(SystemExit) as failure:
        PROVENANCE_VERIFIER.check_security_backport_preimage(commit, record)
    self.assertEqual(failure.exception.code, 1)
    self.assertIn(message, output.getvalue())

  def test_matching_preimage_is_verified(self):
    PROVENANCE_VERIFIER.check_security_backport_preimage(self.commit, self.record)

  def test_missing_preimage_commit_is_rejected(self):
    self.assert_rejected("0" * 40, self.record, "commit is unavailable")

  def test_changed_preimage_hash_is_rejected(self):
    self.assert_rejected(self.commit, {**self.record, "preimageSha256": "0" * 64}, "hash differs")

  def test_missing_preimage_path_is_rejected(self):
    self.assert_rejected(self.commit, {**self.record, "path": "missing.go"}, "file is unavailable")

  def test_git_worktree_metadata_file_is_supported(self):
    worktree = self.directory / "worktree"
    self.git("worktree", "add", "--quiet", "--detach", str(worktree), self.commit)
    self.assertTrue((worktree / ".git").is_file())
    with patch.object(PROVENANCE_VERIFIER, "ROOT", worktree):
      PROVENANCE_VERIFIER.check_security_backport_preimage(self.commit, self.record)
      self.assert_rejected("0" * 40, self.record, "commit is unavailable")

  def test_broken_git_metadata_cannot_skip_preimages(self):
    broken = self.directory / "broken"
    broken.mkdir()
    (broken / ".git").write_text("gitdir: missing-git-directory\n")
    with patch.object(PROVENANCE_VERIFIER, "ROOT", broken):
      self.assert_rejected(self.commit, self.record, "checkout is unavailable")

  def test_malformed_git_metadata_cannot_use_a_parent_repository(self):
    broken = self.repository / "broken"
    broken.mkdir()
    for mode in ("empty directory", "dangling symlink"):
      with self.subTest(mode=mode):
        metadata = broken / ".git"
        if mode == "empty directory":
          metadata.mkdir()
        else:
          metadata.symlink_to("missing-git-directory")
        with patch.object(PROVENANCE_VERIFIER, "ROOT", broken):
          self.assert_rejected(self.commit, self.record, "checkout is unavailable")
        if mode == "empty directory":
          metadata.rmdir()
        else:
          metadata.unlink()

  def test_source_archive_does_not_require_git_history(self):
    archive = self.directory / "archive"
    archive.mkdir()
    with patch.object(PROVENANCE_VERIFIER, "ROOT", archive):
      with patch.object(PROVENANCE_VERIFIER.subprocess, "run", side_effect=AssertionError("Git invoked for archive")):
        PROVENANCE_VERIFIER.check_security_backport_preimage(self.commit, self.record)

  def test_archive_inside_another_checkout_ignores_its_history(self):
    archive = self.repository / "archive"
    archive.mkdir()
    with patch.object(PROVENANCE_VERIFIER, "ROOT", archive):
      with patch.object(PROVENANCE_VERIFIER.subprocess, "run", side_effect=AssertionError("Parent Git history used")):
        PROVENANCE_VERIFIER.check_security_backport_preimage(self.commit, self.record)

  def test_fresh_clone_after_squash_requires_retained_preimage(self):
    self.git("checkout", "--quiet", "-b", "feature")
    (self.repository / "cloudflared.txt").write_text("feature-only metadata\n")
    self.git("add", ".")
    self.git("commit", "--quiet", "-m", "PR-only first commit")
    pr_commit = self.git("rev-parse", "HEAD").stdout.decode().strip()
    (self.repository / self.path).write_text("patched implementation\n")
    self.git("add", ".")
    self.git("commit", "--quiet", "-m", "security backport")
    self.git("checkout", "--quiet", "main")
    self.git("merge", "--squash", "feature")
    self.git("commit", "--quiet", "-m", "squashed PR")
    clone = self.directory / "fresh-main"
    self.git("clone", "--quiet", "--no-local", "--single-branch", "--branch", "main",
             str(self.repository), str(clone), cwd=self.directory)
    self.assertNotEqual(self.git("cat-file", "-e", f"{pr_commit}^{{commit}}", cwd=clone, check=False).returncode, 0)
    with patch.object(PROVENANCE_VERIFIER, "ROOT", clone):
      PROVENANCE_VERIFIER.check_security_backport_preimage(self.commit, self.record)
      self.assert_rejected(pr_commit, self.record, "commit is unavailable")


if __name__ == "__main__":
  unittest.main()

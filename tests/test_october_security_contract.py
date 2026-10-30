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
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
  "october_security_vex", ROOT / "scripts/verify-security-vex.py",
)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
ADVISORIES = ("CVE-2026-78669", "CVE-2026-56851")


class OctoberSecurityContractTests(unittest.TestCase):
  def setUp(self):
    directory = tempfile.TemporaryDirectory()
    self.addCleanup(directory.cleanup)
    self.root = Path(directory.name)
    for relative in (
      "engine/go.mod", "engine/vendor/modules.txt", "source/runtime-files.txt",
      "source/ratio1-engine-overrides.json", "security/openvex.json",
    ):
      self.write(relative, (ROOT / relative).read_bytes())
    for expected in VERIFIER.OCTOBER_BACKPORTS.values():
      for relative in expected["files"]:
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

  def save_overrides(self, data):
    self.write("source/ratio1-engine-overrides.json", json.dumps(data))

  def backport(self, data, advisory):
    return next(item for item in data["securityBackports"] if item["advisory"] == advisory)

  def assert_rejected(self, callback, message):
    with redirect_stderr(io.StringIO()) as output:
      with self.assertRaises(SystemExit) as failure:
        callback()
    self.assertEqual(failure.exception.code, 1)
    self.assertIn(message, output.getvalue())

  def test_official_backports_and_absent_s2_are_accepted(self):
    for advisory in ADVISORIES:
      VERIFIER.verify_october_backport(advisory)
    VERIFIER.verify_s2_absence()

  def test_new_vex_decisions_have_exact_versions_status_and_aliases(self):
    expected = {
      "CVE-2026-78669": ("golang.org/x/net@v0.56.0", "fixed", "GO-2026-6611"),
      "CVE-2026-56851": ("golang.org/x/text@v0.39.0", "fixed", "GO-2026-6629"),
      "CVE-2026-63209": ("github.com/klauspost/compress@v1.17.8", "not_affected", "GHSA-259r-337f-4rfw"),
    }
    self.assertEqual(self.document["version"], 10)
    self.assertEqual(self.document["@id"], "https://github.com/Ratio1/r1db/security/vex/10")
    self.assertEqual(len(self.document["statements"]), 16)
    for advisory, (product, status, alias) in expected.items():
      statements = [s for s in self.document["statements"] if s["vulnerability"]["@id"].endswith(advisory)]
      self.assertEqual(len(statements), 1)
      statement = statements[0]
      self.assertEqual(statement["products"], [{"@id": "pkg:golang/" + product}])
      self.assertEqual(statement["status"], status)
      self.assertEqual(set(statement["vulnerability"]["aliases"]), {advisory, alias})
      self.assertEqual(VERIFIER.validate_statement(statement), advisory)
      if status == "not_affected":
        self.assertEqual(statement["justification"], "vulnerable_code_not_present")
      for field, value in (
        ("products", [{"@id": "pkg:golang/" + product + "0"}]),
        ("status", "affected"), ("justification", "vulnerable_code_not_in_execute_path"),
      ):
        with self.subTest(advisory=advisory, field=field):
          changed = copy.deepcopy(statement)
          changed[field] = value
          self.assert_rejected(lambda: VERIFIER.validate_statement(changed), "VEX")
      changed = copy.deepcopy(statement)
      changed["vulnerability"]["aliases"] = [advisory]
      self.assert_rejected(lambda: VERIFIER.validate_statement(changed), "aliases differ")
      changed = copy.deepcopy(statement)
      changed.pop("status_notes" if status == "fixed" else "impact_statement")
      self.assert_rejected(lambda: VERIFIER.validate_statement(changed), "no evidence")

  def test_missing_duplicate_and_incomplete_backports_are_rejected(self):
    for advisory in ADVISORIES:
      for mutation in ("missing", "duplicate", "missing file", "duplicate file", "extra file"):
        with self.subTest(advisory=advisory, mutation=mutation):
          data = copy.deepcopy(self.overrides)
          record = self.backport(data, advisory)
          if mutation == "missing":
            data["securityBackports"].remove(record)
          elif mutation == "duplicate":
            data["securityBackports"].append(copy.deepcopy(record))
          elif mutation == "missing file":
            record["files"].pop()
          elif mutation == "duplicate file":
            record["files"][-1] = copy.deepcopy(record["files"][0])
          else:
            record["files"].append({"path": "engine/vendor/unreviewed.go"})
          self.save_overrides(data)
          self.assert_rejected(lambda: VERIFIER.verify_october_backport(advisory), "backport")

  def test_changed_backport_origin_preimage_and_change_type_are_rejected(self):
    for advisory in ADVISORIES:
      for field, value in (
        ("module", "golang.org/x/net@v0.60.0"), ("source", "https://example.invalid/fix"),
        ("preimageCommit", "0" * 40), ("preimageSha256", "0" * 64),
        ("changeType", "ratio1-added"), ("sha256", "0" * 64), ("sha256", "pending"),
      ):
        with self.subTest(advisory=advisory, field=field, value=value):
          data = copy.deepcopy(self.overrides)
          record = self.backport(data, advisory)
          target = record["files"][0] if field in {"preimageSha256", "changeType", "sha256"} else record
          target[field] = value
          self.save_overrides(data)
          self.assert_rejected(lambda: VERIFIER.verify_october_backport(advisory), "backport")

  def test_every_implementation_and_regression_hash_is_enforced(self):
    for advisory in ADVISORIES:
      record = self.backport(self.overrides, advisory)
      for item in record["files"]:
        with self.subTest(path=item["path"]):
          path = self.root / item["path"]
          original = path.read_bytes()
          path.write_bytes(original + b"\n// changed\n")
          self.assert_rejected(lambda: VERIFIER.verify_october_backport(advisory), "hash differs")
          path.unlink()
          self.assert_rejected(lambda: VERIFIER.verify_october_backport(advisory), "hash differs")
          path.write_bytes(original)

  def test_reverted_fix_or_missing_regression_is_rejected_even_with_updated_hash(self):
    for advisory in ADVISORIES:
      expected = VERIFIER.OCTOBER_BACKPORTS[advisory]
      for relative in expected["files"]:
        with self.subTest(path=relative):
          path = self.root / relative
          original = path.read_bytes()
          marker = expected["markers"][path.name][0].encode()
          changed = original.replace(marker, b"removed security evidence", 1)
          self.assertNotEqual(original, changed)
          path.write_bytes(changed)
          data = copy.deepcopy(self.overrides)
          record = self.backport(data, advisory)
          next(item for item in record["files"] if item["path"] == relative)["sha256"] = hashlib.sha256(changed).hexdigest()
          self.save_overrides(data)
          self.assert_rejected(lambda: VERIFIER.verify_october_backport(advisory), "evidence is absent")
          path.write_bytes(original)

  def test_backport_implementation_cannot_disappear_from_runtime_evidence(self):
    original = (self.root / "source/runtime-files.txt").read_text()
    for advisory in ADVISORIES:
      for relative, preimage in VERIFIER.OCTOBER_BACKPORTS[advisory]["files"].items():
        if preimage is None:
          continue
        with self.subTest(path=relative):
          self.write("source/runtime-files.txt", original.replace(relative.removeprefix("engine/") + "\n", ""))
          self.assert_rejected(lambda: VERIFIER.verify_october_backport(advisory), "absent from the runtime closure")

  def test_exact_module_versions_are_checked_in_both_manifests(self):
    for module, version in (
      ("github.com/klauspost/compress", "v1.17.8"),
      ("golang.org/x/net", "v0.56.0"), ("golang.org/x/text", "v0.39.0"),
    ):
      for relative in ("engine/go.mod", "engine/vendor/modules.txt"):
        path = self.root / relative
        original = path.read_text()
        with self.subTest(module=module, path=relative):
          path.write_text(original.replace(module + " " + version, module + " " + version + "0"))
          self.assert_rejected(lambda: VERIFIER.verify_exact_engine_module(module, version), "version differs")
          path.write_text(original)

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
      with self.subTest(entry=entry):
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
      with self.subTest(entry=entry):
        path.write_text(original + entry + "\n")
        self.assert_rejected(VERIFIER.verify_s2_absence, "runtime closure unexpectedly includes S2")

  def test_vex_document_rejects_old_identity_version_missing_and_duplicate_decisions(self):
    for mutation in ("identity", "version", "missing", "duplicate"):
      with self.subTest(mutation=mutation):
        document = copy.deepcopy(self.document)
        if mutation == "identity":
          document["@id"] = "https://github.com/Ratio1/r1db/security/vex/9"
        elif mutation == "version":
          document["version"] = 9
        elif mutation == "missing":
          document["statements"].pop()
        else:
          document["statements"][-1] = copy.deepcopy(document["statements"][0])
        self.write("security/openvex.json", json.dumps(document))
        self.assert_rejected(VERIFIER.main, "VEX")

  def test_main_executes_all_october_guards(self):
    self.write("SECURITY.md", "\n".join(VERIFIER.EXPECTED))
    existing = (
      "verify_prometheus", "verify_pgproto_backport", "verify_thrift_backport",
      "verify_grpc_backport", "verify_grpc_xds_absence", "verify_minimal_runtime",
      "verify_ssh_server_authentication_absence",
    )
    for name in existing:
      override = patch.object(VERIFIER, name)
      override.start()
      self.addCleanup(override.stop)
    with patch.object(VERIFIER, "verify_s2_absence", wraps=VERIFIER.verify_s2_absence) as s2:
      with patch.object(VERIFIER, "verify_october_backport", wraps=VERIFIER.verify_october_backport) as backport:
        with redirect_stdout(io.StringIO()):
          VERIFIER.main()
        s2.assert_called_once_with()
        self.assertEqual([call.args[0] for call in backport.call_args_list], list(ADVISORIES))


if __name__ == "__main__":
  unittest.main()

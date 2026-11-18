import hashlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import shutil  # Build real archive-style patch fixtures without repository metadata.
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
  "cloudflared_source_contract", ROOT / "scripts/verify-cloudflared-source.py",
)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
REFRESH_SPEC = importlib.util.spec_from_file_location(
  "cloudflared_evidence_refresh", ROOT / "scripts/refresh-cloudflared-evidence.py",
)
REFRESH = importlib.util.module_from_spec(REFRESH_SPEC)
REFRESH_SPEC.loader.exec_module(REFRESH)


class CloudflaredSourceContractTests(unittest.TestCase):
  def test_inherited_license_origin_uses_matching_repository_root(self):
    content = b"retained license bytes"
    origin = {"URL": "https://github.com/example/modules", "Hash": "a" * 40, "Subdir": "trace"}
    with patch.object(REFRESH, "urlopen", side_effect=[
      HTTPError("missing", 404, "missing", {}, None), io.BytesIO(content),
    ]):
      url = REFRESH.verified_license_url(origin, "LICENSE", hashlib.sha256(content).hexdigest())
    self.assertEqual(url, f"https://github.com/example/modules/blob/{'a' * 40}/LICENSE")

  def test_origin_with_different_license_bytes_is_rejected(self):
    origin = {"URL": "https://github.com/example/modules", "Hash": "a" * 40}
    with patch.object(REFRESH, "urlopen", return_value=io.BytesIO(b"different")):
      with self.assertRaises(ValueError):
        REFRESH.verified_license_url(origin, "LICENSE", hashlib.sha256(b"expected").hexdigest())

  def setUp(self):
    self.directory = tempfile.TemporaryDirectory()
    self.addCleanup(self.directory.cleanup)
    self.root = Path(self.directory.name)
    (self.root / "source").mkdir()
    self.source = self.root / "upstream"
    self.transport = self.source / "vendor/google.golang.org/grpc/internal/transport/transport.go"
    self.transport.parent.mkdir(parents=True)
    self.transport.write_text(
      "compactionThreshold EnableReceiveBufferCompaction uncompactedSuffixLen mem.NewBuffer(newBuf",
    )
    self.modules = self.source / "vendor/modules.txt"
    self.modules.write_text("# google.golang.org/grpc v1.83.2\n")
    self.provenance = {"buildInputs": {"cloudflared": {"securityBackports": []}}}
    self.save_provenance()
    self.root_patch = patch.object(VERIFIER, "ROOT", self.root)
    self.root_patch.start()
    self.addCleanup(self.root_patch.stop)

  def save_provenance(self):
    (self.root / "source/provenance.json").write_text(json.dumps(self.provenance))

  def test_upstream_fixed_grpc_is_accepted(self):
    VERIFIER.verify_grpc_security_fix(self.source)

  def test_old_grpc_is_rejected(self):
    self.modules.write_text("# google.golang.org/grpc v1.83.0\n")
    with self.assertRaises(SystemExit):
      VERIFIER.verify_grpc_security_fix(self.source)

  def test_removed_receive_buffer_fix_is_rejected(self):
    self.transport.write_text("package transport\n")
    with self.assertRaises(SystemExit):
      VERIFIER.verify_grpc_security_fix(self.source)

  def test_obsolete_backport_record_is_rejected(self):
    self.provenance["buildInputs"]["cloudflared"]["securityBackports"] = [{"module": "old"}]
    self.save_provenance()
    with self.assertRaises(SystemExit):
      VERIFIER.verify_grpc_security_fix(self.source)

  def test_changed_module_evidence_is_rejected(self):
    evidence = self.root / "source/cloudflared-module-sources.json"
    evidence.write_text("{}\n")
    cloud = self.provenance["buildInputs"]["cloudflared"]
    cloud["commit"] = VERIFIER.COMMIT
    for key, relative in (
      ("goModSha256", "go.mod"), ("goSumSha256", "go.sum"),
      ("vendorModulesSha256", "vendor/modules.txt"), ("licenseSha256", "LICENSE"),
    ):
      path = self.source / relative
      if not path.exists():
        path.write_text("fixture\n")
      cloud[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    cloud["moduleSourcesSha256"] = hashlib.sha256(evidence.read_bytes()).hexdigest()
    self.save_provenance()
    with patch.object(VERIFIER, "MODULE_SOURCES", evidence):
      VERIFIER.verify_source_hashes(self.source)
      evidence.write_text('{"changed": true}\n')
      with self.assertRaises(SystemExit):
        VERIFIER.verify_source_hashes(self.source)


class CloudflaredDependencyUpdateTests(unittest.TestCase):
  def setUp(self):
    self.directory = tempfile.TemporaryDirectory()
    self.addCleanup(self.directory.cleanup)
    self.root = Path(self.directory.name)
    self.source = self.root / "upstream"
    self.source.mkdir()
    (self.root / "source").mkdir()
    self.cloud = {"dependencyUpdates": [copy.deepcopy(VERIFIER.DEPENDENCY_UPDATE)]}
    self.patch_path = self.root / VERIFIER.DEPENDENCY_UPDATE["patch"]
    self.patch_path.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / VERIFIER.DEPENDENCY_UPDATE["patch"], self.patch_path)
    for name in ("go.mod", "go.sum"):  # Use real complete manifests rather than reconstructed implementation-shaped fixtures.
      shutil.copyfile(ROOT / f"source/cloudflared-{name}", self.source / name)
      shutil.copyfile(self.source / name, self.root / f"source/cloudflared-{name}")
    (self.source / "vendor").mkdir()
    self.modules = self.source / "vendor/modules.txt"
    self.modules.write_text("# golang.org/x/net v0.62.0\n")
    self.record = {
      "module": "golang.org/x/net", "version": "v0.62.0",
      "sum": "h1:18ELalfM5+XNRwzM2nYqXsZQ9ByS1uhj2O/U7+5jqRY=",
      "goModSum": "h1:WgDCOTH8iwtB66T4/GfI94AHo/hhdb7Hah9NDseQfiI=",
      "origin": {"VCS": "git", "URL": "https://go.googlesource.com/net", "Hash": "3de643db506517b3e652a13cc0b56034cea6b8e6", "Ref": "refs/tags/v0.62.0"},
      "licenseUrl": "https://go.googlesource.com/net/+/3de643db506517b3e652a13cc0b56034cea6b8e6/LICENSE",
      "licenseSha256": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    }
    self.evidence = self.root / "source/cloudflared-module-sources.json"
    self.evidence.write_text(json.dumps({"golang.org/x/net": self.record}))
    self.build_info = "\tdep\tgolang.org/x/net\tv0.62.0\t\n"
    for name, value in (("ROOT", self.root), ("MODULE_SOURCES", self.evidence)):
      context = patch.object(VERIFIER, name, value)
      context.start()
      self.addCleanup(context.stop)

  def test_reviewed_patch_reconstructs_exact_immutable_upstream_manifests(self):
    VERIFIER.verify_dependency_update(self.source, self.cloud)
    self.assertFalse((self.source / ".git").exists())

  def test_stale_or_widened_override_declarations_are_rejected(self):
    for field, value in (("toVersion", "v0.61.0"), ("patchSha256", "0" * 64), ("sourceCommit", "0" * 40), ("preimageSha256", {}), ("resultSha256", {})):
      with self.subTest(field=field):
        cloud = copy.deepcopy(self.cloud)
        cloud["dependencyUpdates"][0][field] = value
        with self.assertRaises(SystemExit):
          VERIFIER.verify_dependency_update(self.source, cloud)
    for updates in (None, [], self.cloud["dependencyUpdates"] * 2):
      with self.subTest(updates=updates), self.assertRaises(SystemExit):
        VERIFIER.verify_dependency_update(self.source, {"dependencyUpdates": updates})

  def test_changed_or_missing_patch_is_rejected(self):
    self.patch_path.write_text(self.patch_path.read_text() + "\n")
    with self.assertRaises(SystemExit):
      VERIFIER.verify_dependency_update(self.source, self.cloud)
    self.patch_path.unlink()
    with self.assertRaises(SystemExit):
      VERIFIER.verify_dependency_update(self.source, self.cloud)

  def test_changed_source_or_retained_manifests_are_rejected(self):
    for name in ("go.mod", "go.sum"):
      for path in (self.source / name, self.root / f"source/cloudflared-{name}"):
        with self.subTest(path=path):
          original = path.read_bytes()
          path.write_bytes(original + b"\n")
          with self.assertRaises(SystemExit):
            VERIFIER.verify_dependency_update(self.source, self.cloud)
          path.write_bytes(original)

  def test_patch_that_does_not_reconstruct_upstream_is_rejected(self):
    with patch.object(VERIFIER.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()):
      with self.assertRaises(SystemExit):
        VERIFIER.verify_dependency_update(self.source, self.cloud)

  def test_correct_xnet_source_origin_and_checksums_are_accepted(self):
    VERIFIER.verify_xnet_evidence(self.build_info, self.source)

  def test_stale_or_replaced_compiled_xnet_is_rejected(self):
    for metadata in (self.build_info.replace("v0.62.0", "v0.61.0"), self.build_info * 2, self.build_info + "\t=>\t/tmp/net\t(devel)\t\n", self.build_info + "\t=>\texample.com/net\tv0.62.0\t\n"):
      with self.subTest(metadata=metadata), self.assertRaises(SystemExit):
        VERIFIER.verify_compiled_xnet(metadata)

  def test_stale_or_replaced_vendored_xnet_is_rejected(self):
    for metadata in ("# golang.org/x/net v0.61.0\n", "# golang.org/x/net v0.62.0 => /tmp/net\n", "# golang.org/x/net v0.62.0\n# golang.org/x/net => /tmp/net\n"):
      self.modules.write_text(metadata)
      with self.subTest(metadata=metadata), self.assertRaises(SystemExit):
        VERIFIER.verify_xnet_evidence(self.build_info, self.source)

  def test_missing_module_or_manifest_checksum_is_rejected(self):
    path = self.source / "go.sum"
    original = path.read_text()
    for version in ("v0.62.0", "v0.62.0/go.mod"):
      path.write_text("\n".join(line for line in original.splitlines() if not line.startswith(f"golang.org/x/net {version} ")) + "\n")
      with self.subTest(version=version), self.assertRaises(SystemExit):
        VERIFIER.verify_xnet_evidence(self.build_info, self.source)

  def test_stale_or_tampered_module_origin_and_license_are_rejected(self):
    for field, value in (("version", "v0.61.0"), ("sum", "h1:changed"), ("goModSum", "h1:changed"), ("origin", {**VERIFIER.NET_ORIGIN, "Hash": "0" * 40}), ("licenseSha256", "0" * 64), ("licenseUrl", "https://example.com/LICENSE")):
      record = copy.deepcopy(self.record)
      record[field] = value
      self.evidence.write_text(json.dumps({"golang.org/x/net": record}))
      with self.subTest(field=field), self.assertRaises(SystemExit):
        VERIFIER.verify_xnet_evidence(self.build_info, self.source)

  def test_separate_provenance_output_preserves_shared_manifest(self):
    shared = self.root / "source/provenance.json"
    shared.write_text('{"parent":"unchanged"}\n')
    output = self.root / "cloudflared-only.json"
    provenance = {"buildInputs": {"cloudflared": self.cloud, "engine": {"parent": True}}}
    with patch.object(REFRESH, "ROOT", self.root):
      REFRESH.write_provenance(provenance, output)
      self.assertEqual(shared.read_text(), '{"parent":"unchanged"}\n')
      self.assertEqual(json.loads(output.read_text()), self.cloud)
      REFRESH.write_provenance(provenance, None)
      self.assertEqual(json.loads(shared.read_text()), provenance)

  def test_public_github_api_resolves_origin_without_cli_authentication(self):
    responses = [io.BytesIO(b"{}"), io.BytesIO(json.dumps({"sha": "a" * 40}).encode())]
    with patch.object(REFRESH, "urlopen", side_effect=responses) as requests:  # Require only public HTTP, never local gh state.
      origin = REFRESH.origin({"Path": "github.com/example/module", "Version": "v1.2.3"})
    self.assertEqual(origin["Hash"], "a" * 40)
    request = requests.call_args_list[1].args[0]
    self.assertEqual(request.full_url, "https://api.github.com/repos/example/module/commits/v1.2.3")
    self.assertNotIn("Authorization", request.headers)

  def test_binary_version_time_hash_and_compiled_release_are_enforced(self):
    binary = self.root / "cloudflared"
    binary.write_bytes(b"hash-bound executable fixture")
    cloud = {"version": VERIFIER.VERSION, "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    metadata = "/cloudflared: go1.27.3\n\tdep\tgoogle.golang.org/grpc\tv1.83.2\t\n\tdep\tgolang.org/x/text\tv0.43.0\t\n" + self.build_info
    version = f"cloudflared version {VERIFIER.VERSION} (built 2026-10-29-11:55_UTC)\n"
    with patch.object(VERIFIER, "cloudflared_provenance", return_value=cloud), patch.object(VERIFIER.subprocess, "check_output", return_value=version):
      VERIFIER.verify_binary(metadata, binary)
      with self.assertRaises(SystemExit):
        VERIFIER.verify_binary(metadata.replace("v0.62.0", "v0.61.0"), binary)
      cloud["version"] = "2026.10.6-r1.35b379a"
      with self.assertRaises(SystemExit):
        VERIFIER.verify_binary(metadata, binary)
      cloud["version"] = VERIFIER.VERSION
      binary.write_bytes(b"changed binary")
      with self.assertRaises(SystemExit):
        VERIFIER.verify_binary(metadata, binary)
    binary.write_bytes(b"hash-bound executable fixture")
    for output in (version.replace(VERIFIER.VERSION, "2026.10.6-r1.35b379a"), version.replace("2026-10-29-11:55_UTC", "2026-11-13-00:00_UTC")):
      with self.subTest(output=output), patch.object(VERIFIER, "cloudflared_provenance", return_value=cloud), patch.object(VERIFIER.subprocess, "check_output", return_value=output):
        with self.assertRaises(SystemExit):
          VERIFIER.verify_binary(metadata, binary)


if __name__ == "__main__":
  unittest.main()

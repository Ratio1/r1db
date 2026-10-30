import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
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


if __name__ == "__main__":
  unittest.main()

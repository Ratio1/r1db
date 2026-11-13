#!/usr/bin/env python3
"""Refresh reviewed cloudflared evidence from a source build."""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import quote  # Encode subdirectory tag names for public GitHub commit lookups.
from urllib.request import Request, urlopen  # Public API origin fallback must not depend on local gh credentials.


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "35b379ac174d60a4301615defedc821de5625cef"
EXTRA_SPDX = {
  "github.com/ebitengine/purego": "Apache-2.0",
  "github.com/go-logr/logr": "Apache-2.0",
  "github.com/go-logr/stdr": "Apache-2.0",
  "github.com/go-jose/go-jose/v4": "Apache-2.0 AND BSD-3-Clause",
  "github.com/prometheus/client_golang": "Apache-2.0 AND BSD-3-Clause",
}


def digest(path: Path) -> str:
  return hashlib.sha256(path.read_bytes()).hexdigest()


def escape_module(value: str) -> str:
  return "".join("!" + char.lower() if char.isupper() else char for char in value)


def objects(value: str) -> list[dict]:
  decoder = json.JSONDecoder()
  result = []
  while value.strip():
    item, end = decoder.raw_decode(value.lstrip())
    result.append(item)
    value = value.lstrip()[end:]
  return result


def origin(item: dict) -> dict:
  url = f"https://proxy.golang.org/{escape_module(item['Path'])}/@v/{item['Version']}.info"
  with urlopen(url, timeout=60) as response:
    result = json.load(response).get("Origin", {})
  if not re.fullmatch(r"[0-9a-f]{40}", result.get("Hash", "")):
    aliases = {
      "gopkg.in/yaml.v2": "go-yaml/yaml",
      "gopkg.in/yaml.v3": "go-yaml/yaml",
      "gopkg.in/natefinch/lumberjack.v2": "natefinch/lumberjack",
      "go.uber.org/automaxprocs": "uber-go/automaxprocs",
      "nhooyr.io/websocket": "nhooyr/websocket",
      "zombiezen.com/go/capnproto2": "zombiezen/go-capnproto2",
    }
    module = item["Path"]
    if module.startswith("github.com/"):
      repo = "/".join(module.split("/")[1:3])
      subdir = "/".join(module.split("/")[3:])
      if re.fullmatch(r"v[0-9]+", subdir):
        subdir = ""
    else:
      repo = aliases.get(module)
      subdir = ""
      if module.startswith("go.opentelemetry.io/contrib/"):
        repo = "open-telemetry/opentelemetry-go-contrib"
        subdir = module.removeprefix("go.opentelemetry.io/contrib/")
    if not repo:
      raise ValueError(f"Review immutable module origin: {module}")
    version = item["Version"].removesuffix("+incompatible")
    revision = version.rsplit("-", 1)[-1] if re.search(r"-[0-9a-f]{12}$", version) else f"{subdir}/{version}".lstrip("/")
    request = Request(  # Resolve old proxy entries without invoking the authenticated GitHub CLI.
      f"https://api.github.com/repos/{repo}/commits/{quote(revision, safe='')}",
      headers={"Accept": "application/vnd.github+json", "User-Agent": "r1db-cloudflared-evidence"},
    )
    with urlopen(request, timeout=60) as response:  # The public endpoint returns the immutable full commit.
      commit = json.load(response).get("sha", "")  # Never trust a tag name as a commit hash.
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
      raise ValueError(f"Invalid module origin commit: {module}")
    result = {"VCS": "git", "URL": f"https://github.com/{repo}", "Hash": commit}
    if subdir:
      result["Subdir"] = subdir
  return result


def verified_license_url(module_origin: dict, filename: str, expected_hash: str) -> str:
  repo = module_origin["URL"].removesuffix(".git")
  commit = module_origin["Hash"]
  components = module_origin.get("Subdir", "").strip("/").split("/")
  if components == [""]:
    components = []
  for depth in range(len(components), -1, -1):
    relative = "/".join([*components[:depth], filename])
    if repo.startswith("https://github.com/"):
      path = repo.removeprefix("https://github.com/")
      fetch_url = f"https://raw.githubusercontent.com/{path}/{commit}/{relative}"
      public_url = f"{repo}/blob/{commit}/{relative}"
    elif repo.startswith("https://go.googlesource.com/"):
      public_url = f"{repo}/+/{commit}/{relative}"
      fetch_url = public_url + "?format=TEXT"
    else:
      raise ValueError(f"Review license origin URL: {repo}")
    try:
      with urlopen(fetch_url, timeout=60) as response:
        content = response.read()
    except HTTPError as exc:
      if exc.code == 404:
        continue
      raise
    if repo.startswith("https://go.googlesource.com/"):
      content = base64.b64decode(content)
    if hashlib.sha256(content).hexdigest() == expected_hash:
      return public_url
  raise ValueError(f"No immutable origin matches retained license bytes: {repo}/{filename}")


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--source-root", required=True, type=Path)
  parser.add_argument("--evidence-dir", required=True, type=Path)
  parser.add_argument("--provenance-output", type=Path, help="Write only the Cloudflared buildInputs object to this path")  # Avoid shared-manifest writes.
  args = parser.parse_args()
  source = args.source_root.resolve()
  evidence = args.evidence_dir.resolve()
  spec = importlib.util.spec_from_file_location("cloud_verifier", ROOT / "scripts/verify-cloudflared-source.py")
  verifier = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(verifier)
  updates = [verifier.DEPENDENCY_UPDATE]  # Emit the one reviewed mod/sum patch as an explicit source modification.
  verifier.verify_dependency_update(source, {"dependencyUpdates": updates})  # Reject stale or tampered sources before refreshing notices.

  info_lines = (evidence / "buildinfo.txt").read_text().splitlines()
  info_lines[0] = "/cloudflared: " + info_lines[0].partition(": ")[2]
  build_info = "\n".join(info_lines) + "\n"
  verifier.verify_compiled_xnet(build_info)  # Refuse to refresh evidence for a stale or replaced binary dependency.
  packages = "\n".join(sorted(set((evidence / "compiled-packages.txt").read_text().splitlines()))) + "\n"
  if "runtime/cgo" in packages.splitlines():  # Package evidence must use the same CGO_ENABLED=0 setting as the executable.
    raise ValueError("Cloudflared package evidence was collected with cgo enabled")
  needed = verifier.module_paths(build_info) - {"github.com/cloudflare/cloudflared"}
  downloads = {item["Path"]: item for item in objects((evidence / "module-downloads.json").read_text())}
  replacements = {}
  lines = build_info.splitlines()
  for index, line in enumerate(lines[:-1]):
    fields = line.split("\t")
    following = lines[index + 1].split("\t")
    if len(fields) >= 4 and fields[1] == "dep" and len(following) >= 4 and following[1] == "=>" and fields[2] != following[2]:
      replacements[fields[2]] = following[2]
  actual_modules = sorted(needed - replacements.keys())
  with ThreadPoolExecutor(max_workers=8) as executor:
    origins = dict(zip(actual_modules, executor.map(origin, [downloads[module] for module in actual_modules])))
  with (ROOT / "source/cloudflared-license-inventory.csv").open(newline="") as handle:
    old_rows = list(csv.DictReader(handle))
  conclusions = {row["package"]: row["spdx"] for row in old_rows}
  saved_external = {}
  for relative, _ in verifier.EXTERNAL_LICENSES.values():
    saved_external[relative] = (ROOT / "licenses/cloudflared" / relative).read_bytes()
  verifier.copy_notices(source)
  for relative, content in saved_external.items():
    path = ROOT / "licenses/cloudflared" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)

  records = {}
  rows = [{
    "package": "github.com/cloudflare/cloudflared",
    "license_url": f"https://github.com/cloudflare/cloudflared/blob/{COMMIT}/LICENSE",
    "spdx": "Apache-2.0",
  }]
  for module in sorted(needed):
    actual = replacements.get(module, module)
    item = downloads[actual]
    module_origin = origins[actual]
    vendor_root = source / "vendor" / module
    if not vendor_root.is_dir():
      original = next((name for name, replacement in replacements.items() if replacement == module), None)
      vendor_root = source / "vendor" / (original or module)
    candidates = sorted(path for path in vendor_root.iterdir() if path.is_file() and verifier.is_license_file(path))
    if not candidates and module == "github.com/facebookgo/grace":
      candidates = [ROOT / "licenses/cloudflared/dependencies/github.com/facebookgo/grace/license"]
    if not candidates:
      raise ValueError(f"No retained license for {module}")
    license_path = next((path for path in candidates if path.name.lower().split(".")[0] in {"license", "licence"}), candidates[0])
    spdx = EXTRA_SPDX.get(module) or conclusions.get(module)
    if not spdx:
      prior = {row["spdx"] for row in old_rows if row["package"].startswith(module + "/")}
      if len(prior) == 1:
        spdx = prior.pop()
    if not spdx:
      raise ValueError(f"Review SPDX conclusion for {module}")
    url = verified_license_url(module_origin, license_path.name, digest(license_path))
    rows.append({"package": module, "license_url": url, "spdx": spdx})
    records[module] = {
      "module": actual,
      "version": item["Version"],
      "sum": item["Sum"],
      "origin": module_origin,
      "licenseUrl": url,
      "licenseSha256": digest(license_path),
    }
    if module == "golang.org/x/net":  # Retain both authenticated checksums for the explicit dependency override.
      records[module]["goModSum"] = item["GoModSum"]  # Bind the upgraded release's dependency manifest too.
  (ROOT / "source/cloudflared-buildinfo.txt").write_text(build_info)
  (ROOT / "source/cloudflared-compiled-packages.txt").write_text(packages)
  module_sources = ROOT / "source/cloudflared-module-sources.json"
  module_sources.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
  with (ROOT / "source/cloudflared-license-inventory.csv").open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=["package", "license_url", "spdx"], lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
  provenance_path = ROOT / "source/provenance.json"
  provenance = json.loads(provenance_path.read_text())
  cloud = provenance["buildInputs"]["cloudflared"]
  cloud.update({
    "commit": COMMIT,
    "gitTree": "c2c5fd1befe1f0794180eda8558fc429e859a164",
    "sourceArchiveUrl": f"https://github.com/cloudflare/cloudflared/archive/{COMMIT}.tar.gz",
    "sourceArchiveSha256": "ee21af3280b31559b257e40ff6024956c066e3da6fded6810bf2b3e4749c1186",
    "sourceDateEpoch": 1793274907,
    "version": verifier.VERSION,  # Mark binaries built from the reviewed dependency patch.
    "binarySha256": digest(evidence / "cloudflared"),
    "goBuilder": "golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9",
    "goModSha256": digest(source / "go.mod"),
    "goSumSha256": digest(source / "go.sum"),
    "vendorModulesSha256": digest(source / "vendor/modules.txt"),
    "licenseSha256": digest(source / "LICENSE"),
    "moduleSources": "source/cloudflared-module-sources.json",
    "moduleSourcesSha256": digest(module_sources),
    "securityBackports": [],
    "dependencyUpdates": updates,  # Preserve the unchanged upstream source identity alongside the modification.
  })
  verifier.verify_xnet_evidence(build_info, source)  # Reject mismatched proxy origins, sums, and license evidence before publication.
  write_provenance(provenance, args.provenance_output)  # An explicit output never rewrites the shared provenance file.
  print(f"Refreshed {len(rows)} license records and {len(packages.splitlines())} compiled packages")


def write_provenance(provenance: dict, output: Path | None) -> None:
  """Write the full manifest by default, or only Cloudflared to an explicit path."""
  path = output or ROOT / "source/provenance.json"  # Keep normal callers' destination unchanged.
  document = provenance["buildInputs"]["cloudflared"] if output else provenance  # Limit the disjoint output to its owned object.
  path.write_text(json.dumps(document, indent=2) + "\n")  # Produce deterministic reviewable JSON with a final newline.


if __name__ == "__main__":
  main()

#!/usr/bin/env python3
"""Verify the pinned Cloudflared source build and its notice closure."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
BUILD_INFO = ROOT / "source" / "cloudflared-buildinfo.txt"
PACKAGES = ROOT / "source" / "cloudflared-compiled-packages.txt"
INVENTORY = ROOT / "source" / "cloudflared-license-inventory.csv"
LICENSE_ROOT = ROOT / "licenses" / "cloudflared"
LICENSE_NAMES = {"license", "licence", "copying", "notice", "patents"}
COMMIT = "35b379ac174d60a4301615defedc821de5625cef"
MODULE_SOURCES = ROOT / "source/cloudflared-module-sources.json"
EXTERNAL_LICENSES = {
  "github.com/facebookgo/grace": (
    "dependencies/github.com/facebookgo/grace/license",
    "f657f99d3fb9647db92628e96007aabb46e5f04f33e49999075aab8e250ca7ce",
  ),
}
SSH_USAGE_VERIFIER = ROOT / "scripts" / "verify_cloudflared_ssh_usage.go"
SSH_USAGE_TESTS = ROOT / "scripts" / "verify_cloudflared_ssh_usage_test.go"


def fail(message: str) -> None:
  print(f"cloudflared compliance error: {message}", file=sys.stderr)
  raise SystemExit(1)


def sha256(path: Path) -> str:
  return hashlib.sha256(path.read_bytes()).hexdigest()


def is_license_file(path: Path) -> bool:
  return path.name.lower().split(".", 1)[0] in LICENSE_NAMES


def run(command: list[str], cwd: Path) -> str:
  environment = {
    **os.environ,
    "GOPROXY": "off",
    "GOSUMDB": "off",
    "GOFLAGS": "-buildvcs=false",
    "CGO_ENABLED": "0",
    "GOOS": "linux",
    "GOARCH": "amd64",
    "GOAMD64": "v1",
  }
  return subprocess.run(
    command,
    cwd=cwd,
    env=environment,
    check=True,
    text=True,
    stdout=subprocess.PIPE,
  ).stdout


def normalized_build_info(binary: Path, source_root: Path) -> str:
  output = run(["go", "version", "-m", str(binary)], source_root)
  lines = output.splitlines()
  if not lines:
    fail("go version -m returned no build metadata")
  _, separator, version = lines[0].partition(": ")
  if not separator:
    fail("go version -m first line is malformed")
  lines[0] = f"/cloudflared: {version}"
  return "\n".join(lines) + "\n"


def compiled_packages(source_root: Path) -> str:
  output = run(
    ["go", "list", "-mod=vendor", "-deps", "./cmd/cloudflared"],
    source_root,
  )
  return "\n".join(sorted(set(output.splitlines()))) + "\n"


def verify_ssh_server_authentication_absence(source_root: Path) -> None:
  run(["go", "test", str(SSH_USAGE_VERIFIER), str(SSH_USAGE_TESTS)], source_root)
  run(
    ["go", "run", str(SSH_USAGE_VERIFIER), "--source-root", str(source_root)],
    source_root,
  )


def module_paths(build_info: str) -> set[str]:
  modules: set[str] = {"github.com/cloudflare/cloudflared"}
  lines = build_info.splitlines()
  index = 0
  while index < len(lines):
    fields = lines[index].split("\t")
    if len(fields) >= 4 and fields[1] == "dep":
      modules.add(fields[2])
      if index + 1 < len(lines):
        replacement = lines[index + 1].split("\t")
        if len(replacement) >= 4 and replacement[1] == "=>":
          modules.add(replacement[2])
          index += 1
    index += 1
  return modules


def read_inventory() -> list[dict[str, str]]:
  with INVENTORY.open(newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    if reader.fieldnames != ["package", "license_url", "spdx"]:
      fail("Cloudflared license inventory header changed")
    rows = list(reader)
  if not rows:
    fail("Cloudflared license inventory is empty")
  for row in rows:
    if not all(row.values()) or row["spdx"].lower() in {"unknown", "noassertion"}:
      fail(f"incomplete Cloudflared license row: {row}")
  return rows


def verify_inventory(build_info: str, source_root: Path) -> None:
  rows = read_inventory()
  packages = {row["package"] for row in rows}
  for module in sorted(module_paths(build_info)):
    if module not in packages and not any(package.startswith(f"{module}/") for package in packages):
      fail(f"compiled module is absent from the license inventory: {module}")

  module_sources = json.loads(MODULE_SOURCES.read_text(encoding="utf-8"))
  expected_modules = module_paths(build_info) - {"github.com/cloudflare/cloudflared"}
  if set(module_sources) != expected_modules:
    fail("Cloudflared module-source evidence differs from the binary closure")
  go_sums = set((source_root / "go.sum").read_text(encoding="utf-8").splitlines())
  by_package = {row["package"]: row for row in rows}
  for row in rows:
    package = row["package"]
    if package == "github.com/cloudflare/cloudflared":
      if row["license_url"] != f"https://github.com/cloudflare/cloudflared/blob/{COMMIT}/LICENSE":
        fail("Cloudflared license URL differs from its source commit")
      continue
    record = module_sources.get(package, {})
    if row["license_url"] != record.get("licenseUrl"):
      fail(f"license URL differs from module evidence: {package}")
    origin_hash = record.get("origin", {}).get("Hash", "")
    if not re.fullmatch(r"[0-9a-f]{40}", origin_hash) or origin_hash not in row["license_url"]:
      fail(f"license URL is not pinned to its exact source: {package}")
    if f"{record.get('module')} {record.get('version')} {record.get('sum')}" not in go_sums:
      fail(f"module source is not bound to the upstream go.sum: {package}")
    notice_root = LICENSE_ROOT / "dependencies" / package
    if not notice_root.is_dir():
      original = next((
        name for name, item in module_sources.items()
        if item.get("module") == package and (LICENSE_ROOT / "dependencies" / name).is_dir()
      ), None)
      notice_root = LICENSE_ROOT / "dependencies" / (original or package)
    if not any(
      sha256(path) == record.get("licenseSha256")
      for path in notice_root.iterdir() if path.is_file()
    ):
      fail(f"module license hash differs from retained notices: {package}")

  required_conclusions = {
    "github.com/klauspost/compress": "BSD-3-Clause AND Apache-2.0 AND MIT",
    "gopkg.in/yaml.v2": "Apache-2.0 AND MIT",
    "gopkg.in/yaml.v3": "Apache-2.0 AND MIT",
    "github.com/facebookgo/grace": "MIT",
    "github.com/go-jose/go-jose/v4": "Apache-2.0 AND BSD-3-Clause",
    "github.com/prometheus/client_golang": "Apache-2.0 AND BSD-3-Clause",
  }
  for package, expected in required_conclusions.items():
    actual = by_package.get(package, {}).get("spdx")
    if actual != expected:
      fail(f"incorrect SPDX conclusion for {package}: {actual!r}")

  source_license = source_root / "LICENSE"
  retained_license = LICENSE_ROOT / "LICENSE"
  if not source_license.is_file() or not retained_license.is_file():
    fail("Cloudflared top-level license is missing")
  if sha256(source_license) != sha256(retained_license):
    fail("retained Cloudflared top-level license differs from pinned source")

  vendor = source_root / "vendor"
  source_notices = {
    path.relative_to(vendor): path
    for path in vendor.rglob("*")
    if path.is_file() and is_license_file(path)
  }
  retained_notices = {
    path.relative_to(LICENSE_ROOT / "dependencies"): path
    for path in (LICENSE_ROOT / "dependencies").rglob("*")
    if path.is_file()
  }
  for relative, path in source_notices.items():
    retained = retained_notices.get(relative)
    if retained is None or sha256(path) != sha256(retained):
      fail(f"retained Cloudflared notice differs or is missing: {relative}")
  allowed_extra = {Path(path) for path, _ in EXTERNAL_LICENSES.values()}
  actual_extra = {
    Path("dependencies") / relative
    for relative in retained_notices.keys() - source_notices.keys()
  }
  if actual_extra != allowed_extra:
    fail(f"unexpected retained Cloudflared notice files: {sorted(map(str, actual_extra))}")
  for package, (relative, expected_hash) in EXTERNAL_LICENSES.items():
    path = LICENSE_ROOT / relative
    if not path.is_file() or sha256(path) != expected_hash:
      fail(f"external license differs or is missing: {package}")


def copy_notices(source_root: Path) -> None:
  dependencies = LICENSE_ROOT / "dependencies"
  shutil.rmtree(dependencies, ignore_errors=True)
  dependencies.mkdir(parents=True)
  shutil.copyfile(source_root / "LICENSE", LICENSE_ROOT / "LICENSE")
  vendor = source_root / "vendor"
  for path in vendor.rglob("*"):
    if path.is_file() and is_license_file(path):
      target = dependencies / path.relative_to(vendor)
      target.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(path, target)


def verify_source_hashes(source_root: Path) -> None:
  provenance = json.loads((ROOT / "source" / "provenance.json").read_text(encoding="utf-8"))
  cloudflared = provenance["buildInputs"]["cloudflared"]
  expected = {
    "goModSha256": source_root / "go.mod",
    "goSumSha256": source_root / "go.sum",
    "vendorModulesSha256": source_root / "vendor" / "modules.txt",
    "licenseSha256": source_root / "LICENSE",
    "moduleSourcesSha256": MODULE_SOURCES,
  }
  if cloudflared.get("commit") != COMMIT:
    fail("Cloudflared provenance commit changed")
  for key, path in expected.items():
    if cloudflared.get(key) != sha256(path):
      fail(f"Cloudflared provenance hash differs: {key}")


def verify_grpc_security_fix(source_root: Path) -> None:
  provenance = json.loads((ROOT / "source" / "provenance.json").read_text(encoding="utf-8"))
  if provenance["buildInputs"]["cloudflared"].get("securityBackports") != []:
    fail("Cloudflared must use the upstream-fixed dependency")
  modules = (source_root / "vendor/modules.txt").read_text(encoding="utf-8")
  if "# google.golang.org/grpc v1.83.2\n" not in modules:
    fail("Cloudflared gRPC version differs from the reviewed upstream fix")
  implementation = (source_root / "vendor/google.golang.org/grpc/internal/transport/transport.go").read_text(encoding="utf-8")
  for marker in ("compactionThreshold", "EnableReceiveBufferCompaction", "uncompactedSuffixLen", "mem.NewBuffer(newBuf"):
    if marker not in implementation:
      fail(f"Cloudflared upstream receive-buffer fix is absent: {marker}")


def verify_binary(build_info: str, binary: Path) -> None:
  provenance = json.loads((ROOT / "source" / "provenance.json").read_text(encoding="utf-8"))
  cloudflared = provenance["buildInputs"]["cloudflared"]
  if cloudflared.get("binarySha256") != sha256(binary):
    fail("Cloudflared binary hash differs from provenance")
  required = (
    "/cloudflared: go1.27.3",
    "\tdep\tgoogle.golang.org/grpc\tv1.83.2\t",
    "\tdep\tgolang.org/x/net\tv0.61.0\t",
    "\tdep\tgolang.org/x/text\tv0.43.0\t",
  )
  for marker in required:
    if marker not in build_info:
      fail(f"Cloudflared build is missing required metadata: {marker.strip()}")
  if "google.golang.org/grpc\tv1.81.1" in build_info:
    fail("Cloudflared still embeds the vulnerable gRPC version")


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--source-root", required=True, type=Path)
  parser.add_argument("--binary", required=True, type=Path)
  parser.add_argument("--write", action="store_true")
  args = parser.parse_args()
  source_root = args.source_root.resolve()
  binary = args.binary.resolve()
  if not source_root.is_dir() or not binary.is_file():
    fail("Cloudflared source root or binary is missing")

  build_info = normalized_build_info(binary, source_root)
  packages = compiled_packages(source_root)
  verify_ssh_server_authentication_absence(source_root)
  if args.write:
    BUILD_INFO.write_text(build_info, encoding="utf-8")
    PACKAGES.write_text(packages, encoding="utf-8")
    copy_notices(source_root)
    print("wrote Cloudflared build, package, and notice evidence")
    return

  if BUILD_INFO.read_text(encoding="utf-8") != build_info:
    fail("checked-in Cloudflared build metadata is stale")
  if PACKAGES.read_text(encoding="utf-8") != packages:
    fail("checked-in Cloudflared compiled package closure is stale")
  verify_source_hashes(source_root)
  verify_grpc_security_fix(source_root)
  verify_binary(build_info, binary)
  verify_inventory(build_info, source_root)
  print(f"verified Cloudflared source build: {len(packages.splitlines())} compiled packages")


if __name__ == "__main__":
  main()

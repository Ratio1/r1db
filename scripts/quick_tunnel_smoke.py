#!/usr/bin/env python3
# Copyright 2026 Ratio1
# Licensed under the Apache License, Version 2.0. See LICENSE.

import argparse
import errno
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib import error, request


FIXTURE_IMAGE = "golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb"
OWNER_LABEL = "io.ratio1.quick-tunnel-smoke"
COMMAND_SECONDS, FETCH_SECONDS, CLEANUP_SECONDS = 10, 8, 90
MAX_BODY, MAX_LOG = 4096, 65536
QUICK_URL = re.compile(r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com")
URLS = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"'|]+")  # Include credentials/queries when redacting.
OUTAGE = re.compile(r"context deadline exceeded|i/o timeout|connection (?:refused|reset)|no such host|network is unreachable|temporary failure in name resolution|tls handshake timeout|status(?: code)?:? (?:429|5\d\d)|unexpected status code: (?:429|5\d\d)|failed to dial.*edge|unable to establish connection with cloudflare edge", re.I)

# Serve only the nonce route; all data and code are passed as arguments, never mounted.
FIXTURE_PROGRAM = r'''
import http.server, sys
nonce = sys.argv[1].encode("ascii")  # A fresh nonce prevents cached or unrelated successes.
class Handler(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    body = nonce if self.path == "/" + nonce.decode("ascii") else b"not found"
    self.send_response(200 if body == nonce else 404)
    self.send_header("Content-Length", str(len(body)))  # Make the response finite and exact.
    self.send_header("Cache-Control", "no-store")
    self.end_headers()
    self.wfile.write(body)
  def log_message(self, *args):
    pass
http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''
READINESS_PROGRAM = 'import sys,urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8080/"+sys.argv[1], timeout=2).read(4097).decode("ascii"), end="")'


class SmokeError(RuntimeError):
  def __init__(self, reason, status="failed"):
    super().__init__(reason)
    self.reason, self.status = reason, status


def execute(argv, timeout, env):
  with tempfile.TemporaryFile() as captured:  # Capture even workflow-command-shaped output off stdout.
    process = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=captured, stderr=subprocess.STDOUT, timeout=timeout, env=env, check=False)
    captured.seek(0)
    return process.returncode, captured.read(MAX_LOG).decode("utf-8", errors="replace")


def tunnel_url(logs):
  candidates = {url for url in URLS.findall(logs) if "trycloudflare" in url.lower() and url != "https://api.trycloudflare.com/tunnel"}  # API failure logs do not advertise a probe URL.
  if any(QUICK_URL.fullmatch(url) is None for url in candidates) or len(candidates) > 1:
    raise SmokeError("invalid_quick_tunnel_url")  # Reject userinfo, ports, paths, queries and suffix tricks.
  return next(iter(candidates), None)


class NoRedirect(request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    return None  # Never send the probe to an endpoint chosen by the response.


def http_result(status):
  if 300 <= status < 400:
    return "redirect_refused"
  if status == 502:
    return "bad_origin"  # Cloudflare uses 502 when it cannot reach this controlled origin.
  if status in (429, 500, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530):
    return "network_unavailable"  # Explicit provider errors may exhaust the smoke budget.
  return "http_" + str(status)


def fetch_once(url, nonce):
  if QUICK_URL.fullmatch(url) is None or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
    return "invalid_probe_input"
  opener = request.build_opener(request.ProxyHandler({}), NoRedirect(), request.HTTPSHandler(context=ssl.create_default_context()))
  try:
    req = request.Request(url + "/" + nonce, headers={"Cache-Control": "no-store"})
    with opener.open(req, timeout=FETCH_SECONDS) as response:
      if response.status != 200:
        return http_result(response.status)
      body = response.read(MAX_BODY + 1)  # Reject excess data without reading an unlimited response.
      if len(body) > MAX_BODY:
        return "body_too_large"
      return "passed" if body == nonce.encode("ascii") else "wrong_nonce"
  except error.HTTPError as exc:
    return http_result(exc.code)
  except ssl.SSLCertVerificationError:
    return "tls_verification_failed"
  except error.URLError as exc:
    if isinstance(exc.reason, ssl.SSLError):
      return "tls_verification_failed"
    if isinstance(exc.reason, (ConnectionError, TimeoutError, socket.gaierror)) or re.search(r"DNS unavailable|timed out|name or service not known|temporary failure in name resolution|connection (?:refused|reset)|network is unreachable", str(exc.reason), re.I):
      return "network_unavailable"  # Recognize transport failures rather than swallowing every URLError.
    return "unknown_url_error"
  except (TimeoutError, ConnectionError):
    return "network_unavailable"
  except OSError as exc:
    return "network_unavailable" if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT) else "fetch_os_error"
  except http.client.HTTPException:
    return "invalid_http_response"


def check_logs(logs):
  if re.search(r"flag provided but not defined|incorrect usage|unknown flag|unrecognized (?:argument|option)", logs, re.I):
    raise SmokeError("bad_cloudflared_cli")
  if re.search(r"unable to reach the origin service|error proxying request|dial tcp.*fixture.*(?:refused|no such host)", logs, re.I):
    raise SmokeError("bad_origin")
  outage = False
  for line in logs.splitlines():
    if re.search(r"\b(?:ERR|FATAL|PANIC)\b|level=error|^error\b|failed to request quick tunnel", line, re.I):
      if "Cannot determine default origin certificate path" in line:
        continue  # Named-tunnel certificates are unnecessary for a Quick Tunnel.
      if not OUTAGE.search(line):
        raise SmokeError("unexpected_tunnel_error")  # Unknown errors must never become a soft success.
      outage = True
  return outage


class Smoke:
  def __init__(self, image, output, timeout=120, fixture_image=FIXTURE_IMAGE):
    self.image, self.output, self.timeout, self.fixture_image = image, Path(output), timeout, fixture_image
    self.owner, self.nonce = secrets.token_hex(12), secrets.token_hex(16)
    self.network = "r1db-quick-" + self.owner
    self.fixture, self.tunnel = self.network + "-fixture", self.network + "-tunnel"
    self.logs, self.diagnostics = "", ""
    self.env = {"PATH": os.defpath}  # Do not inherit CF tokens, host proxies or Python environment hooks.
    for key in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
      if key in os.environ:
        self.env[key] = os.environ[key]  # Connection settings stay on the host Docker client.

  def docker(self, args, deadline=None, check=True):
    remaining = (self.deadline if deadline is None else deadline) - time.monotonic()
    if remaining <= 0:
      raise SmokeError("docker_deadline")
    try:
      code, text = execute(["docker", "--config", self.config, *args], min(COMMAND_SECONDS, remaining), self.env)  # Bound the client even when the daemon is slow.
    except subprocess.TimeoutExpired as exc:
      raise SmokeError("docker_timeout") from exc
    if code:
      self.diagnostics = (self.diagnostics + "\n" + text)[-MAX_LOG:]
      if check:
        reason = "missing_cloudflared_binary" if "/usr/local/bin/cloudflared" in text and "no such file" in text else "docker_command_failed"
        raise SmokeError(reason)
    return code, text

  def inspect(self, kind, name, deadline=None):
    code, text = self.docker([kind, "inspect", "--format", "{{json .}}", name], deadline, check=False)
    if code:
      if re.search(r"no such (?:container|network|object)", text, re.I) or re.search(r"network " + re.escape(name) + r" not found\b", text, re.I):
        return None  # Absence is the only acceptable failed inspection during teardown.
      raise SmokeError("resource_inspection_failed")
    return json.loads(text)

  def image_id(self, image):
    _, text = self.docker(["image", "inspect", "--format", "{{json .}}", image])
    data = json.loads(text)
    if re.fullmatch(r"sha256:[a-f0-9]{64}", data["Id"]) is None:
      raise SmokeError("invalid_image_id")
    if data["Config"].get("Volumes"):
      raise SmokeError("image_declares_volumes")  # Docker would otherwise create implicit mounts.
    if any(re.match(r"(?:CF_|CLOUDFLARE_|TUNNEL_)[^=]*=.+", item) for item in data["Config"].get("Env", []) or []):
      raise SmokeError("image_contains_cloudflare_environment")
    return data["Id"]

  def create(self, name, image, binary, arguments, alias=None):
    # The local log driver requires at least two files when its default compression is enabled.
    args = ["create", "--name", name, "--label", OWNER_LABEL + "=" + self.owner, "--network", self.network,
            "--pull", "never", "--read-only", "--user", "65532:65532", "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
            "--memory", "256m", "--memory-swap", "256m", "--cpus", "0.5", "--pids-limit", "64",
            "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2", "--env", "HOME=/tmp"]
    if alias:
      args.extend(["--network-alias", alias])  # Alias is scoped to this run's unique bridge.
    self.docker([*args, "--entrypoint", binary, image, *arguments])
    self.docker(["start", name])  # Separate creation keeps timed-out starts discoverable by name.

  def ready_fixture(self):
    deadline = min(self.deadline, time.monotonic() + 20)
    while time.monotonic() < deadline:
      code, text = self.docker(["exec", self.fixture, "python3", "-c", READINESS_PROGRAM, self.nonce], deadline, check=False)
      if code == 0:
        if text != self.nonce:
          raise SmokeError("bad_origin")
        return
      data = self.inspect("container", self.fixture, deadline)
      if data is None or not data["State"]["Running"]:
        raise SmokeError("fixture_exited")
      time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise SmokeError("fixture_readiness_deadline")

  def probe(self, url):
    remaining = self.deadline - time.monotonic()
    if remaining <= 0:
      return "network_unavailable"
    try:
      code, text = execute([sys.executable, "-I", str(Path(__file__).resolve()), "--_fetch", url, self.nonce], min(FETCH_SECONDS, remaining), self.env)
    except subprocess.TimeoutExpired:
      return "network_unavailable"  # Parent bounds DNS and slow-drip reads as well as socket operations.
    if code:
      self.diagnostics = (self.diagnostics + "\n" + text)[-MAX_LOG:]
      raise SmokeError("fetch_worker_failed")
    result = text.strip()
    if result not in ("passed", "network_unavailable"):
      raise SmokeError(result if re.fullmatch(r"[a-z_0-9]{1,48}", result) else "invalid_fetch_result")
    return result

  def exercise(self):
    image_id = self.image_id(self.image)
    self.result["image_id"] = image_id
    fixture_id = self.image_id(self.fixture_image)
    self.docker(["network", "create", "--driver", "bridge", "--label", OWNER_LABEL + "=" + self.owner, self.network])
    self.create(self.fixture, fixture_id, "python3", ["-c", FIXTURE_PROGRAM, self.nonce], alias="fixture")
    self.ready_fixture()
    self.create(self.tunnel, image_id, "/usr/local/bin/cloudflared", ["tunnel", "--no-autoupdate", "--protocol", "http2", "--url", "http://fixture:8080"])
    outage = False
    while time.monotonic() < self.deadline:
      _, self.logs = self.docker(["logs", "--tail", "200", self.tunnel])
      outage = check_logs(self.logs) or outage
      url = tunnel_url(self.logs)
      state = self.inspect("container", self.tunnel)
      if state is None:
        raise SmokeError("tunnel_disappeared")  # Missing resources are a local defect, regardless of earlier network failures.
      process = state["State"]
      if process.get("OOMKilled") or process.get("Dead") or process.get("Error") or process.get("ExitCode", 0) not in (0, 1):
        raise SmokeError("tunnel_crashed")  # Never disguise an OOM, daemon failure or signal exit as provider unavailability.
      if not process["Running"]:
        raise SmokeError("provider_unavailable" if outage else "tunnel_exited", "inconclusive" if outage else "failed")
      if url:
        if self.probe(url) == "passed":
          return
        outage = True  # Only a recognized host/provider network failure reaches this branch.
      time.sleep(min(1, max(0, self.deadline - time.monotonic())))
    raise SmokeError("network_deadline" if outage else "startup_deadline", "inconclusive" if outage else "failed")

  def cleanup(self, deadline):
    self.cleaning = True  # A separate total deadline and short calls bound best-effort teardown.
    failed = False
    resources = (("container", self.tunnel), ("container", self.fixture), ("network", self.network))
    for index, (kind, name) in enumerate(resources):
      resource_deadline = time.monotonic() + max(0, deadline - time.monotonic()) / (len(resources) - index)  # Reserve a fair share for every remaining resource.
      try:
        data = self.inspect(kind, name, resource_deadline)
        if data is None:
          continue
        labels = data.get("Config", {}).get("Labels", {}) if kind == "container" else data.get("Labels", {})
        if (labels or {}).get(OWNER_LABEL) != self.owner:
          raise SmokeError("cleanup_owner_mismatch")  # Never remove foreign resources, even on name collision.
        if name == self.tunnel:
          try:
            _, self.logs = self.docker(["logs", "--tail", "200", name], resource_deadline)
            check_logs(self.logs)  # Include errors that arrived after the final probe but before teardown.
            process = data["State"]
            if process.get("OOMKilled") or process.get("Dead") or process.get("Error") or process.get("ExitCode", 0) not in (0, 1):
              raise SmokeError("tunnel_crashed")  # Check for a crash during the public HTTP probe as well.
          except Exception as exc:
            failed = True  # Final evidence errors must not prevent removing the owned container.
            self.result["reasons"].append("cleanup_log_" + (exc.reason if isinstance(exc, SmokeError) else "capture_failed"))
        removal = ["rm", "--force", "--volumes", name] if kind == "container" else ["network", "rm", name]
        for attempt in range(2):
          try:
            self.docker(removal, resource_deadline)  # A timed-out client does not establish whether the daemon removed the object.
          except SmokeError:
            pass  # Resolve uncertain removal with an exact inspection, never assume success.
          if self.inspect(kind, name, resource_deadline) is None:
            break  # Verified absence is the teardown success criterion.
          if attempt == 1:
            raise SmokeError("removal_unconfirmed")  # A persistent resource blocks the job after a bounded retry.
      except Exception as exc:
        failed = True  # Keep trying the remaining owned resources, and fail the overall smoke.
        self.result["reasons"].append("cleanup_" + (exc.reason if isinstance(exc, SmokeError) else type(exc).__name__))
    return failed

  def run(self):
    started = time.monotonic()
    self.deadline = started + self.timeout
    self.result = {"status": "failed", "image_reference": self.image, "image_id": None, "scope": "HTTP-only", "named_tcp": "not_run", "reasons": [], "timing": {"timeout_seconds": self.timeout, "cleanup_budget_seconds": CLEANUP_SECONDS}}
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def interrupted(_signum, _frame):
      raise InterruptedError()  # Convert termination into ordinary finally-based teardown.

    try:
      for sig in previous:
        signal.signal(sig, interrupted)
      with tempfile.TemporaryDirectory(prefix="r1db-quick-docker-") as config:
        self.config = config
        Path(config, "config.json").write_text("{}\n")  # Prevent Docker config proxies from becoming container env.
        try:
          self.exercise()
          self.result["status"] = "passed"
          self.result["reasons"].append("exact_nonce_received")
        except SmokeError as exc:
          self.result["status"] = exc.status
          self.result["reasons"].append(exc.reason)
        except (KeyboardInterrupt, InterruptedError):
          self.result["status"] = "failed"  # Cancellation must fail even if it interrupts recording a successful probe.
          self.result["reasons"].append("interrupted")
        except Exception as exc:
          self.result["status"] = "failed"  # Preserve failure semantics for exceptions after a partially recorded success.
          self.result["reasons"].append("unexpected_" + type(exc).__name__)  # Unknown failures always retain exit 1.
        finally:
          for sig in previous:
            signal.signal(sig, signal.SIG_IGN)  # Repeated termination must not interrupt bounded cleanup.
          cleanup_started = time.monotonic()
          self.result["timing"]["smoke_seconds"] = round(cleanup_started - started, 3)
          if self.cleanup(cleanup_started + CLEANUP_SECONDS):
            self.result["status"] = "failed"
            self.result["reasons"].append("cleanup_failed")
          self.result["timing"]["cleanup_seconds"] = round(time.monotonic() - cleanup_started, 3)
    finally:
      for sig, handler in previous.items():
        signal.signal(sig, handler)
    self.result["timing"]["elapsed_seconds"] = round(time.monotonic() - started, 3)
    self.output.parent.mkdir(parents=True, exist_ok=True)
    log_path = self.output.with_suffix(".log")
    log_path.write_text(URLS.sub("<redacted-url>", self.logs + "\n" + self.diagnostics), encoding="utf-8")
    self.result["log_artifact"] = log_path.name
    self.output.write_text(json.dumps(self.result, indent=2) + "\n", encoding="utf-8")
    return 1 if self.result["status"] == "failed" else 0


def main(argv=None):
  parser = argparse.ArgumentParser(description="Bounded, secretless HTTP-only Quick Tunnel smoke (plus at most 90s cleanup).")
  parser.add_argument("--image", required=True)
  parser.add_argument("--output", required=True, type=Path)
  parser.add_argument("--timeout", type=int, choices=(120, 180), default=120)
  parser.add_argument("--fixture-image", default=FIXTURE_IMAGE)
  args = parser.parse_args(argv)
  return Smoke(args.image, args.output, args.timeout, args.fixture_image).run()


if __name__ == "__main__":
  if len(sys.argv) == 4 and sys.argv[1] == "--_fetch":
    print(fetch_once(sys.argv[2], sys.argv[3]))  # The supervising parent captures this controlled status only.
  else:
    sys.exit(main())

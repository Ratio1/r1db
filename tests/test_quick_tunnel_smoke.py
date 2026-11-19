#!/usr/bin/env python3
# Copyright 2026 Ratio1
# Licensed under the Apache License, Version 2.0. See LICENSE.

import io
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib import error, request

from scripts import quick_tunnel_smoke as smoke


class Clock:
  def __init__(self):
    self.now = 100.0

  def time(self):
    return self.now

  def sleep(self, seconds):
    self.now += seconds  # Advance deadlines without making the suite wait.


class DockerAndHTTP:
  def __init__(self, clock, mode="passed"):
    self.clock, self.mode = clock, mode
    self.calls, self.resources, self.removed = [], {}, []
    self.nonce = None
    self.log_reads = 0  # Distinguish final evidence from the probe-time snapshot.

  def __call__(self, argv, timeout, env):
    self.calls.append((argv, timeout, env))  # Keep the actual isolation flags reviewable.
    if argv[0] != "docker":
      self.nonce = argv[-1]
      if self.mode == "fetch_timeout":
        self.clock.now += timeout
        raise subprocess.TimeoutExpired(argv, timeout)  # Simulate a hung DNS lookup.
      result = {"outage": "network_unavailable", "late_unknown_after_outage": "network_unavailable", "wrong_nonce": "wrong_nonce"}.get(self.mode, "passed")
      return 0, result
    args = argv[3:]  # Every invocation must use a disposable Docker client config.
    if args[:2] == ["image", "inspect"]:
      config = {"Volumes": None, "Env": []}
      if self.mode == "image_volume":
        config["Volumes"] = {"/hostish": {}}
      return 0, json.dumps({"Id": "sha256:" + "b" * 64, "Config": config})
    if args[:2] == ["network", "create"]:
      name = args[-1]
      self.resources[name] = {"Labels": {smoke.OWNER_LABEL: name.removeprefix("r1db-quick-")}}
      if self.mode == "create_timeout":
        self.clock.now += timeout
        raise subprocess.TimeoutExpired(argv, timeout)  # The daemon may create before the client times out.
      return 0, "network-id"
    if args[0] == "create":
      name = args[args.index("--name") + 1]
      owner = args[args.index("--label") + 1].split("=", 1)[1]
      self.resources[name] = {"Config": {"Labels": {smoke.OWNER_LABEL: owner}}, "State": {"Running": True}}
      return 0, "container-id"
    if args[0] == "start":
      if self.mode == "missing_binary" and args[-1].endswith("-tunnel"):
        return 127, "exec: /usr/local/bin/cloudflared: no such file or directory"
      if self.mode == "interrupt":
        raise KeyboardInterrupt()  # Verify finally runs even during container startup.
      if self.mode == "sigterm":
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
      return 0, args[-1]
    if args[0] == "exec":
      if self.mode == "bad_origin":
        return 1, "connection refused"
      return 0, args[-1]  # Readiness must return exactly the generated nonce.
    if args[0] == "logs":
      self.log_reads += 1  # The final cleanup snapshot may contain a newly arrived error.
      if self.mode.startswith("late_unknown") and (self.clock.now >= 105 or (self.mode.endswith("pass") and self.log_reads > 1)):
        return 0, "ERR unrecognized internal connector failure"
      if self.mode.startswith("provider_") and self.mode not in ("provider_api",):
        return 0, "ERR failed to request quick Tunnel: context deadline exceeded"
      if self.mode == "logs_failure":
        return 1, "daemon could not collect logs"
      logs = {
        "bad_cli": "Incorrect Usage: flag provided but not defined: -protocol",
        "provider": "ERR failed to request quick Tunnel: context deadline exceeded",
        "provider_api": 'ERR failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel": context deadline exceeded',
        "unknown": "ERR something unexpected happened",
        "origin_error": "ERR Unable to reach the origin service: connection refused",
        "silent": "starting",
        "invalid_url": "https://good.trycloudflare.com.evil.invalid/?token=private-value",
      }.get(self.mode, "INF https://unit-test.trycloudflare.com\n::warning::untrusted logs")
      return 0, logs
    if len(args) > 1 and args[1] == "inspect":
      name = args[-1]
      if name not in self.resources:
        if args[0] == "network":
          return 1, "Error response from daemon: network " + name + " not found"  # Match the real network-inspect absence diagnostic.
        return 1, "Error: No such " + args[0] + ": " + name
      if self.mode == "provider_missing" and name.endswith("-tunnel"):
        self.resources.pop(name)  # Simulate disappearance after the provider logged an outage.
        return 1, "Error: No such container: " + name
      data = self.resources[name]
      if self.mode in ("provider_oom", "provider_crash", "provider_daemon_error", "provider_exit") and name.endswith("-tunnel"):
        data["State"] = {"Running": False, "OOMKilled": self.mode == "provider_oom", "ExitCode": 137 if self.mode in ("provider_oom", "provider_crash") else 1, "Error": "daemon task failure" if self.mode == "provider_daemon_error" else ""}  # A provider error must not hide a separate local crash.
      if self.mode == "foreign_owner":
        data = {"Labels": {}, "Config": {"Labels": {}}, "State": {"Running": True}}
      return 0, json.dumps(data)
    if args[0] == "rm" or args[:2] == ["network", "rm"]:
      name = args[-1]
      if self.mode == "cleanup_uncertain_removed":
        self.removed.append(name)  # The daemon completes removal even though the client times out.
        self.resources.pop(name)
        self.clock.now += timeout
        raise subprocess.TimeoutExpired(argv, timeout)
      if self.mode == "cleanup_reported_success_but_present":
        return 0, name  # A successful client exit alone does not prove cleanup.
      if self.mode == "cleanup_timeout":
        self.clock.now += timeout
        raise subprocess.TimeoutExpired(argv, timeout)  # Each resource still gets a bounded removal attempt.
      if self.mode == "cleanup_failure":
        return 1, "daemon refused removal"
      self.removed.append(name)
      self.resources.pop(name)
      return 0, name
    raise AssertionError("unexpected command: " + repr(args))


class SmokeTests(unittest.TestCase):
  def run_smoke(self, mode="passed", timeout=5):
    clock = Clock()
    fake = DockerAndHTTP(clock, mode)
    with tempfile.TemporaryDirectory() as directory:
      output = Path(directory) / "result.json"
      runner = smoke.Smoke("candidate:local", output, timeout=timeout)
      with patch.object(smoke, "execute", side_effect=fake), patch.object(smoke.time, "monotonic", clock.time), patch.object(smoke.time, "sleep", clock.sleep), patch("sys.stdout", new_callable=io.StringIO) as stdout:
        code = runner.run()
      result = json.loads(output.read_text())
      logs = output.with_suffix(".log").read_text()
      self.assertEqual(stdout.getvalue(), "")  # Docker logs must never become workflow commands.
      self.assertLessEqual(result["timing"]["elapsed_seconds"], timeout + smoke.CLEANUP_SECONDS)
    return code, result, logs, fake, runner

  def test_exact_nonce_passes_and_only_owned_resources_are_removed(self):
    code, result, logs, fake, runner = self.run_smoke()
    self.assertEqual((code, result["status"]), (0, "passed"))
    self.assertEqual(result["image_reference"], "candidate:local")  # Bind evidence to the supplied image reference as well as its resolved ID.
    self.assertEqual(result["image_id"], "sha256:" + "b" * 64)
    self.assertEqual(result["scope"], "HTTP-only")
    self.assertEqual(result["named_tcp"], "not_run")
    self.assertEqual(set(fake.removed), {runner.network, runner.fixture, runner.tunnel})
    self.assertIn("::warning::untrusted logs", logs)  # Evidence remains in an artifact only.
    self.assertNotIn("trycloudflare.com", json.dumps(result) + logs)
    self.assertNotIn(runner.nonce, json.dumps(result))

  def test_known_provider_and_host_network_outages_are_inconclusive(self):
    for mode in ("provider", "provider_api", "provider_exit", "outage", "fetch_timeout"):
      with self.subTest(mode=mode):
        code, result, _, fake, _ = self.run_smoke(mode)
        self.assertEqual((code, result["status"]), (0, "inconclusive"))
        self.assertFalse(fake.resources)

  def test_deterministic_and_unknown_failures_are_not_downgraded(self):
    for mode in ("missing_binary", "bad_cli", "wrong_nonce", "unknown", "origin_error", "bad_origin", "silent", "invalid_url", "image_volume"):
      with self.subTest(mode=mode):
        code, result, logs, _, _ = self.run_smoke(mode)
        self.assertEqual((code, result["status"]), (1, "failed"))
        self.assertNotIn("private-value", json.dumps(result) + logs)

  def test_exception_after_partial_success_still_fails(self):
    for exception in (InterruptedError(), RuntimeError()):
      with self.subTest(exception=type(exception).__name__), tempfile.TemporaryDirectory() as directory:
        runner = smoke.Smoke("candidate:local", Path(directory) / "result.json")  # Use no real container or network resource.
        def interrupt_success():
          runner.result["status"] = "passed"  # Model interruption between recording status and completing the result.
          raise exception
        with patch.object(runner, "exercise", side_effect=interrupt_success), patch.object(runner, "cleanup", return_value=False):
          code = runner.run()  # Exercise the real exception handling and result serialization.
        self.assertEqual((code, runner.result["status"]), (1, "failed"))  # A partially recorded success cannot hide cancellation or failure.

  def test_prior_outage_never_masks_local_crashes_or_disappearance(self):
    for mode in ("provider_oom", "provider_crash", "provider_daemon_error", "provider_missing"):
      with self.subTest(mode=mode):
        code, result, _, fake, _ = self.run_smoke(mode)  # Reproduce a known outage followed by a separate local defect.
        self.assertEqual((code, result["status"]), (1, "failed"))  # These must never become inconclusive exit zero.
        self.assertFalse(fake.resources)  # Failure classification must preserve teardown.

  def test_final_log_errors_override_pass_and_inconclusive(self):
    for mode in ("late_unknown_after_pass", "late_unknown_after_outage"):
      with self.subTest(mode=mode):
        code, result, logs, fake, _ = self.run_smoke(mode)  # Inject the error only into the final cleanup snapshot.
        self.assertEqual((code, result["status"]), (1, "failed"))
        self.assertIn("cleanup_log_unexpected_tunnel_error", result["reasons"])  # Explain why a late defect invalidated the earlier outcome.
        self.assertIn("unrecognized internal connector failure", logs)  # Retain the diagnostic in the artifact.
        self.assertFalse(fake.resources)  # Classifying final logs must not skip any owned cleanup.

  def test_cleanup_requires_verified_absence_after_uncertain_removal(self):
    code, result, _, fake, _ = self.run_smoke("cleanup_uncertain_removed")  # A timed-out client may leave a completed daemon operation.
    self.assertEqual((code, result["status"]), (0, "passed"))
    self.assertFalse(fake.resources)  # Exact inspection confirms success instead of treating timeout as either automatic pass or failure.
    code, result, _, fake, _ = self.run_smoke("cleanup_reported_success_but_present")
    self.assertEqual((code, result["status"]), (1, "failed"))  # Detect leftovers even if the Docker client reports success.
    self.assertTrue(fake.resources)

  def test_cleanup_failure_overrides_a_pass(self):
    for mode in ("cleanup_failure", "cleanup_timeout"):
      with self.subTest(mode=mode):
        code, result, _, fake, fake_runner = self.run_smoke(mode)
        self.assertEqual((code, result["status"]), (1, "failed"))
        self.assertIn("cleanup_failed", result["reasons"])
        removals = [argv for argv, _, _ in fake.calls if argv[0] == "docker" and (argv[3] == "rm" or argv[3:5] == ["network", "rm"])]
        self.assertEqual({argv[-1] for argv in removals}, {fake_runner.network, fake_runner.fixture, fake_runner.tunnel})  # One timeout must not prevent attempts on remaining resources.
        self.assertLessEqual(len(removals), 6)  # Retry each resource at most once.

  def test_log_collection_failure_still_removes_owned_resources(self):
    code, result, _, fake, _ = self.run_smoke("logs_failure")
    self.assertEqual((code, result["status"]), (1, "failed"))
    self.assertFalse(fake.resources)
    self.assertIn("cleanup_log_docker_command_failed", result["reasons"])

  def test_cleanup_never_removes_a_resource_with_another_owner(self):
    code, result, _, fake, _ = self.run_smoke("foreign_owner")
    self.assertEqual((code, result["status"]), (1, "failed"))
    self.assertEqual(fake.removed, [])
    self.assertTrue(fake.resources)

  def test_timed_out_creation_is_recovered_by_name_and_owner_label(self):
    code, result, _, fake, runner = self.run_smoke("create_timeout")
    self.assertEqual((code, result["status"]), (1, "failed"))
    self.assertEqual(fake.removed, [runner.network])
    self.assertTrue(all(0 < call[1] <= smoke.COMMAND_SECONDS for call in fake.calls))

  def test_interrupts_cleanup_and_restore_signal_handlers(self):
    previous = signal.getsignal(signal.SIGTERM)
    for mode in ("interrupt", "sigterm"):
      with self.subTest(mode=mode):
        code, result, _, fake, _ = self.run_smoke(mode)
        self.assertEqual((code, result["status"]), (1, "failed"))
        self.assertIn("interrupted", result["reasons"])
        self.assertFalse(fake.resources)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

  def test_no_host_secrets_mounts_ports_or_proxy_config_are_propagated(self):
    with patch.dict(os.environ, {"CF_API_TOKEN": "host-secret", "TUNNEL_TOKEN": "host-secret", "HTTPS_PROXY": "https://private:secret@proxy.invalid"}):
      _, _, _, fake, _ = self.run_smoke()
    creates = [argv[3:] for argv, _, _ in fake.calls if argv[0] == "docker" and argv[3] == "create"]
    self.assertEqual(len(creates), 2)
    for args in creates:
      for flag in ("--read-only", "--user", "--security-opt", "--cap-drop", "--tmpfs", "--memory", "--cpus", "--pids-limit", "--pull"):
        self.assertIn(flag, args)
      self.assertIn("65532:65532", args)
      self.assertIn("no-new-privileges", args)
      for flag in ("--mount", "--volume", "-v", "--env-file", "--publish", "-p", "--privileged"):
        self.assertNotIn(flag, args)
    tunnel = creates[1]
    self.assertEqual(tunnel[-6:], ["tunnel", "--no-autoupdate", "--protocol", "http2", "--url", "http://fixture:8080"])
    self.assertIn("/usr/local/bin/cloudflared", tunnel)
    for argv, timeout, env in fake.calls:
      self.assertGreater(timeout, 0)
      self.assertNotIn("host-secret", repr(argv) + repr(env))
      self.assertNotIn("HTTPS_PROXY", env)
      self.assertNotIn("CF_API_TOKEN", env)
      if argv[0] == "docker":
        self.assertEqual(argv[1], "--config")


class FetchTests(unittest.TestCase):
  def test_strict_quick_tunnel_urls(self):
    self.assertEqual(smoke.tunnel_url("INF https://abc-12.trycloudflare.com |"), "https://abc-12.trycloudflare.com")
    invalid = ("http://abc.trycloudflare.com", "https://trycloudflare.com", "https://abc.trycloudflare.com.evil.org", "https://x.y.trycloudflare.com", "https://user:secret@abc.trycloudflare.com", "https://abc.trycloudflare.com:443", "https://abc.trycloudflare.com/a", "https://abc.trycloudflare.com?token=secret", "https://-abc.trycloudflare.com", "https://abc.trycloudflare.com#secret")
    for value in invalid:
      with self.subTest(value=value), self.assertRaises(smoke.SmokeError):
        smoke.tunnel_url(value)

  def test_redirect_handler_never_follows(self):
    handler = smoke.NoRedirect()
    self.assertIsNone(handler.redirect_request(request.Request("https://a.trycloudflare.com"), None, 302, "redirect", {}, "https://elsewhere.invalid"))

  def fetch(self, response=None, failure=None):
    opener = unittest.mock.MagicMock()  # urllib responses implement the context-manager protocol.
    if failure is not None:
      opener.open.side_effect = failure
    else:
      opener.open.return_value.__enter__.return_value = response
    with patch.object(smoke.request, "build_opener", return_value=opener) as build:
      result = smoke.fetch_once("https://unit.trycloudflare.com", "a" * 32)
    return result, build, opener

  def test_fetch_requires_tls_exact_nonce_and_bounded_body(self):
    response = unittest.mock.MagicMock()
    response.status = 200
    response.read.return_value = b"a" * 32
    result, build, opener = self.fetch(response)
    self.assertEqual(result, "passed")
    response.read.assert_called_once_with(smoke.MAX_BODY + 1)
    handlers = build.call_args.args
    self.assertTrue(any(isinstance(h, smoke.NoRedirect) for h in handlers))
    self.assertTrue(any(isinstance(h, request.ProxyHandler) and h.proxies == {} for h in handlers))
    context = next(h._context for h in handlers if isinstance(h, request.HTTPSHandler))
    self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
    self.assertTrue(context.check_hostname)
    self.assertGreater(opener.open.call_args.kwargs["timeout"], 0)
    response.read.return_value = b"a" * 32 + b"\n"
    self.assertEqual(self.fetch(response)[0], "wrong_nonce")
    response.read.return_value = b"a" * (smoke.MAX_BODY + 1)
    self.assertEqual(self.fetch(response)[0], "body_too_large")

  def test_fetch_classifies_http_errors_conservatively(self):
    for status, expected in ((302, "redirect_refused"), (404, "http_404"), (500, "network_unavailable"), (501, "http_501"), (502, "bad_origin"), (503, "network_unavailable"), (504, "network_unavailable"), (522, "network_unavailable"), (429, "network_unavailable")):
      with self.subTest(status=status):
        failure = error.HTTPError("https://unit.trycloudflare.com", status, "error", {}, None)
        self.assertEqual(self.fetch(failure=failure)[0], expected)
    self.assertEqual(self.fetch(failure=error.URLError("DNS unavailable"))[0], "network_unavailable")
    self.assertEqual(self.fetch(failure=error.URLError("unexpected condition"))[0], "unknown_url_error")
    self.assertEqual(self.fetch(failure=error.URLError(ssl.SSLCertVerificationError("bad cert")))[0], "tls_verification_failed")


class ExecutionTests(unittest.TestCase):
  def test_processes_are_bounded_captured_and_given_no_stdin(self):
    def process(argv, **kwargs):
      self.assertEqual(kwargs["timeout"], 2.5)
      self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
      self.assertEqual(kwargs["stderr"], subprocess.STDOUT)
      kwargs["stdout"].write(b"::error::untrusted\n")
      return subprocess.CompletedProcess(argv, 0)

    with patch.object(smoke.subprocess, "run", side_effect=process), patch("sys.stdout", new_callable=io.StringIO) as stdout:
      self.assertEqual(smoke.execute(["docker", "version"], 2.5, {}), (0, "::error::untrusted\n"))
      self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
  unittest.main()

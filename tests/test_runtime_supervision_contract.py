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

"""Exercise terminal log observation in the real runtime smoke helper."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RuntimeLogObservationTests(unittest.TestCase):
  def run_wait(self, mode):
    script = (ROOT / "scripts/runtime-supervision-smoke.sh").read_text()
    helper = script[script.index("wait_for_log() {"):script.index("\nmarker_elapsed_millis() {")]
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      docker = root / "docker"
      docker.write_text(f"#!{sys.executable}\n" + '''
import os
from pathlib import Path
import sys

root = Path(__file__).parent
mode = os.environ["LOG_TEST_MODE"]
if sys.argv[1] == "logs":
  counter = root / "log-reads"
  reads = int(counter.read_text()) if counter.exists() else 0
  counter.write_text(str(reads + 1))
  if mode == "exit-race" and reads == 0:
    pass  # The final container message arrives between logs and inspect.
  elif mode == "missing":
    print("actual container failure diagnostic", file=sys.stderr)
  else:
    print("expected terminal message", file=sys.stderr, flush=True)
    if mode == "large-log":
      print("later diagnostic\\n" * 20000, file=sys.stderr)
elif sys.argv[1] == "inspect":
  print("false")
''')
      docker.chmod(0o755)
      result = subprocess.run(
        ["bash", "-c", 'set -euo pipefail\n' + helper + '\nwait_for_log test-container "expected terminal message" 1'],
        env={**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"], "LOG_TEST_MODE": mode},
        text=True, capture_output=True, timeout=10,
      )
      reads = int((root / "log-reads").read_text())
      return result, reads

  def test_terminal_message_arriving_between_logs_and_exit_is_observed(self):
    result, reads = self.run_wait("exit-race")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertGreaterEqual(reads, 2)

  def test_log_producer_is_drained_after_a_match(self):
    result, _ = self.run_wait("large-log")
    self.assertEqual(result.returncode, 0, result.stderr)

  def test_missing_terminal_message_fails_and_preserves_stderr_diagnostics(self):
    result, _ = self.run_wait("missing")
    self.assertNotEqual(result.returncode, 0)
    self.assertIn("actual container failure diagnostic", result.stderr)
    self.assertIn("timed out waiting for log", result.stderr)


if __name__ == "__main__":
  unittest.main()

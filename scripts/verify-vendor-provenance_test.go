// Copyright 2026 Ratio1
// Licensed under the Apache License, Version 2.0. See LICENSE.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func downloadFixture(t *testing.T, output string, exitCode int) (string, string) {
	t.Helper()                                    // Attribute fixture failures to the calling test.
	root := t.TempDir()                           // Keep synthetic command output and process identity disposable.
	payload := filepath.Join(root, "output.json") // Separate JSON bytes from shell syntax.
	pidPath := filepath.Join(root, "pid")         // Observe whether the verifier reaps its subprocess.
	if err := os.WriteFile(payload, []byte(output), 0600); err != nil {
		t.Fatal(err) // Fixture construction must succeed before exercising the verifier.
	}
	command := filepath.Join(root, "go-fixture")                                                                // Exercise the actual executable boundary.
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$$\" > %q\ncat %q\nexit %d\n", pidPath, payload, exitCode) // Paths are generated temporary names, never module-controlled input.
	if err := os.WriteFile(command, []byte(script), 0700); err != nil {
		t.Fatal(err) // The fixture needs executable permissions inside the Linux test image.
	}
	t.Cleanup(func() {
		data, err := os.ReadFile(pidPath) // Also clean a child leaked by the pre-fix regression run.
		if err != nil {
			return // No process was started if the identity file is absent.
		}
		pid, err := strconv.Atoi(string(data)) // Restrict cleanup to this fixture's exact child.
		if err != nil {
			return // Never signal an unparsed process identity.
		}
		process, err := os.FindProcess(pid) // Reaping an already-waited child returns harmlessly.
		if err == nil {
			_ = process.Kill()    // Bound cleanup even when a failed implementation leaves the child alive.
			_, _ = process.Wait() // Remove a zombie left by an early decode return.
		}
	})
	return command, pidPath // Return only the executable and observable process identity.
}

func TestDownloadModulesRecordsAndFailures(t *testing.T) {
	const first = `{"Path":"example.com/first","Version":"v1.0.0","Dir":"/verified/first","Sum":"h1:first"}`     // Synthetic successful download metadata.
	const second = `{"Path":"example.com/second","Version":"v1.0.0","Dir":"/verified/second","Sum":"h1:second"}` // Distinct requested module for completeness checks.
	cases := []struct {
		name      string
		output    string
		exitCode  int
		wantError string
	}{
		{"success", first + "\n" + second, 0, ""},
		{"string error", `{"Path":"example.com/first","Version":"v1.0.0","Error":"proxy returned 503"}`, 1, "module download failed for example.com/first@v1.0.0: proxy returned 503"},
		{"later string error", first + "\n" + `{"Path":"example.com/second","Version":"v1.0.0","Error":"checksum mismatch"}`, 1, "example.com/second@v1.0.0: checksum mismatch"},
		{"malformed output", "{", 1, "unexpected EOF"},
		{"unexpected error type", `{"Path":"example.com/first","Version":"v1.0.0","Error":{"Err":"invalid schema"}}`, 1, "cannot unmarshal object"},
		{"failed exit", first + "\n" + second, 7, "exit status 7"},
		{"empty failed exit", "", 2, "exit status 2"},
		{"missing module", first, 0, "downloaded 1 of 2"},
		{"unknown module", `{"Path":"example.com/unrequested","Version":"v1.0.0"}`, 0, "unexpected module download"},
		{"missing verified directory", `{"Path":"example.com/first","Version":"v1.0.0","Sum":"h1:first"}`, 0, "lacks a verified directory or checksum"},
		{"missing verified checksum", `{"Path":"example.com/first","Version":"v1.0.0","Dir":"/verified/first"}`, 0, "lacks a verified directory or checksum"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			command, pidPath := downloadFixture(t, item.output, item.exitCode) // Supply actual subprocess stdout/exit behavior.
			modules := []module{
				{SourcePath: "example.com/first", SourceVer: "v1.0.0"},
				{SourcePath: "example.com/second", SourceVer: "v1.0.0"},
			} // Each invocation gets fresh mutable result records.
			err := downloadModules(modules, command) // Run the production parser and process handling.
			if item.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), item.wantError) {
					t.Errorf("error = %v, want diagnostic containing %q", err, item.wantError) // Preserve module identity and original failure reason.
				}
			} else if err != nil {
				t.Errorf("successful downloads rejected: %v", err) // Successful metadata must still be accepted.
			} else if modules[0].Dir != "/verified/first" || modules[0].Sum != "h1:first" || modules[1].Dir != "/verified/second" || modules[1].Sum != "h1:second" {
				t.Errorf("download metadata not retained: %+v", modules) // Retain the verified archive locations and sums used by file comparison.
			}
			data, err := os.ReadFile(pidPath) // Read only the exact child created by this fixture.
			if err != nil {
				t.Fatal(err) // A missing PID would make the process-lifecycle assertion vacuous.
			}
			pid, err := strconv.Atoi(string(data)) // Convert the shell's positive PID before probing it.
			if err != nil {
				t.Fatal(err) // Reject malformed fixture identity.
			}
			if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
				t.Errorf("download child %d remains running or unreaped: %v", pid, err) // Early parser returns must not leak children or zombies.
			}
		})
	}
}

func TestDownloadModulesRealGoProxyFailure(t *testing.T) {
	goBinary, err := exec.LookPath("go") // Exercise the same pinned Go command used by CI.
	if err != nil {
		t.Fatal(err) // This suite is intentionally run in the Go toolchain image.
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "fixture proxy unavailable", http.StatusServiceUnavailable) // Produce a real Go download error without Internet dependencies.
	}))
	defer server.Close()                                                                            // Release the fixture listener before the test process exits.
	t.Setenv("GOPROXY", server.URL)                                                                 // Route this test's real Go download only to its local fixture.
	t.Setenv("GOSUMDB", "off")                                                                      // The failing local fixture contains no public modules to authenticate.
	t.Setenv("GOMODCACHE", t.TempDir())                                                             // Prevent an unrelated cache hit from bypassing the proxy error.
	modules := []module{{SourcePath: "example.com/vendor-provenance-fixture", SourceVer: "v1.0.0"}} // Request a disposable module identity.
	err = downloadModules(modules, goBinary)                                                        // Decode the actual Go tool's JSON error schema.
	if err == nil || !strings.Contains(err.Error(), "example.com/vendor-provenance-fixture@v1.0.0") || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("real Go proxy failure lost module or reason: %v", err) // A generic JSON type error would reproduce the release bug.
	}
}

func TestDownloadModulesFixtureSchema(t *testing.T) {
	var record download // Confirm the documented Error string is accepted independently of process fixtures.
	if err := json.Unmarshal([]byte(`{"Error":"module unavailable"}`), &record); err != nil {
		t.Fatalf("Go download Error string rejected: %v", err) // The release failure must remain directly reproducible.
	}
}

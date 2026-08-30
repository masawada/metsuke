package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `
deny = ["git push"]
allow = ["git status", "git log"]
`

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func hookInputJSON(tool, command string) string {
	in := map[string]any{
		"tool_name":  tool,
		"tool_input": map[string]any{"command": command},
	}
	b, _ := json.Marshal(in)
	return string(b)
}

func runHook(t *testing.T, stdin string, args ...string) (string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	if code := run(strings.NewReader(stdin), &stdout, &stderr, args); code != 0 {
		t.Fatalf("run exited with %d, stderr: %s", code, stderr.String())
	}
	return stdout.String(), stderr.String()
}

func decodeDecision(t *testing.T, stdout string) (string, string) {
	t.Helper()
	var out struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("invalid output JSON %q: %v", stdout, err)
	}
	if got := out.HookSpecificOutput.HookEventName; got != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", got)
	}
	return out.HookSpecificOutput.PermissionDecision, out.HookSpecificOutput.PermissionDecisionReason
}

func TestRunDecisions(t *testing.T) {
	cfgPath := writeTestConfig(t, testConfig)
	tests := []struct {
		name         string
		command      string
		wantDecision string
		wantInReason string
	}{
		{"deny", "git push origin main", "deny", "deny rule"},
		{"ask", "git stash pop", "ask", "git stash pop"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _ := runHook(t, hookInputJSON("Bash", tt.command), "--config", cfgPath)
			decision, reason := decodeDecision(t, stdout)
			if decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q", decision, tt.wantDecision)
			}
			if !strings.Contains(reason, tt.wantInReason) {
				t.Errorf("reason %q does not contain %q", reason, tt.wantInReason)
			}
		})
	}
}

func TestRunDelegates(t *testing.T) {
	cfgPath := writeTestConfig(t, testConfig)
	tests := []struct {
		name  string
		stdin string
	}{
		{"allow-rule match delegates", hookInputJSON("Bash", "git status")},
		{"unwatched command", hookInputJSON("Bash", "curl example.com")},
		{"mixture", hookInputJSON("Bash", "git log | head -5")},
		{"unparseable command", hookInputJSON("Bash", "git status &&")},
		{"non-bash tool", hookInputJSON("Edit", "")},
		{"empty command", hookInputJSON("Bash", "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _ := runHook(t, tt.stdin, "--config", cfgPath)
			if stdout != "" {
				t.Errorf("expected no output, got %q", stdout)
			}
		})
	}
}

func TestRunConfigErrorsAsk(t *testing.T) {
	brokenPath := writeTestConfig(t, `deny = ["git push | cat"]`)
	typoPath := writeTestConfig(t, `denny = ["git push"]`)
	tests := []struct {
		name string
		args []string
	}{
		{"missing config", []string{"--config", filepath.Join(t.TempDir(), "nope.toml")}},
		{"broken config", []string{"--config", brokenPath}},
		{"unknown key config", []string{"--config", typoPath}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _ := runHook(t, hookInputJSON("Bash", "echo hi"), tt.args...)
			decision, reason := decodeDecision(t, stdout)
			if decision != "ask" {
				t.Errorf("decision = %q, want ask", decision)
			}
			if !strings.Contains(reason, "metsuke") {
				t.Errorf("reason %q should mention metsuke", reason)
			}
		})
	}
}

func TestRunInvalidStdinAsks(t *testing.T) {
	cfgPath := writeTestConfig(t, testConfig)
	tests := []struct {
		name  string
		stdin string
	}{
		{"not json", "not json"},
		{"trailing garbage", hookInputJSON("Bash", "git status") + " garbage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _ := runHook(t, tt.stdin, "--config", cfgPath)
			decision, _ := decodeDecision(t, stdout)
			if decision != "ask" {
				t.Errorf("decision = %q, want ask", decision)
			}
		})
	}
}

func TestResolveConfigPath(t *testing.T) {
	t.Run("explicit flag wins", func(t *testing.T) {
		got, err := resolveConfigPath("/x/y.toml")
		if err != nil || got != "/x/y.toml" {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("xdg config home", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "/xdg")
		got, err := resolveConfigPath("")
		if err != nil || got != "/xdg/metsuke/config.toml" {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("home fallback", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "/home/x")
		got, err := resolveConfigPath("")
		if err != nil || got != "/home/x/.config/metsuke/config.toml" {
			t.Errorf("got %q, %v", got, err)
		}
	})
}

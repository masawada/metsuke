package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type hookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, os.Args[1:]))
}

// run implements the PreToolUse hook protocol: it reads the hook input from
// stdin and prints a permission decision to stdout, or prints nothing to
// delegate to the normal permission flow. It always exits 0; configuration
// and internal failures degrade loudly to "ask" so a broken setup cannot
// silently disable the rules.
func run(stdin io.Reader, stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("metsuke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configFlag := fs.String("config", "", "path to the rule config file (TOML)")
	if err := fs.Parse(args); err != nil {
		emit(stdout, decisionAsk, fmt.Sprintf("invalid arguments: %v", err))
		return 0
	}

	// Unmarshal over the whole body (rather than a streaming decode) so a
	// payload with trailing garbage is rejected instead of half-processed.
	body, err := io.ReadAll(stdin)
	if err != nil {
		emit(stdout, decisionAsk, fmt.Sprintf("failed to read hook input: %v", err))
		return 0
	}
	var in hookInput
	if err := json.Unmarshal(body, &in); err != nil {
		emit(stdout, decisionAsk, fmt.Sprintf("failed to decode hook input: %v", err))
		return 0
	}
	if in.ToolName != "Bash" || in.ToolInput.Command == "" {
		return 0
	}

	path, err := resolveConfigPath(*configFlag)
	if err != nil {
		emit(stdout, decisionAsk, fmt.Sprintf("cannot resolve config path: %v", err))
		return 0
	}
	cfg, err := loadConfig(path)
	if err != nil {
		emit(stdout, decisionAsk, fmt.Sprintf("config error (%s): %v", path, err))
		return 0
	}

	cmds, err := parseCommands(in.ToolInput.Command)
	if err != nil {
		// Unparseable command lines are delegated; the classifier still
		// sees the full command text.
		fmt.Fprintf(stderr, "metsuke: parse error: %v\n", err)
		return 0
	}
	dec, reason := cfg.judge(cmds)
	if dec == decisionDelegate {
		return 0
	}
	emit(stdout, dec, reason)
	return 0
}

func emit(w io.Writer, dec decision, reason string) {
	out := hookOutput{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       dec.String(),
			PermissionDecisionReason: "metsuke: " + reason,
		},
	}
	json.NewEncoder(w).Encode(out)
}

// resolveConfigPath returns the config file location: the --config flag if
// given, otherwise $XDG_CONFIG_HOME/metsuke/config.toml, otherwise
// $HOME/.config/metsuke/config.toml (XDG_CONFIG_HOME is usually unset on
// macOS).
func resolveConfigPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "metsuke", "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "metsuke", "config.toml"), nil
}

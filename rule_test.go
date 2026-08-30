package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig([]byte(`
deny = [
  "git push",
  "gh api",
]
allow = [
  "git status",
  "git log",
  "git commit -m 'foo bar'",
]
`))
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	var watched []string
	for name := range cfg.watched {
		watched = append(watched, name)
	}
	sort.Strings(watched)
	if want := []string{"gh", "git"}; !reflect.DeepEqual(watched, want) {
		t.Errorf("watched = %v, want %v", watched, want)
	}
	if want := []string{"git", "commit", "-m", "foo bar"}; !reflect.DeepEqual(cfg.allowRules[2], want) {
		t.Errorf("quoted rule tokens = %v, want %v", cfg.allowRules[2], want)
	}
}

func TestParseConfigInvalidRules(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"pipe in rule", `deny = ["git push | cat"]`},
		{"and chain in rule", `deny = ["git add . && git push"]`},
		{"expansion in rule", `deny = ["git push $BRANCH"]`},
		{"command substitution in rule", `deny = ["git push $(cat f)"]`},
		{"redirect in rule", `allow = ["git status > out.txt"]`},
		{"env prefix in rule", `deny = ["GIT_DIR=/x git push"]`},
		{"empty rule", `deny = [""]`},
		{"path command name in rule", `deny = ["/usr/bin/git push"]`},
		{"broken toml", `deny = [`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseConfig([]byte(tt.src)); err == nil {
				t.Errorf("parseConfig(%q) expected error, got nil", tt.src)
			}
		})
	}
}

func TestJudgeCommand(t *testing.T) {
	cfg, err := parseConfig([]byte(`
deny = ["git push", "gh api"]
allow = ["git status", "git log"]
`))
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	tests := []struct {
		name string
		cmd  Command
		want cmdVerdict
	}{
		{
			name: "deny exact",
			cmd:  Command{Words: argv(lit("git"), lit("push"))},
			want: verdictDeny,
		},
		{
			name: "deny prefix with trailing args",
			cmd:  Command{Words: argv(lit("git"), lit("push"), lit("--force"), lit("origin"))},
			want: verdictDeny,
		},
		{
			name: "deny matches basename of path",
			cmd:  Command{Words: argv(lit("/usr/bin/git"), lit("push"))},
			want: verdictDeny,
		},
		{
			name: "deny matches even with uncertain word after prefix",
			cmd:  Command{Words: argv(lit("git"), lit("push"), unc())},
			want: verdictDeny,
		},
		{
			name: "deny matches even with output redirect",
			cmd:  Command{Words: argv(lit("git"), lit("push")), OutputRedirect: true},
			want: verdictDeny,
		},
		{
			name: "deny matches even with env prefix",
			cmd:  Command{Words: argv(lit("git"), lit("push")), EnvPrefix: true},
			want: verdictDeny,
		},
		{
			name: "allow exact",
			cmd:  Command{Words: argv(lit("git"), lit("status"))},
			want: verdictAllow,
		},
		{
			name: "allow prefix with trailing args",
			cmd:  Command{Words: argv(lit("git"), lit("log"), lit("--oneline"), lit("-5"))},
			want: verdictAllow,
		},
		{
			name: "allow requires bare command name",
			cmd:  Command{Words: argv(lit("./git"), lit("status"))},
			want: verdictNoMatch,
		},
		{
			name: "watched without matching rule",
			cmd:  Command{Words: argv(lit("git"), lit("stash"), lit("pop"))},
			want: verdictNoMatch,
		},
		{
			name: "watched with uncertain word gets no allow",
			cmd:  Command{Words: argv(lit("git"), lit("log"), unc())},
			want: verdictNoMatch,
		},
		{
			name: "watched with output redirect abstains",
			cmd:  Command{Words: argv(lit("git"), lit("status")), OutputRedirect: true},
			want: verdictAbstain,
		},
		{
			name: "watched with env prefix abstains",
			cmd:  Command{Words: argv(lit("git"), lit("status")), EnvPrefix: true},
			want: verdictAbstain,
		},
		{
			name: "unwatched command",
			cmd:  Command{Words: argv(lit("curl"), lit("example.com"))},
			want: verdictUnwatched,
		},
		{
			name: "empty argv (bare assignment)",
			cmd:  Command{EnvPrefix: true},
			want: verdictUnwatched,
		},
		{
			name: "uncertain command name",
			cmd:  Command{Words: argv(unc(), lit("push"))},
			want: verdictUnwatched,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.judgeCommand(tt.cmd); got != tt.want {
				t.Errorf("judgeCommand(%+v) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

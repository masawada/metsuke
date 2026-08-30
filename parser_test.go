package main

import (
	"reflect"
	"testing"
)

func lit(s string) Word      { return Word{Text: s, Literal: true} }
func unc() Word              { return Word{Literal: false} }
func argv(ws ...Word) []Word { return ws }

func TestParseCommands(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Command
	}{
		{
			name: "single command",
			src:  "git status",
			want: []Command{
				{Words: argv(lit("git"), lit("status"))},
			},
		},
		{
			name: "and chain",
			src:  "git status && git push origin main",
			want: []Command{
				{Words: argv(lit("git"), lit("status"))},
				{Words: argv(lit("git"), lit("push"), lit("origin"), lit("main"))},
			},
		},
		{
			name: "pipe",
			src:  "git log | head -5",
			want: []Command{
				{Words: argv(lit("git"), lit("log"))},
				{Words: argv(lit("head"), lit("-5"))},
			},
		},
		{
			name: "semicolon and newline",
			src:  "git add .; git commit -m wip\ngit log",
			want: []Command{
				{Words: argv(lit("git"), lit("add"), lit("."))},
				{Words: argv(lit("git"), lit("commit"), lit("-m"), lit("wip"))},
				{Words: argv(lit("git"), lit("log"))},
			},
		},
		{
			name: "operator inside quotes is not a separator",
			src:  `echo "a && b"`,
			want: []Command{
				{Words: argv(lit("echo"), lit("a && b"))},
			},
		},
		{
			name: "single quotes",
			src:  `git commit -m 'foo bar'`,
			want: []Command{
				{Words: argv(lit("git"), lit("commit"), lit("-m"), lit("foo bar"))},
			},
		},
		{
			name: "command substitution arg is uncertain and inner command is extracted",
			src:  "git push $(cat target.txt)",
			want: []Command{
				{Words: argv(lit("git"), lit("push"), unc())},
				{Words: argv(lit("cat"), lit("target.txt"))},
			},
		},
		{
			name: "backquote substitution",
			src:  "echo `date`",
			want: []Command{
				{Words: argv(lit("echo"), unc())},
				{Words: argv(lit("date"))},
			},
		},
		{
			name: "variable expansion is uncertain",
			src:  "git checkout $BRANCH",
			want: []Command{
				{Words: argv(lit("git"), lit("checkout"), unc())},
			},
		},
		{
			name: "unquoted glob is uncertain",
			src:  "rm -rf *",
			want: []Command{
				{Words: argv(lit("rm"), lit("-rf"), unc())},
			},
		},
		{
			name: "tilde is uncertain",
			src:  "rm -rf ~/tmp",
			want: []Command{
				{Words: argv(lit("rm"), lit("-rf"), unc())},
			},
		},
		{
			name: "env assignment prefix",
			src:  "GIT_DIR=/x git push",
			want: []Command{
				{Words: argv(lit("git"), lit("push")), EnvPrefix: true},
			},
		},
		{
			name: "bare assignment yields empty argv command",
			src:  "FOO=$(git status)",
			want: []Command{
				{EnvPrefix: true},
				{Words: argv(lit("git"), lit("status"))},
			},
		},
		{
			name: "output redirect",
			src:  "git status > out.txt",
			want: []Command{
				{Words: argv(lit("git"), lit("status")), OutputRedirect: true},
			},
		},
		{
			name: "append redirect",
			src:  "git status >> out.txt",
			want: []Command{
				{Words: argv(lit("git"), lit("status")), OutputRedirect: true},
			},
		},
		{
			name: "stderr redirect to file",
			src:  "git status 2> err.txt",
			want: []Command{
				{Words: argv(lit("git"), lit("status")), OutputRedirect: true},
			},
		},
		{
			name: "fd duplication is harmless",
			src:  "git status 2>&1",
			want: []Command{
				{Words: argv(lit("git"), lit("status"))},
			},
		},
		{
			name: "input redirect is harmless",
			src:  "git apply < patch.diff",
			want: []Command{
				{Words: argv(lit("git"), lit("apply"))},
			},
		},
		{
			name: "subshell",
			src:  "(git push)",
			want: []Command{
				{Words: argv(lit("git"), lit("push"))},
			},
		},
		{
			name: "for loop body is extracted with uncertain loop variable",
			src:  "for f in a b; do git add $f; done",
			want: []Command{
				{Words: argv(lit("git"), lit("add"), unc())},
			},
		},
		{
			name: "redirect on compound applies conservatively to inner commands",
			src:  "{ git status; } > out.txt",
			want: []Command{
				{Words: argv(lit("git"), lit("status")), OutputRedirect: true},
			},
		},
		{
			name: "c-style loop header substitutions are extracted",
			src:  "for ((i=$(git push); i<3; i++)); do echo x; done",
			want: []Command{
				{Words: argv(lit("git"), lit("push"))},
				{Words: argv(lit("echo"), lit("x"))},
			},
		},
		{
			name: "case pattern substitutions are extracted",
			src:  "case x in $(git push)) echo y;; esac",
			want: []Command{
				{Words: argv(lit("git"), lit("push"))},
				{Words: argv(lit("echo"), lit("y"))},
			},
		},
		{
			name: "array subscript substitutions are extracted",
			src:  "a[$(git push)]=x",
			want: []Command{
				{EnvPrefix: true},
				{Words: argv(lit("git"), lit("push"))},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCommands(tt.src)
			if err != nil {
				t.Fatalf("parseCommands(%q) error: %v", tt.src, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCommands(%q)\n got: %+v\nwant: %+v", tt.src, got, tt.want)
			}
		})
	}
}

func TestParseCommandsError(t *testing.T) {
	for _, src := range []string{"git status &&", "echo 'unterminated"} {
		if _, err := parseCommands(src); err == nil {
			t.Errorf("parseCommands(%q) expected error, got nil", src)
		}
	}
}

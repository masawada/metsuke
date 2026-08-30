package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config holds the deny/allow rules. Each rule is an argv token sequence
// matched as a prefix against a simple command. Watched commands are the
// union of the first tokens of all rules.
type Config struct {
	denyRules  [][]string
	allowRules [][]string
	watched    map[string]bool
}

// cmdVerdict is the result of judging a single simple command.
type cmdVerdict int

const (
	// verdictDeny: a deny rule matched.
	verdictDeny cmdVerdict = iota
	// verdictAllow: the command is watched and an allow rule matched.
	verdictAllow
	// verdictNoMatch: the command is watched but no rule matched; the
	// aggregate decision becomes ask.
	verdictNoMatch
	// verdictAbstain: the command is watched and would otherwise be
	// allowable, but carries an output redirect or env assignment prefix,
	// so no allow is granted and the normal permission flow decides.
	verdictAbstain
	// verdictUnwatched: no rules are defined for this command.
	verdictUnwatched
)

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (*Config, error) {
	var raw struct {
		Deny  []string `toml:"deny"`
		Allow []string `toml:"allow"`
	}
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	cfg := &Config{watched: map[string]bool{}}
	for _, s := range raw.Deny {
		rule, err := parseRule(s)
		if err != nil {
			return nil, fmt.Errorf("deny rule %q: %w", s, err)
		}
		cfg.denyRules = append(cfg.denyRules, rule)
		cfg.watched[rule[0]] = true
	}
	for _, s := range raw.Allow {
		rule, err := parseRule(s)
		if err != nil {
			return nil, fmt.Errorf("allow rule %q: %w", s, err)
		}
		cfg.allowRules = append(cfg.allowRules, rule)
		cfg.watched[rule[0]] = true
	}
	return cfg, nil
}

// parseRule tokenizes a rule string with the same lexer as real commands.
// A rule must be a single simple command made of literal words only, so
// mistakes like `git push | cat` are rejected instead of silently never
// matching.
func parseRule(s string) ([]string, error) {
	cmds, err := parseCommands(s)
	if err != nil {
		return nil, err
	}
	if len(cmds) != 1 {
		return nil, fmt.Errorf("must be a single simple command")
	}
	cmd := cmds[0]
	if len(cmd.Words) == 0 {
		return nil, fmt.Errorf("must contain a command name")
	}
	if cmd.OutputRedirect {
		return nil, fmt.Errorf("must not contain a redirect")
	}
	if cmd.EnvPrefix {
		return nil, fmt.Errorf("must not contain an env assignment")
	}
	rule := make([]string, len(cmd.Words))
	for i, w := range cmd.Words {
		if !w.Literal {
			return nil, fmt.Errorf("must consist of literal words only")
		}
		rule[i] = w.Text
	}
	if strings.Contains(rule[0], "/") {
		return nil, fmt.Errorf("command name must be a bare name")
	}
	return rule, nil
}

// judgeCommand judges one simple command against the rules.
//
// Deny matching compares the basename of argv[0] so that /usr/bin/git is
// still caught. Allow matching requires a bare command name so that a local
// binary like ./git cannot impersonate an allowed command.
func (c *Config) judgeCommand(cmd Command) cmdVerdict {
	if len(cmd.Words) == 0 || !cmd.Words[0].Literal {
		return verdictUnwatched
	}
	name := filepath.Base(cmd.Words[0].Text)
	for _, rule := range c.denyRules {
		if rule[0] == name && prefixMatch(rule[1:], cmd.Words[1:]) {
			return verdictDeny
		}
	}
	if !c.watched[name] {
		return verdictUnwatched
	}
	if cmd.OutputRedirect || cmd.EnvPrefix {
		return verdictAbstain
	}
	for _, w := range cmd.Words {
		if !w.Literal {
			return verdictNoMatch
		}
	}
	if !strings.Contains(cmd.Words[0].Text, "/") {
		for _, rule := range c.allowRules {
			if rule[0] == cmd.Words[0].Text && prefixMatch(rule[1:], cmd.Words[1:]) {
				return verdictAllow
			}
		}
	}
	return verdictNoMatch
}

// prefixMatch reports whether every rule token equals the corresponding
// argv word. Uncertain words never match a token.
func prefixMatch(rule []string, words []Word) bool {
	if len(words) < len(rule) {
		return false
	}
	for i, tok := range rule {
		if !words[i].Literal || words[i].Text != tok {
			return false
		}
	}
	return true
}

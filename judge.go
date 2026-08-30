package main

import (
	"fmt"
	"strings"
)

// decision is the aggregate permission decision for a whole command line.
type decision int

const (
	decisionDeny decision = iota
	decisionAsk
	decisionAllow
	// decisionDelegate: metsuke stays silent and the normal permission
	// flow (rules, then the auto-mode classifier) decides.
	decisionDelegate
)

func (d decision) String() string {
	switch d {
	case decisionDeny:
		return "deny"
	case decisionAsk:
		return "ask"
	case decisionAllow:
		return "allow"
	default:
		return "delegate"
	}
}

// judge aggregates per-command verdicts into one decision:
//
//  1. any deny wins
//  2. any watched command without a matching rule asks
//  3. allow only when every command is watched and allowed
//  4. anything else delegates, so an allow from metsuke never lets
//     unwatched commands skip the classifier
func (c *Config) judge(cmds []Command) (decision, string) {
	allAllowed := len(cmds) > 0
	askReason := ""
	for _, cmd := range cmds {
		verdict, rule := c.judgeCommand(cmd)
		switch verdict {
		case verdictDeny:
			return decisionDeny, fmt.Sprintf("%q matches deny rule %q", cmdText(cmd), strings.Join(rule, " "))
		case verdictNoMatch:
			if askReason == "" {
				askReason = fmt.Sprintf("no rule matches watched command %q", cmdText(cmd))
			}
		case verdictAllow:
		default:
			allAllowed = false
		}
	}
	if askReason != "" {
		return decisionAsk, askReason
	}
	if allAllowed {
		return decisionAllow, "all commands match allow rules"
	}
	return decisionDelegate, ""
}

// cmdText renders a command for use in decision reasons. Words whose value
// is not known until runtime are shown as "?".
func cmdText(cmd Command) string {
	parts := make([]string, len(cmd.Words))
	for i, w := range cmd.Words {
		if w.Literal {
			parts[i] = w.Text
		} else {
			parts[i] = "?"
		}
	}
	return strings.Join(parts, " ")
}

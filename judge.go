package main

import (
	"fmt"
	"strings"
)

// decision is the aggregate permission decision for a whole command line.
// metsuke never emits "allow": an allow-rule match only prevents an ask,
// and the normal permission flow (rules, then the auto-mode classifier)
// still decides. This way a parsing blind spot can at worst delegate,
// never wave a dangerous command through.
type decision int

const (
	decisionDeny decision = iota
	decisionAsk
	// decisionDelegate: metsuke stays silent and the normal permission
	// flow decides.
	decisionDelegate
)

func (d decision) String() string {
	switch d {
	case decisionDeny:
		return "deny"
	case decisionAsk:
		return "ask"
	default:
		return "delegate"
	}
}

// judge aggregates per-command verdicts into one decision:
//
//  1. any deny wins
//  2. any watched command without a matching allow rule asks
//  3. everything else delegates
func (c *Config) judge(cmds []Command) (decision, string) {
	askReason := ""
	for _, cmd := range cmds {
		verdict, rule := c.judgeCommand(cmd)
		switch verdict {
		case verdictDeny:
			return decisionDeny, fmt.Sprintf("%q matches deny rule %q", cmdText(cmd), strings.Join(rule, " "))
		case verdictAsk:
			if askReason == "" {
				askReason = fmt.Sprintf("no rule matches watched command %q", cmdText(cmd))
			}
		}
	}
	if askReason != "" {
		return decisionAsk, askReason
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

package main

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
func (c *Config) judge(cmds []Command) decision {
	allAllowed := len(cmds) > 0
	sawAsk := false
	for _, cmd := range cmds {
		switch c.judgeCommand(cmd) {
		case verdictDeny:
			return decisionDeny
		case verdictNoMatch:
			sawAsk = true
		case verdictAllow:
		default:
			allAllowed = false
		}
	}
	if sawAsk {
		return decisionAsk
	}
	if allAllowed {
		return decisionAllow
	}
	return decisionDelegate
}

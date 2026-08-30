package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Word is a single argv element of a simple command. When Literal is false,
// the value is not known until runtime (it contains parameter expansion,
// command substitution, globs, tilde expansion, etc.).
type Word struct {
	Text    string
	Literal bool
}

// Command is one simple command extracted from a command line. Commands found
// inside command substitutions are extracted as siblings.
type Command struct {
	Words          []Word
	OutputRedirect bool
	EnvPrefix      bool
}

// parseCommands parses a whole shell command line and extracts every simple
// command that may be executed.
func parseCommands(src string) ([]Command, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	return visitStmts(nil, file.Stmts, false), nil
}

func visitStmts(cmds []Command, stmts []*syntax.Stmt, redirected bool) []Command {
	for _, s := range stmts {
		cmds = visitStmt(cmds, s, redirected)
	}
	return cmds
}

// visitStmt processes one statement. redirected reports that an enclosing
// compound command carries an output redirect; it propagates conservatively
// to every inner command.
func visitStmt(cmds []Command, stmt *syntax.Stmt, redirected bool) []Command {
	redirected = redirected || hasOutputRedirect(stmt.Redirs)
	cmds = visitCommand(cmds, stmt.Cmd, redirected)
	// Substitutions buried in redirect targets still run; extract them so
	// deny rules can see them.
	for _, r := range stmt.Redirs {
		if r.Word != nil {
			cmds = visitWordSubsts(cmds, r.Word)
		}
		if r.Hdoc != nil {
			cmds = visitWordSubsts(cmds, r.Hdoc)
		}
	}
	return cmds
}

func visitCommand(cmds []Command, cmd syntax.Command, redirected bool) []Command {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		var words []Word
		for _, w := range c.Args {
			words = append(words, evalWord(w))
		}
		cmds = append(cmds, Command{
			Words:          words,
			OutputRedirect: redirected,
			EnvPrefix:      len(c.Assigns) > 0,
		})
		for _, w := range c.Args {
			cmds = visitWordSubsts(cmds, w)
		}
		for _, a := range c.Assigns {
			if a.Value != nil {
				cmds = visitWordSubsts(cmds, a.Value)
			}
			if a.Array != nil {
				for _, el := range a.Array.Elems {
					if el.Value != nil {
						cmds = visitWordSubsts(cmds, el.Value)
					}
				}
			}
		}
		return cmds
	case *syntax.BinaryCmd:
		cmds = visitStmt(cmds, c.X, redirected)
		return visitStmt(cmds, c.Y, redirected)
	case *syntax.Block:
		return visitStmts(cmds, c.Stmts, redirected)
	case *syntax.Subshell:
		return visitStmts(cmds, c.Stmts, redirected)
	case *syntax.IfClause:
		cmds = visitStmts(cmds, c.Cond, redirected)
		cmds = visitStmts(cmds, c.Then, redirected)
		if c.Else != nil {
			cmds = visitCommand(cmds, c.Else, redirected)
		}
		return cmds
	case *syntax.WhileClause:
		cmds = visitStmts(cmds, c.Cond, redirected)
		return visitStmts(cmds, c.Do, redirected)
	case *syntax.ForClause:
		if wi, ok := c.Loop.(*syntax.WordIter); ok {
			for _, w := range wi.Items {
				cmds = visitWordSubsts(cmds, w)
			}
		}
		return visitStmts(cmds, c.Do, redirected)
	case *syntax.CaseClause:
		cmds = visitWordSubsts(cmds, c.Word)
		for _, item := range c.Items {
			cmds = visitStmts(cmds, item.Stmts, redirected)
		}
		return cmds
	case *syntax.FuncDecl:
		return visitStmt(cmds, c.Body, false)
	case *syntax.TimeClause:
		if c.Stmt != nil {
			cmds = visitStmt(cmds, c.Stmt, redirected)
		}
		return cmds
	case *syntax.CoprocClause:
		if c.Stmt != nil {
			cmds = visitStmt(cmds, c.Stmt, redirected)
		}
		return cmds
	case nil:
		return cmds
	default:
		// DeclClause, LetClause, TestClause, etc.: extract only the inner
		// command substitutions so deny rules can see them.
		syntax.Walk(c, func(node syntax.Node) bool {
			switch n := node.(type) {
			case *syntax.CmdSubst:
				cmds = visitStmts(cmds, n.Stmts, false)
				return false
			case *syntax.ProcSubst:
				cmds = visitStmts(cmds, n.Stmts, false)
				return false
			}
			return true
		})
		return cmds
	}
}

// visitWordSubsts extracts commands buried in command/process substitutions
// within a word. Substitutions run in a subshell, so the enclosing redirect
// context does not carry over.
func visitWordSubsts(cmds []Command, w *syntax.Word) []Command {
	syntax.Walk(w, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CmdSubst:
			cmds = visitStmts(cmds, n.Stmts, false)
			return false
		case *syntax.ProcSubst:
			cmds = visitStmts(cmds, n.Stmts, false)
			return false
		}
		return true
	})
	return cmds
}

// evalWord returns the literal value of a word, or an uncertain Word
// (Literal: false) if the word contains any expansion.
func evalWord(w *syntax.Word) Word {
	var sb strings.Builder
	for _, part := range w.Parts {
		s, ok := litPart(part)
		if !ok {
			return Word{}
		}
		sb.WriteString(s)
	}
	return Word{Text: sb.String(), Literal: true}
}

func litPart(p syntax.WordPart) (string, bool) {
	switch n := p.(type) {
	case *syntax.Lit:
		// Characters that may trigger globbing, escaping, or tilde
		// expansion make the value uncertain.
		if strings.ContainsAny(n.Value, `*?[\~`) {
			return "", false
		}
		return n.Value, true
	case *syntax.SglQuoted:
		if n.Dollar {
			// $'...' may contain escape sequences.
			return "", false
		}
		return n.Value, true
	case *syntax.DblQuoted:
		var sb strings.Builder
		for _, part := range n.Parts {
			l, ok := part.(*syntax.Lit)
			if !ok || strings.Contains(l.Value, `\`) {
				return "", false
			}
			sb.WriteString(l.Value)
		}
		return sb.String(), true
	default:
		return "", false
	}
}

// hasOutputRedirect reports whether any redirect writes to a file.
// Fd duplication (e.g. 2>&1) and input redirects are considered harmless.
func hasOutputRedirect(redirs []*syntax.Redirect) bool {
	for _, r := range redirs {
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.ClbOut, syntax.RdrInOut:
			return true
		case syntax.DplOut:
			// >&N and >&- only manipulate fds; anything else behaves
			// like >&file and writes.
			if w := evalWord(r.Word); !w.Literal || !isFdRef(w.Text) {
				return true
			}
		}
	}
	return false
}

func isFdRef(s string) bool {
	if s == "-" {
		return true
	}
	s = strings.TrimSuffix(s, "-")
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

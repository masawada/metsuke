# metsuke

metsuke (目付, an Edo-period inspector) is a PreToolUse hook for
[Claude Code](https://code.claude.com/) that inspects Bash commands with a
real shell parser before they run.

Claude Code's built-in permission rules match a command line as a single
glob pattern, so a compound command like `git commit && git push` can slip
past a `Bash(git push *)` rule. metsuke parses the command line with
[mvdan/sh](https://github.com/mvdan/sh), splits it into simple commands
(including those hidden in pipes, `&&`/`;` chains, subshells, and command
substitutions), and checks each one against your rules.

## How it decides

Rules are argv token sequences matched as a prefix. For each Bash call,
metsuke returns one of three outcomes:

1. **deny** — some command matches a deny rule. The call is blocked.
2. **ask** — some watched command matches no allow rule. A permission
   dialog is shown even in auto mode.
3. **delegate** — everything else. metsuke stays silent and the normal
   permission flow (your permission rules, then the auto-mode classifier)
   decides.

A command is *watched* when any rule starts with its name. In other words:
deny rules block, allow rules only suppress the ask for commands you have
reviewed, and everything you have no opinion about is left to Claude Code.

metsuke never emits an `allow` decision. An allow-rule match just means
"do not ask", and the command line still goes through the normal
permission flow. This is a deliberate safety property: if metsuke's parser
misreads a command, the worst outcome is a delegation — it can never wave
a dangerous command through on its own.

Some details of the matching:

- Deny matching compares the basename of argv[0], so `/usr/bin/git push`
  is still caught. Allow matching requires a bare command name, so a local
  `./git` cannot impersonate an allowed command.
- Words whose value is not known until runtime (`$VAR`, `$(...)`, globs,
  tilde expansion, escapes) never satisfy a rule token. A watched command
  with such words falls through to ask.
- Commands inside `$(...)` are extracted and checked against deny rules
  too, including in loop headers, case patterns, and array subscripts.
- If the configuration is missing or broken, every Bash call degrades to
  **ask** with the error in the reason — a misconfigured metsuke gets loud,
  not silently disabled. Only an unparseable command line delegates.

## Install

```console
$ go install github.com/masawada/metsuke@latest
```

## Configure

Write your rules in TOML. Each rule is written exactly like the command
you would type; it must be a single simple command made of literal words
(quoting is fine), and anything else — pipes, redirects, expansions —
is rejected at load time so a rule like `"git push | cat"` cannot
silently never match.

```toml
# ~/.config/metsuke/config.toml
deny = [
  "git credential",
  "gh auth token",
]
allow = [
  "git status",
  "git log",
  "git diff",
  "gh pr view",
  "gh pr list",
]
```

With this configuration, `git push` (watched via the other git rules, but
matching neither list) asks, `git log --oneline` delegates without a
prompt, and `gh auth token` is always blocked — even when buried in a
pipeline or a `$(...)`.

The configuration is looked up in this order:

1. `--config <path>`
2. `$XDG_CONFIG_HOME/metsuke/config.toml`
3. `$HOME/.config/metsuke/config.toml`

## Register the hook

Add a PreToolUse hook to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/bin/metsuke --config ~/.config/metsuke/config.toml"
          }
        ]
      }
    ]
  }
}
```

### Protect the configuration from the agent

metsuke is only meaningful if Claude cannot rewrite its rules or its
binary. Deny the agent access to them in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Edit(~/.config/metsuke/**)"
    ]
  },
  "sandbox": {
    "filesystem": {
      "denyWrite": [
        "/path/to/bin",
        "~/.config/metsuke/config.toml"
      ]
    }
  }
}
```

`settings.json` itself (the hook registration) is already write-protected
by Claude Code's sandbox.

## Limitations

Deny rules are **best-effort, not a security boundary**. Static analysis
cannot fully resolve what bash will execute: brace expansion
(`{git,push}`), escaped command names (`g\it push`), extended glob
patterns, and arithmetic re-evaluation of variable values can all hide a
command from the parser. Because metsuke never allows, such blind spots
degrade to delegation — the normal permission flow still sees the full
command text — but do not rely on a deny rule as your only defense.
Keep critical denies in Claude Code's own `permissions.deny` as an
additional layer.

## License

[MIT](LICENSE)

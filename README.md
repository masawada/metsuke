# metsuke

metsuke (目付, an Edo-period inspector) is a PreToolUse hook for [Claude Code](https://code.claude.com/) that inspects Bash commands with a real shell parser before they run.

Claude Code's built-in permission rules already split compound commands (`&&`, `;`, pipes) and require each subcommand to match. metsuke digs deeper: it parses the command line into a full AST with [mvdan/sh](https://github.com/mvdan/sh), so it also sees commands hidden in command substitutions, loop headers, and array subscripts; it matches rules token by token instead of by glob; and it lets you declare *watched* commands whose unreviewed invocations always require an explicit confirmation and cannot be silently approved by the auto-mode classifier.

## How it decides

Rules are argv token sequences matched as a prefix. For each Bash call, metsuke returns one of three outcomes:

1. **deny** — some command matches a deny rule. The call is blocked.
2. **ask** — some watched command matches no allow rule. A permission dialog is shown even in auto mode.
3. **delegate** — everything else. metsuke stays silent and the normal permission flow (your permission rules, then the auto-mode classifier) decides.

A command is *watched* when any rule starts with its name. In other words: deny rules block, allow rules only suppress the ask for commands you have reviewed, and everything you have no opinion about is left to Claude Code.

metsuke never emits an `allow` decision. An allow-rule match just means "do not ask", and the command line still goes through the normal permission flow. This is a deliberate safety property: if metsuke's parser misreads a command, the worst outcome is a delegation — it can never wave a dangerous command through on its own.

Some details of the matching:

- Deny matching compares the basename of argv[0], so `/usr/bin/git push` is still caught. Allow matching requires a bare command name, so a local `./git` cannot impersonate an allowed command.
- Words whose value is not known until runtime (`$VAR`, `$(...)`, globs, tilde expansion, escapes) never satisfy a rule token, so an uncertain word inside the matched prefix means no match. Uncertain words after an already-matched allow prefix are treated like any other trailing arguments — the command delegates.
- Commands inside `$(...)` are extracted and checked against deny rules too, including in loop headers, case patterns, and array subscripts.
- If the configuration is missing or broken, every Bash call degrades to **ask** with the error in the reason — a misconfigured metsuke gets loud, not silently disabled. Only an unparseable command line delegates.

## Install

```console
$ brew install masawada/tap/metsuke
```

Or with `go install`:

```console
$ go install github.com/masawada/metsuke@latest
```

## Configure

Write your rules in TOML. Each rule is written exactly like the command you would type; it must be a single simple command made of literal words (quoting is fine), and anything else — pipes, redirects, expansions — is rejected at load time so a rule like `"git push | cat"` cannot silently never match.

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

With this configuration, `git push` (watched via the other git rules, but matching neither list) asks, `git log --oneline` delegates without a prompt, and `gh auth token` is always blocked — even when buried in a pipeline or a `$(...)`.

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

metsuke is only meaningful if Claude cannot rewrite its rules or its binary. Two layers are needed because they cover different write paths: `permissions.deny` blocks Claude's built-in file-editing tools, and the sandbox blocks writes from the shell commands Claude runs. The sandbox defaults are permissive — `sandbox.enabled` is off and commands may retry outside the sandbox — so a hard setup should pin them explicitly:

```json
{
  "permissions": {
    "deny": [
      "Edit(~/.config/metsuke/**)",
      "Edit(//path/to/bin/**)"
    ]
  },
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "failIfUnavailable": true,
    "filesystem": {
      "denyWrite": [
        "/path/to/bin",
        "~/.config/metsuke/config.toml"
      ]
    }
  }
}
```

Merge this with the hook registration above into one `settings.json`.

`permissions.deny` rules and the sandbox keep applying in every permission mode, including bypass-permissions mode. What bypass mode does skip is the approval check for protected paths such as `~/.claude`, so the hook registration in `settings.json` itself becomes editable there — do not treat this setup as tamper-proof under bypass mode.

## Limitations

Deny rules are **best-effort, not a security boundary**. Static analysis cannot fully resolve what bash will execute: brace expansion (`{git,push}`), escaped command names (`g\it push`), extended glob patterns, and arithmetic re-evaluation of variable values can all hide a command from the parser. Because metsuke never allows, such blind spots degrade to delegation — the normal permission flow still sees the full command text — but do not rely on a deny rule as your only defense. Keep critical denies in Claude Code's own `permissions.deny` as an additional layer.

## License

[MIT](LICENSE)

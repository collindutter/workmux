---
title: "Rex"
description: Use Rex as a multiplexer backend
---

:::caution[Experimental]
The Rex backend supports worktree tabs within an existing Rex session.
Session mode (`--session`) and the tmux sidebar are not supported.
:::

Run workmux inside a [Rex](https://www.superlogical.com/rex/) terminal with
`rex` on your `PATH`.

workmux detects `REX_SESSION` or `REX_BLOCK`. To override detection:

```sh
WORKMUX_BACKEND=rex workmux add my-feature
```

Existing `panes` configuration applies:

```yaml
panes:
  - command: nvim
    focus: true
  - command: pi
    split: horizontal
    percentage: 50
```

Each worktree gets a Rex tab. `workmux close` closes its tab without deleting
the worktree; `workmux open` recreates it. `workmux remove` cleans up both.

## Agent tracking

Install your agent's [status hooks](/guide/status-tracking/) to use
`workmux status`, `dashboard`, `send`, `capture`, and `wait`.
Workmux stores agent status keyed by Rex server and block ID. Icons are not
added to tab labels. Rex itself supports native program status through
[OSC 7501](https://www.superlogical.com/rex/docs/build/program-status), but workmux
status hooks do not currently report it: hooks may run outside the target pane
or have their output captured, and Rex's terminal `write` API sends input, not
terminal output.

## Limitations

- Run workmux on the same host as the Rex server. Worktree paths and shell
  startup handshakes use the local filesystem.
- Foreground tabs and dashboard jumps select the connected Rex app. If several
  apps are connected, set `REX_CLIENT` to its label or ID (`rex client ls`).
  Without a connected app, only server-side focus changes.
- Use `percentage` for pane sizing. Fixed-cell `size` and Zellij's
  `split: stacked` are not supported.
- Rex has no pane-respawn operation. Starting a configured command replaces
  the initial block while keeping its tab.

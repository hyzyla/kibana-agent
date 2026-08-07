# kibana-agent

Read-only Kibana/ES CLI for AI agents. Queries Elasticsearch through Kibana's console proxy API.

## Install

```bash
uv tool install kibana-agent

# or just run:
# uvx kibana-agent
```

## Setup

```bash
kibana-agent profile create prd --url https://kibana.example.com --auth 1password \
  --op-username "op://vault/item/username" --op-password "op://vault/item/password" --use
```

Auth: `1password` (Touch ID, cached 24h per profile), `keychain` (OS keyring — macOS Keychain / Linux Secret Service / Windows Credential Locker via the [`keyring`](https://pypi.org/project/keyring/) library; on Linux requires a running Secret Service provider such as gnome-keyring, KWallet, or KeePassXC), `plain`.

## Usage

```bash
kibana-agent context                                            # index overview
kibana-agent search 'my-index-*' --last 1h -n 10                 # search logs
kibana-agent count 'my-index-*' -q '{"match":{"level":"ERROR"}}'   # count docs
kibana-agent tail 'my-index-*' -f @timestamp,level,message        # live stream
kibana-agent histogram 'my-index-*' --last 6h --interval 10m     # date histogram
kibana-agent discover 'my-index-*' --kql "level:ERROR"            # Kibana URL
```

## Agent setup

### Install the skill (recommended)

This repo ships an [agent skill](skills/kibana-agent/SKILL.md) that teaches an agent how to drive
the CLI: which query matches which field type, how to read the hints on stderr, and why an empty
result is usually a wrong query rather than missing data.

```bash
npx skills add hyzyla/kibana-agent -g     # all projects
npx skills add hyzyla/kibana-agent        # this project only
npx skills update                         # pull later changes
```

This works with any agent the [skills CLI](https://github.com/vercel-labs/skills) supports — Claude
Code, Cursor, Codex, and others. For Claude Code it installs to `~/.claude/skills/` (global) or
`.claude/skills/` (project), and loads automatically when you ask about Kibana, Elasticsearch, or
logs.

To install by hand instead, copy or symlink `skills/kibana-agent/` into your agent's skills
directory.

### Without a skill

Add to your `CLAUDE.md` (or equivalent system prompt):

```markdown
Use `kibana-agent` to query Elasticsearch. Start with `kibana-agent context` to
discover indices and fields, then use `kibana-agent search`, `kibana-agent count`,
`kibana-agent histogram` to investigate. Read stderr: the CLI warns when a query
cannot match and explains empty results. Run `kibana-agent agent-help` for the
full reference.
```

Output is JSON. All operations are read-only.

## MCP server

The same operations are also available as an MCP server (`kibana-agent mcp`) for use with Claude Code, Claude Desktop, Cursor, etc. Profiles and credentials are shared with the CLI.

## License

MIT

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

Auth: `1password` (Touch ID, cached 30 min), `keychain` (OS keyring — macOS Keychain / Linux Secret Service / Windows Credential Locker via the [`keyring`](https://pypi.org/project/keyring/) library; on Linux requires a running Secret Service provider such as gnome-keyring, KWallet, or KeePassXC), `plain`.

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

Add to your `CLAUDE.md` (or equivalent system prompt):

```markdown
Use `kibana-agent` to query Elasticsearch. Start with `kibana-agent context` to
discover indices and fields, then use `kibana-agent search`, `kibana-agent count`,
`kibana-agent histogram` to investigate. Run `kibana-agent agent-help` for full
usage reference.
```

Output is JSON. All operations are read-only.

## License

MIT

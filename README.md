# brektra-cli

Run AI app security scans from your terminal.

```
npx brektra-cli scan http://localhost:3000
```

Localhost runs need no signup. They probe common chat endpoints with safe-mode prompt-injection payloads and report what came back.

## Install

```sh
npm install -g brektra-cli
```

Or just use `npx brektra-cli ...`. Both work.

## Sign in

Sign in to scan public domains and view replay links.

```sh
brektra login
```

This opens the API keys page. Create a key, paste it back into the terminal. The token is saved to `~/.brektra/config.json`.

## Scan a verified domain

Add the target as a verified domain in the dashboard first.

```sh
brektra scan https://app.example.com
```

The scan runs on Brektra's cloud orchestrator. The CLI streams progress and prints a replay link at the end.

## Run a single Atlas pattern

Pick any pattern from [the Attack Atlas](https://brektra.com/atlas).

```sh
brektra atlas direct-instruction-override --target https://app.example.com
```

## Open the replay

```sh
brektra replay scan_abc123
```

## Flags

| flag | what it does |
|------|--------------|
| `--target <url>` | required for atlas runs |
| `--mode safe\|aggressive` | defaults to `safe` |
| `--json` | machine-readable output (planned) |

## Exit codes

`0` no findings. `2` findings present (use this in CI). `1` something broke.

## Docs

Full docs at [brektra.com/docs/cli](https://brektra.com/docs/cli).

## License

MIT

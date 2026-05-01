# brektra-cli

Run security scans across web, AI, cloud, CI/CD, mobile, and network surfaces from your terminal.

```sh
npx brektra-cli scan web http://localhost:3000
```

Localhost web runs need no signup — they probe common chat endpoints with safe-mode payloads and report what came back. Everything else runs on Brektra's cloud orchestrator.

## Install

```sh
npm install -g brektra-cli
```

Or just use `npx brektra-cli ...`. Both work.

## Sign in

```sh
brektra login
```

This opens the API keys page. Paste a key back into the terminal — it's saved to `~/.brektra/config.json`.

## Scan surfaces

| command | what it scans | engine |
|---|---|---|
| `brektra scan web <url>` | DOM XSS, SSTI (13 engines), NoSQL/LDAP/XXE, OAuth, JWT, GraphQL deep | E10 |
| `brektra scan ai <endpoint>` | 58 modules incl. Crescendo, Skeleton Key, multimodal injection, GCG/PAIR/TAP | E11 |
| `brektra scan cloud <provider>` | AWS / GCP / Azure / K8s — 44 modules with compliance mapping | E12 |
| `brektra scan cicd <platform>` | GitHub Actions, GitLab CI, CircleCI, Jenkins, Bitbucket, Azure DevOps | E13 |
| `brektra scan mobile <apk-or-ipa>` | Android APK + iOS IPA static analysis (37 modules) | E14 |
| `brektra scan host <cidr>` | network / Active Directory scanning (via Brektra Agent) | Agent v1.0 |

The legacy form `brektra scan https://app.example.com` still works and defaults to a web scan.

### Surface-specific flags

```sh
# AI
brektra scan ai https://api.example.com/chat --crescendo --skeleton-key --multimodal

# Web
brektra scan web https://app.example.com --dom-xss --ssti --graphql

# Cloud
brektra scan cloud aws --aws-profile prod
brektra scan cloud gcp --gcp-creds ./sa.json
brektra scan cloud azure --azure-sub 00000000-0000-0000-0000-000000000000
brektra scan cloud k8s --k8s-config ~/.kube/config

# CI/CD
brektra scan cicd github --github-token $GITHUB_TOKEN
brektra scan cicd gitlab --gitlab-token $GITLAB_TOKEN
brektra scan cicd jenkins --jenkins-url https://ci.example.com

# Mobile (uploads the artifact)
brektra scan mobile ./app-release.apk
brektra scan mobile ./MyApp.ipa

# Host (requires a connected agent on the network)
brektra scan host 10.0.0.0/24
```

## Atlas patterns

Pick any pattern from [the Attack Atlas](https://brektra.com/atlas).

```sh
brektra atlas direct-instruction-override --target https://app.example.com
```

## CI mode

Multi-surface scans intended for pipelines.

```sh
brektra ci scan https://app.example.com \
  --surfaces web,ai,cloud \
  --fail-on-severity high
```

`--fail-on-severity` accepts `info|low|medium|high|critical`. The CLI exits `2` if any finding meets or exceeds the threshold (CVSS × EPSS composite is honored for severity rollups).

## Workspace utilities

```sh
brektra agents list                  # connected agents in the workspace
brektra agents update                # available agent updates
brektra engines list                 # connected scan engines
brektra playbooks <finding-id>       # remediation playbook for a finding
brektra compliance export soc2       # also: pci, hipaa, iso, nist, gdpr, fedramp
```

## Replay

```sh
brektra replay scan_abc123
```

## Exit codes

`0` no findings. `2` findings present (or `--fail-on-severity` threshold breached). `1` something broke.

## Docs

Full docs at [brektra.com/docs/cli](https://brektra.com/docs/cli).

## License

MIT

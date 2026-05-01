# Changelog

## 0.2.0

Adds CLI coverage for Engine v1.5 (5 new attack-surface phases) and Agent v1.0.

### New scan surfaces

- `brektra scan web <url>` — E10 web attack expansion: DOM XSS, SSTI (13 engines), NoSQL, LDAP, XXE, OAuth, JWT, GraphQL deep. Flags: `--dom-xss --ssti --nosql --ldap --xxe --oauth --jwt --graphql`.
- `brektra scan ai <endpoint>` — E11 AI attack expansion: 58 modules including Crescendo, Skeleton Key, multimodal injection, GCG, PAIR, TAP. Flags: `--crescendo --skeleton-key --multimodal --gcg --pair --tap`.
- `brektra scan cloud <provider>` — E12 cloud attack expansion: 44 modules across AWS/GCP/Azure/K8s with compliance mapping. Flags: `--aws-profile --gcp-creds --azure-sub --k8s-config`.
- `brektra scan cicd <platform>` — E13 CI/CD attacks: 53 modules across GitHub Actions, GitLab CI, CircleCI, Jenkins, Bitbucket, Azure DevOps. Flags: `--github-token --gitlab-token --jenkins-url`.
- `brektra scan mobile <apk-or-ipa>` — E14 mobile static analysis: 37 modules for Android APK + iOS IPA. Uploads the artifact before scanning.
- `brektra scan host <cidr>` — network / Active Directory scanning via a connected Brektra Agent v1.0.

### CI mode

- `brektra ci scan <target>` — multi-surface pipeline scans with `--surfaces web,ai,cloud,...`.
- `--fail-on-severity info|low|medium|high|critical` — exit `2` when any finding meets the threshold (CVSS × EPSS composite is honored).

### Workspace utilities

- `brektra agents list` and `brektra agents update`.
- `brektra engines list`.
- `brektra playbooks <finding-id>` — fetch a finding's remediation playbook.
- `brektra compliance export <framework>` — export evidence packages for `soc2`, `pci`, `hipaa`, `iso`, `nist`, `gdpr`, `fedramp`.

### Compatibility

- The legacy form `brektra scan <url>` still works and is treated as `brektra scan web <url>`.
- Localhost web targets continue to run via the local probe with no auth or telemetry.

## 0.1.1

- Fix `package.json` `bin` field.

## 0.1.0

- Initial release: `scan`, `atlas`, `login`, `replay`.

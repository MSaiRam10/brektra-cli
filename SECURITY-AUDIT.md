# Security Audit — brektra-cli

Date: 2026-05-02
Scope: full repo as of v0.2.0 (commit `b1d16c9`).
Auditor: in-tree audit.
Tooling: manual review, ripgrep secret/keyword sweep, `npm audit --omit=dev` (0 vulns).

## Applicability

`brektra-cli` is a Node.js CLI client. Several items on the requested checklist are **not applicable**:

- No SQL or DB layer → SQL injection N/A.
- No `child_process.exec`, `spawn`, or `shell:true` usage → command injection N/A.
- No HTTP server endpoints, no cookies, no CSRF, no security headers, no CORS → server-side classes N/A.
- No `eval`, `Function()`, `pickle`, `unserialize`, or JSON.parse reviver use → insecure deserialization N/A.
- No cryptographic primitives implemented locally; auth is bearer-token over TLS → crypto-mode/IV/key-reuse N/A.
- No file-mounted Docker/`/proc`/`/etc`/`--privileged` surfaces → container escape N/A.
- No login/signup/password-reset endpoints → that flavor of rate limiting N/A.
- No long-lived service credentials shipped with the package → rotation N/A.

This audit therefore focuses on what actually exists: a CLI that holds a bearer token, makes outbound HTTPS, accepts user-supplied URLs/paths/tokens on argv, opens URLs in the OS shell, and renders server-supplied strings to a terminal.

---

## CRITICAL — fixed

### C1. Credentials forwarded to attacker-controlled origin via `BREKTRA_API_URL`/`api_url`
- **Where**: [src/api.ts:79](src/api.ts#L79), [src/api.ts:130](src/api.ts#L130) (bearer attached); [src/config.ts](src/config.ts) (`apiBase` returned env value with no validation).
- **What was wrong**: `apiBase()` accepted any string from `cfg.api_url` or `BREKTRA_API_URL`. `authedFetch` and `uploadMobileArtifact` then attached the user's `bk_*` bearer to whatever destination resolved. A poisoned env var could exfiltrate the API key, GitHub PAT, GitLab PAT, AWS profile metadata, etc. Plain `http://` to a non-loopback host was also allowed, sending the bearer in cleartext.
- **Fix**: [src/safety.ts:12-32](src/safety.ts#L12-L32) `assertSafeApiBase` enforces `http`/`https` only and refuses `http://` to non-loopback. Wired in [src/config.ts:30-37](src/config.ts#L30-L37).

### C2. CI/CD secrets shipped over plain HTTP allowed
- **Where**: [src/scan.ts](src/scan.ts) `--github-token` / `--gitlab-token` collected and forwarded via `authedFetch`.
- **What was wrong**: same root as C1 — without scheme enforcement, tokens could traverse plain HTTP.
- **Fix**: scheme enforcement now hard-fails before any fetch. See `assertSafeApiBase` and the new bearer-shape validation at [src/scan.ts:135-148](src/scan.ts#L135-L148).

### C3. `open()` could launch arbitrary URI schemes
- **Where**: [src/replay.ts:9](src/replay.ts#L9), [src/auth.ts:12](src/auth.ts#L12).
- **What was wrong**: `open(url)` invokes the OS shell handler. A `cfg.api_url` of `javascript:`, `file:`, `vscode:`, `ms-something:`, etc. would be passed to the registered handler and could execute attacker-chosen code or read local files via `file:`.
- **Fix**: [src/safety.ts:34-43](src/safety.ts#L34-L43) `assertSafeOpenUrl` blocks any non-http(s) scheme; called from [src/replay.ts:11-16](src/replay.ts#L11-L16) and [src/auth.ts:9](src/auth.ts#L9).

### C4. Path traversal / smuggling via finding-id and scan-id in URLs
- **Where**: [src/api.ts:165](src/api.ts#L165) (playbook URL), [src/replay.ts:7](src/replay.ts#L7) (replay URL).
- **What was wrong**: ids embedded in URLs without shape validation. A crafted id could include `../`, `?`, `#`, or query params that change the request semantics.
- **Fix**: strict `/^[A-Za-z0-9_\-]{1,64}$/` validators at [src/replay.ts:8-12](src/replay.ts#L8-L12) and [src/playbooks.ts:11-15](src/playbooks.ts#L11-L15); `encodeURIComponent` on the id where embedded.

---

## HIGH — fixed

### H1. API key prefix check was a substring; key could be echoed in error chains
- **Where**: [src/auth.ts:16-19](src/auth.ts#L16-L19) (old `startsWith("bk_")`), and in any wrapped `Error.message` flowing through `console.error`.
- **Fix**: [src/safety.ts:81-95](src/safety.ts#L81-L95) `validateApiKey` enforces `^bk_[A-Za-z0-9_\-]{16,}$` with a length cap of 256, and error messages report shape only — never the value. Wired into both `login()` and `requireApiKey()`.

### H2. Server error bodies leaked verbatim into thrown `Error.message`
- **Where**: [src/api.ts:88-90](src/api.ts#L88-L90).
- **Fix**: `redactErrorBody` strips `Authorization` headers, `Bearer …` tokens, and `bk_…` strings, then truncates to 500 chars. See [src/safety.ts:55-63](src/safety.ts#L55-L63) and the call site at [src/api.ts:91-95](src/api.ts#L91-L95).

### H3. Mobile artifact uploader had no extension/symlink/size guard
- **Where**: [src/api.ts:121-137](src/api.ts#L121-L137).
- **What was wrong**: `fs.readFile(filePath)` with user-supplied path would happily read `/etc/shadow`, follow a symlink to `~/.aws/credentials`, or buffer a 50 GB file into memory and POST it.
- **Fix**: extension allowlist `.apk`/`.ipa` ([src/safety.ts:97-107](src/safety.ts#L97-L107)), `lstat` symlink rejection, regular-file check, 500 MB cap, and a 10-minute upload timeout. See [src/api.ts:130-152](src/api.ts#L130-L152).

### H4. `runLocalScan` had no defense-in-depth loopback check
- **Where**: [src/local-scan.ts:28](src/local-scan.ts#L28).
- **What was wrong**: the loopback regex lived only in the dispatcher. `runLocalScan` is exported and could be reached by another caller with a non-loopback URL, sending unauthenticated probes off-host.
- **Fix**: re-validates inside via `isLoopback` ([src/local-scan.ts:30-44](src/local-scan.ts#L30-L44)).

### H5. POSIX `mkdir` mode unset for `~/.brektra`
- **Where**: [src/config.ts:23](src/config.ts#L23).
- **Fix**: directory now created `0o700` on POSIX ([src/config.ts:27](src/config.ts#L27)). Windows already inherits user-only ACL on `%USERPROFILE%`; comment in source documents this.

### H6. Argv-supplied secrets visible to other processes
- **Where**: [src/scan.ts](src/scan.ts) cicd token flags.
- **What was wrong**: `--github-token`/`--gitlab-token` on argv land in `/proc/<pid>/cmdline`, `ps`, Windows Task Manager, parent shell history, etc. We can't unleak it, but the user must be told.
- **Fix**: `warnArgvSecret` warns once on first use ([src/scan.ts:265-275](src/scan.ts#L265-L275)).

### H7. Insufficient bearer-shape validation on CI/CD tokens
- **Where**: [src/scan.ts:122-123](src/scan.ts#L122-L123) (old).
- **Fix**: `validateBearerLike` ([src/safety.ts:69-75](src/safety.ts#L69-L75)) rejects empty, oversized, or control-char-bearing tokens before they're forwarded.

### H8. Indefinite hang on outbound fetch (resource exhaustion / hang)
- **Where**: every `fetch` in `api.ts` and `local-scan.ts`.
- **Fix**: 60 s default timeout on `authedFetch`, 15 s on local probe POSTs, 5 s on discovery OPTIONS, 10 min on artifact upload. See [src/api.ts:84-93](src/api.ts#L84-L93), [src/local-scan.ts:64-71](src/local-scan.ts#L64-L71), [src/local-scan.ts:113](src/local-scan.ts#L113).

---

## MEDIUM — fixed

### M1. Terminal injection via control characters in user-supplied target
- **Where**: every `r.header(target, …)` call site.
- **What was wrong**: a target like `https://x\r\n[INFO] all clean` would forge log lines or move the cursor with ANSI escapes.
- **Fix**: `sanitizeForDisplay` ([src/safety.ts:111-115](src/safety.ts#L111-L115)) strips control chars before display. Applied at [src/scan.ts:104-106](src/scan.ts#L104-L106), [src/atlas.ts:25-29](src/atlas.ts#L25-L29), [src/ci.ts:37-43](src/ci.ts#L37-L43), [src/local-scan.ts:46](src/local-scan.ts#L46).

### M2. ANSI/control injection via server-supplied strings
- **Where**: agents.ts, engines.ts, playbooks.ts, scan/atlas finding rendering, compliance download URL.
- **What was wrong**: a compromised or hostile backend could embed escape sequences in any field rendered to the terminal.
- **Fix**: every server-string render goes through `sanitizeForDisplay`. See [src/agents.ts:30-52](src/agents.ts#L30-L52), [src/engines.ts:25-37](src/engines.ts#L25-L37), [src/playbooks.ts:25-46](src/playbooks.ts#L25-L46), [src/scan.ts:159-170](src/scan.ts#L159-L170), [src/atlas.ts:39-43](src/atlas.ts#L39-L43), [src/compliance.ts:46-56](src/compliance.ts#L46-L56).

### M3. Server-supplied compliance download URL not validated
- **Where**: [src/compliance.ts](src/compliance.ts).
- **Fix**: validate via `assertSafeOpenUrl` (http(s) only) before printing.

### M4. Server-supplied replay URL not validated
- **Where**: [src/scan.ts](src/scan.ts) `emitSummary`.
- **Fix**: re-parse and require `http`/`https` scheme; drop the URL silently if it's anything else. See [src/scan.ts:189-202](src/scan.ts#L189-L202).

### M5. API key echoed to terminal during `login`
- **Where**: [src/auth.ts:14](src/auth.ts#L14) `readline.question` with default echo.
- **Fix**: new `silentPrompt` toggles raw mode + echo-off on a TTY ([src/auth.ts:48-91](src/auth.ts#L48-L91)). On a non-TTY (CI piping stdin) it falls back to readline rather than blocking.

### M6. Top-level error handler leaked stack traces with potentially sensitive paths/tokens
- **Where**: [src/index.ts](src/index.ts) `main().catch(...)`.
- **Fix**: stack only printed when `BREKTRA_DEBUG=1`; otherwise just the (already-redacted) message ([src/index.ts:118-128](src/index.ts#L118-L128)).

### M7. Target shape validation per surface
- **Where**: [src/scan.ts](src/scan.ts).
- **What was wrong**: `host`/`cloud`/`cicd` targets were freeform.
- **Fix**: per-surface validator at [src/scan.ts:43-87](src/scan.ts#L43-L87) — strict charsets for cloud/cicd/host, `URL.parse` for web/ai, length cap 2048, control-char rejection.

### M8. `--jenkins-url` not validated
- **Where**: [src/scan.ts](src/scan.ts) `collectSurfaceOptions`.
- **Fix**: parsed as URL and required to be http(s) ([src/scan.ts:151-156](src/scan.ts#L151-L156)).

### M9. `atlas` slug not validated
- **Where**: [src/atlas.ts:14](src/atlas.ts#L14).
- **Fix**: `^[A-Za-z0-9_\-]{1,128}$` ([src/atlas.ts:13-22](src/atlas.ts#L13-L22)).

---

## LOW / informational — not changed (rationale)

- **`localhost:3000` example in README**: intentional and clearly documented.
- **`node_modules` audit**: `npm audit --omit=dev` reports **0 vulnerabilities** as of this commit. `picocolors@^1.1.0` and `open@^10.1.0` are the only runtime deps.
- **Author email in commit history**: `saimuthineni101@gmail.com` is the user's chosen public commit identity (matches v0.1.x). Out of scope to change without user direction.
- **Logs to stdout/stderr**: structured PII (the *configured* target URL) is intentionally shown to the operator running the CLI — they supplied it. Not redacted.

## Verification

- `tsc --noEmit` clean — see `npm run build` output in CI.
- `npm audit --omit=dev` → 0 vulnerabilities.
- No test suite exists in this repo (pre-existing); not introduced as part of this audit.

## Counts (pass 1)

- CRITICAL fixed: **4**
- HIGH fixed: **8**
- MEDIUM fixed: **9**
- Total: **21**

---

# Pass 2 — deeper sweep

Additional findings discovered on a second read of the codebase. All fixed in the same commit family.

## CRITICAL — pass 2

### P-C5. Prototype pollution via `~/.brektra/config.json`
- **Where**: [src/config.ts](src/config.ts) `loadConfig` previously did `JSON.parse(raw)` directly.
- **What was wrong**: a tampered config of the form `{"__proto__":{"api_url":"https://evil.com"}}` would pollute `Object.prototype.api_url`. Every later access to `cfg.api_url` (across the whole process) would read the attacker value, redirecting bearer tokens.
- **Fix**: [src/safety.ts](src/safety.ts) `parseConfigSafely` parses with a JSON reviver that drops `__proto__`, `constructor`, `prototype` keys and then copies only the typed fields `api_key`/`api_url` onto a fresh plain object. Wired in [src/config.ts loadConfig](src/config.ts).

### P-C6. Phishing via custom `BREKTRA_API_URL` / `cfg.api_url`
- **Where**: [src/auth.ts:10-13](src/auth.ts) old `login()` path.
- **What was wrong**: `login()` used `apiBase(cfg)` to build the URL it auto-opens in the browser. `apiBase` allows any HTTPS host, so `BREKTRA_API_URL=https://evil.com` would direct the user's browser to evil.com's fake api-keys page; the user would paste a real `bk_*` into it.
- **Fix**: new `isCustomApiBase()` ([src/config.ts:69-82](src/config.ts)) detects override; [src/auth.ts:17-24](src/auth.ts) refuses to auto-open the browser when the base is overridden, prints the URL for explicit user inspection.

### P-C7. `validateTarget` mobile regex was unanchored
- **Where**: [src/scan.ts](src/scan.ts) old `/[A-Za-z0-9._\-/\\: ]{1,1024}/`.
- **What was wrong**: `RegExp.test` of an unanchored class returns true if *any* substring matches. The mobile branch effectively accepted every string (only the global control-char check at the top of the function caught anything). Adversarial paths could be silently accepted for display/forward.
- **Fix**: anchored to `^…$` ([src/scan.ts](src/scan.ts) mobile branch).

## HIGH — pass 2

### P-H9. Server-supplied IDs embedded in fetch URLs without `encodeURIComponent`
- **Where**: [src/api.ts](src/api.ts) `getCiScan(id)`, `getPlaybook(id)`, `getComplianceExport(id)`.
- **What was wrong**: `id` returned by the server was concatenated into the URL: `\`/api/v1/scans/ci/${id}\``. A compromised backend could return `id: "../admin/secrets"` and the CLI would happily reissue the bearer at a *different* authenticated endpoint of the same origin.
- **Fix**: new `safeServerId()` ([src/safety.ts](src/safety.ts)) shape-checks `^[A-Za-z0-9_\-]{1,128}$`; URLs use `encodeURIComponent` after the shape check. Same applies to the `artifact_id` returned by `uploadMobileArtifact` before it's embedded in the resolved target ([src/scan.ts](src/scan.ts) mobile dispatch).

### P-H10. `saveConfig` did not reset mode on existing files
- **Where**: [src/config.ts saveConfig](src/config.ts).
- **What was wrong**: Node's `fs.writeFile({mode})` only honors mode on *creation*. If `~/.brektra/config.json` existed with permissive bits (e.g. left over from an earlier process run), `saveConfig` overwrote contents but kept the loose mode — bearer key world-readable.
- **Fix**: write to a randomly-named tempfile via `fs.open(O_CREAT|O_EXCL|O_WRONLY, 0o600)`, `chmod 0o600` post-open, then atomic `rename` over the target ([src/config.ts saveConfig](src/config.ts)). Also closes a partial-write race on crash mid-write.

### P-H11. TOCTOU between `lstat` and `readFile` in `uploadMobileArtifact`
- **Where**: [src/api.ts uploadMobileArtifact](src/api.ts).
- **What was wrong**: a same-machine attacker could swap the file between the `lstat` (which checks for symlink) and the `readFile` call, causing a sensitive file to be read and uploaded.
- **Fix**: open with `O_RDONLY | O_NOFOLLOW` (POSIX), then stat the file *descriptor* and read from the same descriptor — every check operates on the same inode ([src/api.ts uploadMobileArtifact](src/api.ts)).

## MEDIUM — pass 2

### P-M10. Cloud/CI flag values not length/control-char checked
- **Where**: `--aws-profile`, `--gcp-creds`, `--azure-sub`, `--k8s-config` in [src/scan.ts](src/scan.ts).
- **Fix**: `validateOpaqueArg` ([src/safety.ts](src/safety.ts)) enforces a max length and rejects `\x00–\x1f\x7f`. Lengths chosen per arg.

### P-M11. URL `userinfo` (user:pass@host) leaked through targets
- **Where**: every `--target` / `scan <surface> <target>` / `ci scan <target>` path.
- **What was wrong**: `https://user:pass@host` is preserved by the `URL` parser; the userinfo would be sent in the JSON body to the backend, printed to the console, and (via `open`) handed to the OS shell.
- **Fix**: refuse userinfo at validation time in [src/scan.ts validateTarget](src/scan.ts), [src/atlas.ts](src/atlas.ts), [src/ci.ts](src/ci.ts); also defensive `stripUserInfo()` ([src/safety.ts](src/safety.ts)) before display/forward.

### P-M12. Local-scan response excerpt could carry ANSI escapes
- **Where**: [src/local-scan.ts findingProof excerpt](src/local-scan.ts).
- **What was wrong**: `bodyText.slice(0, 200)` from a hostile local app was rendered raw. The renderer in [src/render.ts findingProof](src/render.ts) trusts callers, so the excerpt could forge log lines.
- **Fix**: `sanitizeForDisplay` on the excerpt before passing to the renderer.

### P-M13. Mobile upload `r.info` line printed raw target
- **Where**: [src/scan.ts dispatch mobile branch](src/scan.ts).
- **Fix**: target stripped of userinfo and run through `sanitizeForDisplay` before display.

### P-M14. Top-level error handler did not redact bearer-shaped tokens
- **Where**: [src/index.ts main().catch](src/index.ts).
- **What was wrong**: `redactErrorBody` only ran inside `jsonOrThrow`. An error thrown elsewhere (e.g. a custom string with a bearer token) would bypass redaction.
- **Fix**: top-level handler now runs `redactErrorBody` on `err.message` and `err.stack`.

### P-M15. `silentPrompt` had no input length cap
- **Where**: [src/auth.ts silentPrompt](src/auth.ts).
- **Fix**: cap at 512 chars; further input is dropped with a graceful finish.

### P-M16. `saveConfig` not atomic
- **Where**: [src/config.ts saveConfig](src/config.ts) — same fix path as P-H10. Tempfile + atomic rename eliminates partial-write corruption.

### P-M17. `runAtlas` polling had no timeout and never bailed on persistent error
- **Where**: [src/atlas.ts](src/atlas.ts).
- **Fix**: 15-minute hard timeout on the poll loop, matching the scan dispatcher.

### P-M18. `runAtlas` printed unvalidated server `replay_url`
- **Where**: [src/atlas.ts r.summary](src/atlas.ts).
- **Fix**: `URL` parse + http(s) scheme requirement, sanitize for display, drop silently on failure (mirrors `emitSummary` in [src/scan.ts](src/scan.ts)).

## Counts (pass 2)

- CRITICAL fixed: **3** (P-C5, P-C6, P-C7)
- HIGH fixed: **3** (P-H9, P-H10, P-H11)
- MEDIUM fixed: **9** (P-M10 – P-M18)
- Total pass 2: **15**

## Combined counts

- CRITICAL: **7**
- HIGH: **11**
- MEDIUM: **18**
- Total: **36**

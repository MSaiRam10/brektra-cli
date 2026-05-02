import pc from "picocolors";

// Centralised safety helpers used across the CLI. Keep this file
// dependency-free so it can be imported from anywhere without cycles.

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);
const MAX_ERROR_BODY = 500;
const MAX_API_KEY_LEN = 256;
// 500MB cap on mobile artifact uploads. Enough for realistic APK/IPA, small
// enough that a typo (--mobile /var/log) can't OOM the box.
export const MAX_ARTIFACT_BYTES = 500 * 1024 * 1024;
const ARTIFACT_EXTS = [".apk", ".ipa"];

export function assertSafeApiBase(rawUrl: string): URL {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new Error(`invalid api base url: ${redact(rawUrl)}`);
  }
  if (!ALLOWED_SCHEMES.has(u.protocol)) {
    // refuse javascript:, file:, data:, ftp:, and anything else the OS
    // shell handler might launch in `open()` or fetch in non-obvious ways
    throw new Error(`refusing api base with scheme ${u.protocol}`);
  }
  if (u.protocol === "http:" && !isLoopback(u.hostname)) {
    throw new Error(
      `refusing to send credentials over http:// to ${u.hostname} — use https:// or a localhost dev base`,
    );
  }
  return u;
}

export function isLoopback(host: string): boolean {
  if (!host) return false;
  const h = host.toLowerCase();
  return (
    h === "localhost" ||
    h === "127.0.0.1" ||
    h === "[::1]" ||
    h === "::1" ||
    h.endsWith(".localhost")
  );
}

export function assertSafeOpenUrl(rawUrl: string): string {
  // Used before handing a URL to `open()`. open() invokes the OS shell
  // handler so a javascript:, file:, or custom-scheme URL would be
  // executed by whatever app is registered for that scheme.
  const u = new URL(rawUrl);
  if (!ALLOWED_SCHEMES.has(u.protocol)) {
    throw new Error(`refusing to open ${u.protocol} url`);
  }
  return u.toString();
}

export function redactErrorBody(body: string): string {
  // strip authorization headers a server may echo back, then truncate
  const stripped = body
    .replace(/(?:authorization|x-api-key)\s*:\s*[^\s]+/gi, "[redacted-auth-header]")
    .replace(/Bearer\s+[A-Za-z0-9._\-]+/gi, "Bearer [redacted]")
    .replace(/bk_[A-Za-z0-9._\-]+/g, "bk_[redacted]");
  return stripped.length > MAX_ERROR_BODY
    ? stripped.slice(0, MAX_ERROR_BODY) + "...[truncated]"
    : stripped;
}

export function redact(s: string): string {
  if (!s) return s;
  if (s.length > 80) return s.slice(0, 16) + "...[redacted]";
  return s;
}

export function validateApiKey(raw: string): string {
  // we never log the key. If validation fails, error messages must NOT
  // include the raw value — only its length / shape.
  if (!raw) throw new Error("empty api key");
  if (raw.length > MAX_API_KEY_LEN) {
    throw new Error(`api key too long (${raw.length} chars; max ${MAX_API_KEY_LEN})`);
  }
  if (!/^bk_[A-Za-z0-9_\-]{16,}$/.test(raw)) {
    // shape check: prefix + at least 16 chars of urlsafe alphabet.
    // length and charset are reported, never the key itself.
    throw new Error(
      `api key does not match expected shape (got ${raw.length} chars; keys start with bk_ and are url-safe)`,
    );
  }
  return raw;
}

export function validateBearerLike(name: string, raw: string): string {
  // CI/CD token flags. Reject empty, control chars, or absurd lengths.
  if (!raw) throw new Error(`${name} is empty`);
  if (raw.length > 4096) throw new Error(`${name} too long`);
  if (/[\x00-\x1f\x7f\s]/.test(raw)) throw new Error(`${name} contains whitespace or control chars`);
  return raw;
}

export function validateArtifactPath(p: string): string {
  // Used by the mobile-artifact uploader. We *intentionally* don't
  // resolve to a sandboxed root: the user is the actor, and the file is
  // their property. We do enforce extension to avoid accidental upload
  // of /etc/shadow or similar when the user types the wrong arg.
  const lower = p.toLowerCase();
  if (!ARTIFACT_EXTS.some((e) => lower.endsWith(e))) {
    throw new Error(`mobile artifact must end in ${ARTIFACT_EXTS.join(" or ")} (got ${p})`);
  }
  return p;
}

export function sanitizeForDisplay(s: string): string {
  // Strip control characters before echoing back to the terminal so a
  // crafted target like "https://x\r\n[INFO] All clear" cannot forge log
  // lines (terminal-injection / log-forging).
  return s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "?");
}

export function stripUserInfo(rawUrl: string): string {
  // SECURITY: drop any userinfo (user:pass@) from a URL before display
  // or forward — embedded creds otherwise leak to console, to logs, to
  // the backend JSON body, and to the open() OS shell handler.
  try {
    const u = new URL(rawUrl);
    if (u.username || u.password) {
      u.username = "";
      u.password = "";
      return u.toString();
    }
    return rawUrl;
  } catch {
    return rawUrl;
  }
}

export function validateOpaqueArg(name: string, raw: string, max = 1024): string {
  // For cloud/cicd argument values that we forward verbatim: enforce
  // length and reject control characters (newline-injection / log-forge
  // on the backend, terminal injection on local display).
  if (!raw) throw new Error(`${name} is empty`);
  if (raw.length > max) throw new Error(`${name} too long (>${max})`);
  if (/[\x00-\x1f\x7f]/.test(raw)) {
    throw new Error(`${name} contains control characters`);
  }
  return raw;
}

export function safeServerId(name: string, raw: unknown): string {
  // SECURITY: ids returned by the backend are then embedded in
  // /api/v1/.../<id> URLs. A hostile/compromised backend that returns
  // `../admin/secrets` would otherwise cause us to reissue the bearer
  // against a different authenticated endpoint of the same origin.
  // Refuse anything outside [A-Za-z0-9_-]{1,128}.
  if (typeof raw !== "string") throw new Error(`${name} from server is not a string`);
  if (!/^[A-Za-z0-9_\-]{1,128}$/.test(raw)) {
    throw new Error(`${name} from server has invalid shape`);
  }
  return raw;
}

// SECURITY: parse JSON from disk while stripping prototype-pollution
// vectors (__proto__, constructor, prototype). Returns a plain object
// with only the expected scalar fields (api_key, api_url) honored.
export function parseConfigSafely(raw: string): { api_key?: string; api_url?: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw, (key, value) => {
      // reviver runs for every key. Drop the dangerous ones.
      if (key === "__proto__" || key === "constructor" || key === "prototype") return undefined;
      return value;
    });
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const obj = parsed as Record<string, unknown>;
  const out: { api_key?: string; api_url?: string } = {};
  if (typeof obj.api_key === "string") out.api_key = obj.api_key;
  if (typeof obj.api_url === "string") out.api_url = obj.api_url;
  return out;
}

// re-export pc to encourage callers to use sanitizeForDisplay+colors together
export { pc };

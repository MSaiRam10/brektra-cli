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

// re-export pc to encourage callers to use sanitizeForDisplay+colors together
export { pc };

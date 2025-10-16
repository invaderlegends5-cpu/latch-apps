// src/auth/utils/normalize.util.ts

/**
 * Normalize IPv6-mapped IPv4 addresses to pure IPv4
 * Example: "::ffff:192.168.1.1" → "192.168.1.1"
 */
export function normalizeIp(ip: string | undefined | null): string | null {
  if (!ip) return null;

  // Handle IPv6-mapped IPv4 (common when behind proxies)
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7); // strip "::ffff:"
  }

  // Optional: handle other formats (e.g., [::1] for IPv6 localhost)
  // But generally, leave IPv6 as-is

  return ip;
}

/**
 * Truncate user-agent to prevent DB bloat
 * Max length: 200 chars (adjustable)
 */
export function normalizeUserAgent(
  ua: string | undefined | null,
): string | null {
  if (!ua) return null;

  // Strip leading/trailing whitespace
  const trimmed = ua.trim();

  // Truncate if too long
  return trimmed.length > 200 ? trimmed.substring(0, 200) : trimmed;
}

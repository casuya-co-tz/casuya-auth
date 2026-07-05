import { randomBytes, createHash } from 'crypto';

export function generateRandomString(length: number = 32): string {
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}

export function generateSecureToken(): string {
  return randomBytes(32).toString('hex');
}

export function hashString(input: string, algorithm: string = 'sha256'): string {
  return createHash(algorithm).update(input).digest('hex');
}

export function generateSessionId(): string {
  return randomBytes(16).toString('hex');
}

export function generateDeviceFingerprint(components: Record<string, string>): string {
  const sorted = Object.entries(components)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('|');
  return hashString(sorted);
}

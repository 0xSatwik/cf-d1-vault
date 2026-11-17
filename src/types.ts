import { z } from 'zod';

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  PUBLIC_ORIGIN: string;
  ENABLE_GITHUB_WRITES: string;
  MASTER_SHA256: string;
  HUMAN_SHA256?: string;
  VAULT_DEK_V1: string;
  VAULT_DEK_V2?: string;
}
export class VaultError extends Error {
  constructor(public readonly code: string, public readonly status = 403) { super(code); }
}
export const identifier = z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
export const requestId = z.string().uuid();
// Key names are human names: letters, digits, spaces, _ and -, 1–80 chars,
// must start with a letter or digit (no leading/trailing/double space).
export const labelName = z.string().min(1).max(80)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9_-]| [A-Za-z0-9_-])*$/);
// A service is a short slug: github, cloudflare, openrouter, ... or a custom slug.
export const serviceName = identifier;
// The API base a key belongs to, e.g. https://api.github.com. HTTPS only, no spaces.
export const website = z.string().regex(/^https:\/\/\S{1,2048}$/);
export function normalizeWebsite(value: string): string {
  return value.replace(/\/+$/, '');
}
// Validators for API-call parameters Pi mentions in chat (repo, branch, file).
// These are call arguments, not stored policy: the vault stores no repo/branch/path.
export const repoName = z.string().regex(/^[a-z0-9][a-z0-9_.-]{0,99}\/[a-z0-9][a-z0-9_.-]{0,99}$/);
export const branchName = z.string().min(1).max(200).refine(s =>
  !/[\s\\%?#\x00-\x1f]/.test(s) && !s.includes('..') && !s.startsWith('/') && !s.endsWith('/'));
export const filePath = z.string().min(1).max(500).refine(s =>
  s.split('/').every(p => p.length > 0 && p !== '.' && p !== '..') && !/[\\%?#\x00-\x1f]/.test(s));
export interface KeyRow {
  id: string; service: string; label: string; website: string; ciphertext: string; nonce: string;
  enc_version: number; enabled: number;
}
export interface AgentRow { id: string; token_hash: string; revoked_at: number | null }
export interface GrantRow {
  id: string; agent_id: string; key_id: string; service: string;
  opened_at: number; expires_at: number; revoked_at: number | null; admin_request_id: string;
}
export function now(): number { return Math.floor(Date.now() / 1000); }
export function json(data: unknown, status = 200): Response {
  return Response.json(data, { status, headers: { 'Cache-Control': 'no-store' } });
}
export async function readBounded(request: Request | Response, max: number): Promise<string> {
  if (Number(request.headers.get('content-length')) > max) throw new VaultError('too_large', 413);
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > max) { await reader.cancel(); throw new VaultError('too_large', 413); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
}

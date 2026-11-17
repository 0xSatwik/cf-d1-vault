import { z } from 'zod';
import { authorize } from './auth.js';
import { sampledRead } from './audit.js';
import { decrypt, redact } from './crypto.js';
import { type Env, identifier, labelName, readBounded, serviceName, VaultError } from './types.js';

// Generic proxy for any stored service: the Worker calls the key's website with the
// decrypted key, the agent never sees the key. The repo/path/endpoint is said in chat, not stored.
export const serviceRequestSchema = z.object({
  key_label: labelName,
  service: serviceName,
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
  path: z.string().min(1).max(2048).regex(/^\/[^\s\\]*$/).refine(s => !s.includes('..')),
  body: z.string().max(32768).optional()
}).strict();

function redactBody(value: string, secrets: string[]): string {
  const clean = redact(value, secrets);
  return clean.length > 32768 ? clean.slice(0, 32768) : clean;
}

export async function serviceRequest(env: Env, tokenHash: string, raw: unknown): Promise<unknown> {
  const args = serviceRequestSchema.parse(raw);
  const admission = await authorize(env, tokenHash, args.service, args.key_label);
  const token = await decrypt(env, admission.key);
  // Fresh primary read immediately before the network dispatch; never retry automatically.
  const fresh = await authorize(env, tokenHash, args.service, args.key_label);
  if (fresh.key.id !== admission.key.id || fresh.key.ciphertext !== admission.key.ciphertext ||
      fresh.key.nonce !== admission.key.nonce || fresh.key.enc_version !== admission.key.enc_version)
    throw new VaultError('unlock_required');
  const base = admission.key.website.replace(/\/+$/, '');
  const url = new URL(base + args.path);
  const secrets = [token, env.VAULT_DEK_V1, env.VAULT_DEK_V2 ?? '', env.MASTER_SHA256, env.HUMAN_SHA256 ?? ''];
  const response = await fetch(url, {
    method: args.method, redirect: 'manual',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json',
      'User-Agent': 'cf-d1-vault/1.0',
      ...(args.body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    // 25s, not longer: the Workers platform caps a request at ~30s wall-clock,
    // so a longer timeout would be killed mid-flight instead of returning cleanly.
    body: args.body, signal: AbortSignal.timeout(25000)
  });
  if (!response.ok) {
    await response.body?.cancel();
    if (response.status === 429 || response.status === 403) {
      const retry = Number(response.headers.get('retry-after'));
      throw new VaultError(Number.isFinite(retry) && retry > 0
        ? `upstream_refused_retry_after_${Math.min(Math.ceil(retry), 86400)}` : 'upstream_refused', 429);
    }
    throw new VaultError('upstream_failed', 502);
  }
  const text = await readBounded(response, 131072);
  await sampledRead(env, { agent_id: admission.agent.id, key_id: admission.key.id, grant_id: admission.grant.id,
    operation: 'service_request', status: 'succeeded', request_id: crypto.randomUUID() });
  const clean = redactBody(text, secrets);
  try {
    return { status: response.status, body: JSON.parse(clean) };
  } catch {
    return { status: response.status, body: clean };
  }
}

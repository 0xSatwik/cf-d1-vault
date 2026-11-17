import { type Env, type KeyRow, VaultError } from './types.js';

const encoder = new TextEncoder();
export function base64(bytes: Uint8Array): string {
  let result = '';
  for (const byte of bytes) result += String.fromCharCode(byte);
  return btoa(result);
}
export function unbase64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
export function equalHash(a: string, b: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b)) return false;
  let difference = 0;
  for (let i = 0; i < 64; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
export async function verifyMaster(secret: string, verifier: string): Promise<boolean> {
  return equalHash(await sha256(secret), verifier);
}
type Identity = Pick<KeyRow, 'id' | 'service' | 'label' | 'enc_version'>;
function aad(row: Identity): Uint8Array {
  return encoder.encode(JSON.stringify(['cf-vault', row.id, row.service, row.label, row.enc_version]));
}
async function dek(env: Env, version: number): Promise<CryptoKey> {
  const encoded = version === 1 ? env.VAULT_DEK_V1 : version === 2 ? env.VAULT_DEK_V2 : undefined;
  if (!encoded) throw new VaultError('encryption_unavailable', 503);
  const bytes = unbase64(encoded);
  if (bytes.length !== 32) throw new VaultError('encryption_unavailable', 503);
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function encrypt(env: Env, row: Identity, plaintext: string): Promise<{ciphertext: string; nonce: string}> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad(row), tagLength: 128 },
    await dek(env, row.enc_version), encoder.encode(plaintext)
  );
  // WebCrypto appends the 128-bit tag to ciphertext.
  return { ciphertext: base64(new Uint8Array(ciphertext)), nonce: base64(nonce) };
}
export async function decrypt(env: Env, row: KeyRow): Promise<string> {
  const nonce = unbase64(row.nonce);
  if (nonce.length !== 12) throw new VaultError('encryption_unavailable', 503);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad(row), tagLength: 128 },
    await dek(env, row.enc_version), unbase64(row.ciphertext)
  );
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(plaintext);
}
export function redact(value: string, secrets: string[]): string {
  // Mask complete token patterns before short configured secrets can split them.
  let clean = value.replace(/(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})/g, '[REDACTED]');
  // Upstream-issued temporary tokens are credentials too, even though they are
  // not the stored key — e.g. GitHub puts a ?token= on file download URLs,
  // and OAuth-style responses carry "access_token" / "token" JSON fields.
  clean = clean.replace(/([?&](?:token|access_token)=)[^&\s"']+/g, '$1[REDACTED]');
  clean = clean.replace(/("(?:access_token|token)"\s*:\s*")[^"]*(")/g, '$1[REDACTED]$2');
  for (const secret of [...secrets].sort((a, b) => b.length - a.length))
    if (secret) clean = clean.split(secret).join('[REDACTED]');
  return clean;
}

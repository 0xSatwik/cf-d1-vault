import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt, sha256, verifyMaster, base64, redact } from '../src/crypto.js';
import { permits, subset, authorize } from '../src/auth.js';
import { safePath } from '../src/github.js';
import { type Env, type KeyRow, policySchema } from '../src/types.js';

const policy = policySchema.parse({ allowed_tools: ['github_read_file'],
  resources: [{ repository: 'example/project', branches: ['main'], paths: ['README.md'] }] });
test('GCM binds all identity fields, detects tampering, and uses fresh nonces', async () => {
  const env = { VAULT_DEK_V1: base64(crypto.getRandomValues(new Uint8Array(32))),
    VAULT_DEK_V2: base64(crypto.getRandomValues(new Uint8Array(32))) } as Env;
  const row = { id: 'id', service: 'github', label: 'work', enc_version: 1 } as KeyRow;
  Object.assign(row, await encrypt(env, row, 'synthetic-canary'));
  assert.equal(await decrypt(env, row), 'synthetic-canary');
  assert.notEqual((await encrypt(env, row, 'synthetic-canary')).nonce, row.nonce);
  for (const change of [{ id: 'other' }, { service: 'other' }, { label: 'personal' }, { enc_version: 2 },
    { ciphertext: row.ciphertext.slice(0, -4) + 'AAAA' }])
    await assert.rejects(decrypt(env, { ...row, ...change }));
  const rotated = { ...row, enc_version: 2 };
  Object.assign(rotated, await encrypt(env, rotated, await decrypt(env, row)));
  assert.equal(await decrypt(env, rotated), 'synthetic-canary');
});
test('master verifier and redaction', async () => {
  assert.equal(await verifyMaster('synthetic', await sha256('synthetic')), true);
  assert.equal(await verifyMaster('wrong', await sha256('synthetic')), false);
  assert.equal(redact('canary abc ghp_abcdefghijklmnopqrst', ['abc']), 'canary [REDACTED] [REDACTED]');
});
test('exact policy intersection prevents branch, path, repository and operation widening', () => {
  assert(permits(policy, { tool: 'github_read_file', repository: 'example/project', branch: 'main', path: 'README.md' }));
  for (const change of [{ branch: 'dev' }, { path: 'README.md/../secret' }, { repository: 'example/other' },
    { tool: 'github_create_issue' as const }])
    assert(!permits(policy, { tool: 'github_read_file', repository: 'example/project', branch: 'main', path: 'README.md', ...change }));
  assert(subset(policy, policy));
  assert(!subset({ ...policy, allowed_tools: ['github_create_issue'] }, policy));
  for (const path of ['.env', 'a/.git/config', 'private.key', 'secrets.json']) assert(!safePath(path));
});
test('authorization fails closed on D1 errors and missing grants, using primary binding', async () => {
  let sql = '';
  const env = { DB: { prepare(query: string) {
    sql = query;
    return { bind() { return this; }, async all() { return { results: [] }; } };
  } } } as unknown as Env;
  await assert.rejects(authorize(env, 'hash', 'personal', { tool: 'github_list_issues', repository: 'example/project' }), /unlock_required/);
  assert(sql.includes('g.expires_at>?'));
  assert(sql.includes('g.revoked_at IS NULL'));
  assert(sql.includes('k.label=?'));
  const failed = { DB: { prepare() { throw Error('quota'); } } } as unknown as Env;
  await assert.rejects(authorize(failed, 'hash', 'work', { tool: 'github_list_issues', repository: 'example/project' }));
});

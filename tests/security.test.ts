import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt, sha256, verifyMaster, base64, redact } from '../src/crypto.js';
import { authorize } from '../src/auth.js';
import { readFileSchema, safePath } from '../src/github.js';
import { agentSchema, keySchema } from '../src/admin.js';
import { type Env, type KeyRow, labelName, normalizeWebsite, repoName, website } from '../src/types.js';

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
test('repo names accept mixed case (GitHub names are case-insensitive)', () => {
  assert.equal(repoName.safeParse('0xSatwik/cf-d1-vault').success, true);
  assert.equal(repoName.safeParse('octocat/Hello-World').success, true);
  assert.equal(repoName.safeParse('octocat/hello-world').success, true);
  assert.equal(repoName.safeParse('octocat').success, false);
  assert.equal(repoName.safeParse('octocat/hello world').success, false);
});
test('key enable action parses without website or secret', () => {
  const ok = keySchema.safeParse({ action: 'enable', service: 'github',
    label: 'old key', request_id: '22222222-2222-4222-8222-222222222222' });
  assert.equal(ok.success, true);
  assert.equal(keySchema.safeParse({ action: 'enable', service: 'github',
    label: 'old key', website: 'https://api.github.com',
    request_id: '22222222-2222-4222-8222-222222222222' }).success, false);
});
test('redaction masks upstream temporary tokens in download URLs', () => {
  const url = 'https://raw.githubusercontent.com/o/r/main/hello.txt?token=ABC123xyz';
  const clean = redact(url, []);
  assert.equal(clean, 'https://raw.githubusercontent.com/o/r/main/hello.txt?token=[REDACTED]');
  assert.equal(redact('{"a":1,"access_token":"sekret"}', []), '{"a":1,"access_token":"[REDACTED]"}');
  assert.equal(redact('{"token":"ghs_abc123"}', []), '{"token":"[REDACTED]"}');
  assert.equal(redact('x?foo=bar&token=t1&baz=2', []), 'x?foo=bar&token=[REDACTED]&baz=2');
});
test('agent add parses only a 64-hex token hash, never a raw token', () => {
  const hash = 'a'.repeat(64);
  const ok = agentSchema.safeParse({ id: 'pi', token_hash: hash, request_id: '33333333-3333-4333-8333-333333333333' });
  assert.equal(ok.success, true);
  assert.equal(agentSchema.safeParse({ id: 'pi', token_hash: 'raw-token-value', request_id: '33333333-3333-4333-8333-333333333333' }).success, false);
  assert.equal(agentSchema.safeParse({ id: 'pi', token_hash: hash }).success, false);
});
test('github read file: branch is optional (default branch when omitted)', () => {
  const noBranch = readFileSchema.safeParse({ key_label: 'my key', repository: '0xSatwik/cf-d1-vault', path: 'README.md' });
  assert.equal(noBranch.success, true);
  const withBranch = readFileSchema.safeParse({ key_label: 'my key', repository: '0xSatwik/cf-d1-vault', branch: 'main', path: 'README.md' });
  assert.equal(withBranch.success, true);
  assert.equal(withBranch.data.branch, 'main');
});
test('key delete action parses without website or secret', () => {
  const ok = keySchema.safeParse({ action: 'delete', service: 'github',
    label: 'old key', request_id: '11111111-1111-4111-8111-111111111111' });
  assert.equal(ok.success, true);
  assert.equal(keySchema.safeParse({ action: 'delete', service: 'github',
    label: 'old key', website: 'https://api.github.com',
    request_id: '11111111-1111-4111-8111-111111111111' }).success, false);
  assert.equal(keySchema.safeParse({ action: 'delete', service: 'github',
    label: 'old key' }).success, false);
});
test('key names may contain spaces, but no leading/trailing/double space', () => {
  assert.equal(labelName.safeParse('GitHub satwik work token').success, true);
  assert.equal(labelName.safeParse('work').success, true);
  assert.equal(labelName.safeParse('a').success, true);
  assert.equal(labelName.safeParse('work-1_2').success, true);
  assert.equal(labelName.safeParse(' work').success, false);
  assert.equal(labelName.safeParse('work ').success, false);
  assert.equal(labelName.safeParse('work  token').success, false);
  assert.equal(labelName.safeParse('').success, false);
  assert.equal(labelName.safeParse('x'.repeat(81)).success, false);
  assert.equal(labelName.safeParse('work/token').success, false);
});
test('website must be https and is normalized', () => {
  assert.equal(website.safeParse('https://api.github.com').success, true);
  assert.equal(website.safeParse('https://openrouter.ai/api/v1').success, true);
  assert.equal(website.safeParse('http://api.github.com').success, false);
  assert.equal(website.safeParse('api.github.com').success, false);
  assert.equal(website.safeParse('https://api.github.com/path with space').success, false);
  assert.equal(normalizeWebsite('https://api.github.com///'), 'https://api.github.com');
  assert.equal(normalizeWebsite('https://api.github.com'), 'https://api.github.com');
});
test('sensitive paths stay blocked', () => {
  for (const path of ['.env', 'a/.git/config', 'private.key', 'secrets.json',
    'id_rsa', 'keys/id_ed25519', 'id_rsa.pub', 'id_dsa', 'id_ecdsa', 'key.ppk']) assert(!safePath(path));
  assert(safePath('README.md'));
  assert(safePath('docs/guide.md'));
});
test('authorization is the grant alone: agent + service + key label, unexpired', async () => {
  const grantRow = {
    id: 'key-id', service: 'cloudflare', label: 'main', website: 'https://api.cloudflare.com',
    ciphertext: 'x', nonce: 'y', enc_version: 1, enabled: 1,
    agent_id: 'pi', token_hash: 'hash', agent_revoked: null,
    grant_id: 'grant-id', opened_at: 1000, expires_at: 8200,
    grant_revoked: null, admin_request_id: 'req-id'
  };
  const env = { DB: { prepare() {
    let args: unknown[] = [];
    return { bind(...values: unknown[]) { args = values; return this; },
      async all() { return { results: args[1] === 'cloudflare' && args[2] === 'main' ? [grantRow] : [] }; } };
  } } } as unknown as Env;
  const admitted = await authorize(env, 'hash', 'cloudflare', 'main');
  assert.equal(admitted.key.id, 'key-id');
  assert.equal(admitted.grant.id, 'grant-id');
  assert.equal(admitted.agent.id, 'pi');
  const empty = { DB: { prepare() {
    return { bind() { return this; }, async all() { return { results: [] }; } };
  } } } as unknown as Env;
  await assert.rejects(authorize(empty, 'hash', 'cloudflare', 'main'), /unlock_required/);
  // Wrong service or label finds no grant.
  await assert.rejects(authorize(env, 'hash', 'github', 'main'), /unlock_required/);
});

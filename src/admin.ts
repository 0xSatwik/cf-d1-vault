import { z } from 'zod';
import { adminRole, subset } from './auth.js';
import { auditStatement, finishAudit, prune, reserveAudit } from './audit.js';
import { encrypt } from './crypto.js';
import { type AgentRow, type Env, type GrantRow, type KeyRow, identifier, json, now,
  parsePolicy, policySchema, readBounded, requestId, VaultError } from './types.js';

const unlockSchema = z.object({ agent_id: identifier, service: z.literal('github'), key_label: identifier,
  ...policySchema.shape, request_id: requestId }).strict();
const keySchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('add'), service: z.literal('github'), label: identifier,
    secret: z.string().min(1).max(2048).regex(/^[\x21-\x7e]+$/), policy: policySchema,
    enc_version: z.union([z.literal(1), z.literal(2)]).default(1), request_id: requestId }).strict(),
  z.object({ action: z.literal('rotate'), service: z.literal('github'), label: identifier,
    secret: z.string().min(1).max(2048).regex(/^[\x21-\x7e]+$/), policy: policySchema,
    enc_version: z.union([z.literal(1), z.literal(2)]).default(1), request_id: requestId }).strict(),
  z.object({ action: z.literal('disable'), service: z.literal('github'), label: identifier,
    request_id: requestId }).strict()
]);
const revokeSchema = z.object({ target: z.enum(['grant', 'agent', 'key']), id: identifier, request_id: requestId }).strict();
const agentSchema = z.object({ id: identifier, token_hash: z.string().regex(/^[0-9a-f]{64}$/),
  policy: policySchema, request_id: requestId }).strict();
async function body(request: Request): Promise<unknown> {
  if (request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/json')
    throw new VaultError('json_required', 415);
  return JSON.parse(await readBounded(request, 32768));
}
async function remember(env: Env, id: string, operation: string): Promise<void> {
  await env.DB.prepare('INSERT INTO admin_requests(request_id,operation,created_at) VALUES(?,?,?)')
    .bind(id, operation, now()).run();
}
async function repeated(env: Env, id: string): Promise<void> {
  if (await env.DB.prepare('SELECT request_id FROM admin_requests WHERE request_id=?').bind(id).first())
    throw new VaultError('admin_request_already_used', 409);
}
function safeGrant(grant: GrantRow): object {
  return { id: grant.id, agent_id: grant.agent_id, key_id: grant.key_id, service: grant.service,
    policy: parsePolicy(grant.policy_json), opened_at: grant.opened_at, expires_at: grant.expires_at,
    revoked_at: grant.revoked_at };
}
export async function admin(request: Request, env: Env, path: string): Promise<Response> {
  const role = await adminRole(request, env);
  if (path === '/whoami') {
    if (request.method !== 'GET') throw new VaultError('method_not_allowed', 405);
    return json({ role });
  }
  if (role === 'human' && !(path === '/admin/keys' && ['GET', 'POST'].includes(request.method)))
    throw new VaultError('forbidden', 403);
  // Check the human action before any database or audit side effects.
  const raw = request.method === 'POST' ? await body(request) : undefined;
  if (role === 'human' && request.method === 'POST' &&
      (typeof raw !== 'object' || raw === null || !('action' in raw) || raw.action !== 'add'))
    throw new VaultError('forbidden', 403);
  await prune(env);
  if (path === '/admin/keys' && request.method === 'GET') {
    const audit = await reserveAudit(env, { operation: 'admin_keys_list', status: 'reserved', request_id: crypto.randomUUID() });
    const rows = await env.DB.prepare('SELECT id,service,label,enc_version,policy_json,enabled FROM keys ORDER BY service,label LIMIT 100').all();
    await finishAudit(env, audit, 'succeeded');
    return json({ keys: rows.results, limit: 100 });
  }
  if (request.method !== 'POST') throw new VaultError('method_not_allowed', 405);
  if (path === '/unlock') {
    const args = unlockSchema.parse(raw);
    const previous = await env.DB.prepare('SELECT * FROM grants WHERE admin_request_id=?')
      .bind(args.request_id).first<GrantRow>();
    const policy = policySchema.parse({ allowed_tools: args.allowed_tools, resources: args.resources });
    const key = await env.DB.prepare('SELECT * FROM keys WHERE service=? AND label=?')
      .bind(args.service, args.key_label).first<KeyRow>();
    if (previous) {
      if (previous.agent_id !== args.agent_id || previous.key_id !== key?.id || previous.service !== args.service ||
          previous.policy_json !== JSON.stringify(policy)) throw new VaultError('idempotency_conflict', 409);
      // Never revive or extend an old grant, even if already expired/revoked.
      return json(safeGrant(previous));
    }
    const agent = await env.DB.prepare('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL')
      .bind(args.agent_id).first<AgentRow>();
    if (!agent || !key?.enabled) throw new VaultError('disabled_or_missing');
    if (!subset(policy, parsePolicy(agent.policy_json)) || !subset(policy, parsePolicy(key.policy_json)))
      throw new VaultError('scope_exceeds_policy');
    const count = await env.DB.prepare('SELECT count(*) AS n FROM grants').first<{n: number}>();
    if (!count || count.n >= 10000) throw new VaultError('grant_capacity', 503);
    const grant: GrantRow = { id: crypto.randomUUID(), agent_id: agent.id, key_id: key.id, service: key.service,
      policy_json: JSON.stringify(policy), opened_at: now(), expires_at: 0, revoked_at: null, admin_request_id: args.request_id };
    grant.expires_at = grant.opened_at + 7200;
    await env.DB.batch([
      auditStatement(env, { agent_id: agent.id, key_id: key.id, grant_id: grant.id,
        operation: 'unlock', status: 'succeeded', request_id: args.request_id }),
      env.DB.prepare(`INSERT INTO grants(id,agent_id,key_id,service,policy_json,opened_at,expires_at,revoked_at,admin_request_id)
        VALUES(?,?,?,?,?,?,?,NULL,?)`).bind(grant.id, agent.id, key.id, key.service, grant.policy_json,
        grant.opened_at, grant.expires_at, args.request_id)
    ]);
    return json(safeGrant(grant));
  }
  if (path === '/revoke') {
    const args = revokeSchema.parse(raw);
    await repeated(env, args.request_id);
    // Static statement selection only; identifiers are never interpolated from a request.
    const timestamp = now();
    const statements: D1PreparedStatement[] = [
      auditStatement(env, { operation: `revoke_${args.target}`, status: 'succeeded', request_id: args.request_id }),
      env.DB.prepare('INSERT INTO admin_requests VALUES(?,?,?)').bind(args.request_id, 'revoke', timestamp)
    ];
    if (args.target === 'grant') statements.push(env.DB.prepare('UPDATE grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL').bind(timestamp, args.id));
    if (args.target === 'agent') statements.push(
      env.DB.prepare('UPDATE agents SET revoked_at=? WHERE id=? AND revoked_at IS NULL').bind(timestamp, args.id),
      env.DB.prepare('UPDATE grants SET revoked_at=? WHERE agent_id=? AND revoked_at IS NULL').bind(timestamp, args.id));
    if (args.target === 'key') statements.push(
      env.DB.prepare('UPDATE keys SET enabled=0 WHERE id=?').bind(args.id),
      env.DB.prepare('UPDATE grants SET revoked_at=? WHERE key_id=? AND revoked_at IS NULL').bind(timestamp, args.id));
    await env.DB.batch(statements);
    return json({ status: 'revoked' });
  }
  if (path === '/admin/agents') {
    const args = agentSchema.parse(raw);
    await repeated(env, args.request_id);
    await env.DB.batch([
      auditStatement(env, { agent_id: args.id, operation: 'admin_agent_add', status: 'succeeded', request_id: args.request_id }),
      env.DB.prepare('INSERT INTO admin_requests VALUES(?,?,?)').bind(args.request_id, 'admin_agent_add', now()),
      env.DB.prepare('INSERT INTO agents(id,token_hash,policy_json,revoked_at) VALUES(?,?,?,NULL)')
        .bind(args.id, args.token_hash, JSON.stringify(args.policy))
    ]);
    return json({ id: args.id, status: 'created' }, 201);
  }
  if (path === '/admin/keys') {
    const args = keySchema.parse(raw);
    await repeated(env, args.request_id);
    const old = await env.DB.prepare('SELECT * FROM keys WHERE service=? AND label=?')
      .bind(args.service, args.label).first<KeyRow>();
    if (args.action === 'add' && old) throw new VaultError('label_exists', 409);
    if (args.action !== 'add' && !old) throw new VaultError('key_missing', 404);
    const id = old?.id ?? crypto.randomUUID();
    const statements: D1PreparedStatement[] = [
      auditStatement(env, { key_id: id, operation: `admin_key_${args.action}`, status: 'succeeded', request_id: args.request_id }),
      env.DB.prepare('INSERT INTO admin_requests VALUES(?,?,?)').bind(args.request_id, `admin_key_${args.action}`, now())
    ];
    if (args.action === 'disable') {
      statements.push(env.DB.prepare('UPDATE keys SET enabled=0 WHERE id=?').bind(id));
    } else {
      const encrypted = await encrypt(env, { id, service: args.service, label: args.label, enc_version: args.enc_version }, args.secret);
      if (args.action === 'add') statements.push(env.DB.prepare(`INSERT INTO keys
        (id,service,label,ciphertext,nonce,enc_version,policy_json,enabled) VALUES(?,?,?,?,?,?,?,1)`)
        .bind(id, args.service, args.label, encrypted.ciphertext, encrypted.nonce, args.enc_version, JSON.stringify(args.policy)));
      else statements.push(env.DB.prepare(`UPDATE keys SET ciphertext=?,nonce=?,enc_version=?,policy_json=?,enabled=1 WHERE id=?`)
        .bind(encrypted.ciphertext, encrypted.nonce, args.enc_version, JSON.stringify(args.policy), id));
    }
    if (old) statements.push(env.DB.prepare('UPDATE grants SET revoked_at=? WHERE key_id=? AND revoked_at IS NULL').bind(now(), id));
    await env.DB.batch(statements);
    return json({ id, service: args.service, label: args.label, action: args.action });
  }
  throw new VaultError('not_found', 404);
}

// Capacity tombstones intentionally require explicit offline archival; never silently
// expire a write/admin request ID and risk replay. Kept here to document the invariant.
void remember;

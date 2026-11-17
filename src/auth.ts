import { equalHash, sha256 } from './crypto.js';
import { type AgentRow, type Env, type GrantRow, type KeyRow, type Operation, type Policy,
  now, parsePolicy, VaultError } from './types.js';

export function bearer(request: Request): string {
  const match = /^Bearer ([^\s]{32,512})$/.exec(request.headers.get('Authorization') ?? '');
  if (!match?.[1]) throw new VaultError('unauthorized', 401);
  return match[1];
}
export type AdminRole = 'master' | 'human';
export async function adminRole(request: Request, env: Env): Promise<AdminRole> {
  const match = /^Bearer (.{1,512})$/.exec(request.headers.get('Authorization') ?? '');
  if (!match?.[1]) throw new VaultError('unauthorized', 401);
  const hash = await sha256(match[1]);
  if (equalHash(hash, env.MASTER_SHA256)) return 'master';
  if (env.HUMAN_SHA256 && equalHash(hash, env.HUMAN_SHA256)) return 'human';
  throw new VaultError('unauthorized', 401);
}
export async function requireMaster(request: Request, env: Env): Promise<void> {
  if (await adminRole(request, env) !== 'master') throw new VaultError('forbidden', 403);
}
export async function authenticate(request: Request, env: Env): Promise<AgentRow> {
  return authenticateHash(env, await sha256(bearer(request)));
}
export async function authenticateHash(env: Env, hash: string): Promise<AgentRow> {
  // Direct D1 binding calls always use primary; no Sessions API or cache.
  const agent = await env.DB.prepare('SELECT * FROM agents WHERE token_hash=? AND revoked_at IS NULL')
    .bind(hash).first<AgentRow>();
  if (!agent || !equalHash(hash, agent.token_hash)) throw new VaultError('unauthorized', 401);
  return agent;
}
export function permits(policy: Policy, operation: Operation): boolean {
  return policy.allowed_tools.includes(operation.tool) && policy.resources.some(resource =>
    resource.repository === operation.repository &&
    (operation.branch === undefined || resource.branches.includes(operation.branch)) &&
    (operation.path === undefined || resource.paths.includes(operation.path)));
}
export function subset(child: Policy, parent: Policy): boolean {
  return child.allowed_tools.every(tool => parent.allowed_tools.includes(tool)) &&
    child.resources.every(resource => parent.resources.some(p =>
      p.repository === resource.repository && resource.branches.every(b => p.branches.includes(b)) &&
      resource.paths.every(path => p.paths.includes(path))));
}
export interface Admission { agent: AgentRow; key: KeyRow; grant: GrantRow }
export async function authorize(env: Env, tokenHash: string, label: string, operation: Operation): Promise<Admission> {
  const rows = await env.DB.prepare(`SELECT k.*, a.id AS agent_id, a.token_hash,
    a.policy_json AS agent_policy, a.revoked_at AS agent_revoked,
    g.id AS grant_id, g.policy_json AS grant_policy, g.opened_at, g.expires_at,
    g.revoked_at AS grant_revoked, g.admin_request_id
    FROM agents a JOIN grants g ON g.agent_id=a.id JOIN keys k ON k.id=g.key_id
    WHERE a.token_hash=? AND a.revoked_at IS NULL AND k.service='github' AND k.label=?
      AND k.enabled=1 AND g.service=k.service AND g.revoked_at IS NULL AND g.expires_at>?
    ORDER BY g.opened_at DESC LIMIT 32`).bind(tokenHash, label, now()).all<KeyRow & {
      agent_id: string; token_hash: string; agent_policy: string; agent_revoked: number | null;
      grant_id: string; grant_policy: string; opened_at: number; expires_at: number;
      grant_revoked: number | null; admin_request_id: string;
    }>();
  for (const row of rows.results) {
    if (![row.policy_json, row.agent_policy, row.grant_policy].every(p => permits(parsePolicy(p), operation))) continue;
    return {
      key: row,
      agent: { id: row.agent_id, token_hash: row.token_hash, policy_json: row.agent_policy, revoked_at: row.agent_revoked },
      grant: { id: row.grant_id, agent_id: row.agent_id, key_id: row.id, service: row.service,
        policy_json: row.grant_policy, opened_at: row.opened_at, expires_at: row.expires_at,
        revoked_at: row.grant_revoked, admin_request_id: row.admin_request_id }
    };
  }
  throw new VaultError('unlock_required');
}

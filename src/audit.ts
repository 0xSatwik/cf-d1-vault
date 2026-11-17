import { type Env, now, VaultError } from './types.js';

export interface AuditEvent {
  agent_id?: string; key_id?: string; grant_id?: string;
  operation: string; status: string; request_id: string;
}
export function auditStatement(env: Env, event: AuditEvent, id = crypto.randomUUID()): D1PreparedStatement {
  return env.DB.prepare(`INSERT INTO audit(id,ts,agent_id,key_id,grant_id,operation,status,request_id)
    VALUES(?,?,?,?,?,?,?,?)`).bind(id, now(), event.agent_id ?? null, event.key_id ?? null,
    event.grant_id ?? null, event.operation, event.status, event.request_id);
}
export async function reserveAudit(env: Env, event: AuditEvent): Promise<string> {
  const id = crypto.randomUUID();
  await auditStatement(env, event, id).run();
  return id;
}
export async function finishAudit(env: Env, id: string, status: string): Promise<void> {
  const result = await env.DB.prepare('UPDATE audit SET status=? WHERE id=?').bind(status, id).run();
  if (result.meta.changes !== 1) throw new VaultError('audit_unavailable', 503);
}
export async function sampledRead(env: Env, event: AuditEvent): Promise<void> {
  if (crypto.getRandomValues(new Uint8Array(1))[0]! < 13) {
    // Sampling is optional; mandatory events never use this path.
    try { await auditStatement(env, event).run(); } catch { /* no secret-bearing logging */ }
  }
}
export async function prune(env: Env): Promise<void> {
  // At most 100 deletions per invocation; no unbounded scheduled sweep.
  await env.DB.prepare('DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE ts<? ORDER BY ts LIMIT 100)')
    .bind(now() - 7 * 86400).run();
}

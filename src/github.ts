import { z } from 'zod';
import { authorize, type Admission } from './auth.js';
import { auditStatement, finishAudit, sampledRead } from './audit.js';
import { decrypt, redact, sha256, unbase64 } from './crypto.js';
import { type Env, type Operation, branchName, filePath, identifier, now, readBounded,
  repoName, requestId, VaultError } from './types.js';

const common = { key_label: identifier, repository: repoName };
export const readFileSchema = z.object({ ...common, branch: branchName, path: filePath }).strict();
export const listIssuesSchema = z.object({ ...common, page: z.number().int().min(1).max(10).default(1),
  state: z.enum(['open', 'closed', 'all']).default('open') }).strict();
export const createIssueSchema = z.object({ ...common, request_id: requestId,
  title: z.string().min(1).max(200), body: z.string().max(8000) }).strict();

export function safePath(path: string): boolean {
  return !path.split('/').some(segment =>
    segment.startsWith('.') || /^(?:secrets?|credentials?)(?:[._-]|$)/i.test(segment) ||
    /\.(?:pem|key|p12|pfx|env)$/i.test(segment));
}
function endpoint(repository: string, suffix: string): URL {
  const [owner, repo] = repository.split('/');
  return new URL(`https://api.github.com/repos/${encodeURIComponent(owner!)}/${encodeURIComponent(repo!)}/${suffix}`);
}
async function dispatch(env: Env, tokenHash: string, label: string, operation: Operation,
  admitted: Admission, url: URL, token: string, body?: string): Promise<Response> {
  // Fresh primary read immediately before EACH network dispatch; never retry automatically.
  const fresh = await authorize(env, tokenHash, label, operation);
  if (fresh.key.id !== admitted.key.id || fresh.key.ciphertext !== admitted.key.ciphertext ||
      fresh.key.nonce !== admitted.key.nonce || fresh.key.enc_version !== admitted.key.enc_version)
    throw new VaultError('unlock_required');
  const response = await fetch(url, {
    method: body === undefined ? 'GET' : 'POST', redirect: 'error',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'cf-d1-vault/1.0',
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body, signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) {
    await response.body?.cancel();
    if (response.status === 429 || response.status === 403) {
      // Return only bounded retry metadata, never upstream error bodies or headers.
      const retry = Number(response.headers.get('retry-after'));
      throw new VaultError(Number.isFinite(retry) && retry > 0
        ? `upstream_refused_retry_after_${Math.min(Math.ceil(retry), 86400)}` : 'upstream_refused', 429);
    }
    throw new VaultError('upstream_failed', 502);
  }
  return response;
}
export async function readFile(env: Env, tokenHash: string, raw: unknown): Promise<unknown> {
  const args = readFileSchema.parse(raw);
  if (!safePath(args.path)) throw new VaultError('sensitive_path');
  const operation: Operation = { tool: 'github_read_file', repository: args.repository, branch: args.branch, path: args.path };
  const admission = await authorize(env, tokenHash, args.key_label, operation);
  const token = await decrypt(env, admission.key);
  const url = endpoint(args.repository, `contents/${args.path.split('/').map(encodeURIComponent).join('/')}`);
  url.searchParams.set('ref', args.branch);
  const response = await dispatch(env, tokenHash, args.key_label, operation, admission, url, token);
  const data = z.object({ type: z.literal('file'), encoding: z.literal('base64'), size: z.number().max(32768),
    content: z.string().max(50000), sha: z.string() }).parse(JSON.parse(await readBounded(response, 65536)));
  const bytes = unbase64(data.content.replace(/\s/g, ''));
  if (bytes.length > 32768) throw new VaultError('too_large', 413);
  const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  await sampledRead(env, { agent_id: admission.agent.id, key_id: admission.key.id, grant_id: admission.grant.id,
    operation: operation.tool, status: 'succeeded', request_id: crypto.randomUUID() });
  return { repository: args.repository, path: args.path, branch: args.branch, sha: data.sha,
    content: redact(content, [token, env.VAULT_DEK_V1, env.VAULT_DEK_V2 ?? '', env.MASTER_SHA256, env.HUMAN_SHA256 ?? '']) };
}
export async function listIssues(env: Env, tokenHash: string, raw: unknown): Promise<unknown> {
  const args = listIssuesSchema.parse(raw);
  const operation: Operation = { tool: 'github_list_issues', repository: args.repository };
  const admission = await authorize(env, tokenHash, args.key_label, operation);
  const token = await decrypt(env, admission.key);
  const url = endpoint(args.repository, 'issues');
  url.search = new URLSearchParams({ state: args.state, page: String(args.page), per_page: '20' }).toString();
  const response = await dispatch(env, tokenHash, args.key_label, operation, admission, url, token);
  const issues = z.array(z.object({ number: z.number().int(), title: z.string().max(2048),
    state: z.string(), pull_request: z.unknown().optional() })).max(20)
    .parse(JSON.parse(await readBounded(response, 131072)));
  await sampledRead(env, { agent_id: admission.agent.id, key_id: admission.key.id, grant_id: admission.grant.id,
    operation: operation.tool, status: 'succeeded', request_id: crypto.randomUUID() });
  return { page: args.page, issues: issues.filter(i => !i.pull_request).map(i => ({ number: i.number,
    title: redact(i.title, [token, env.VAULT_DEK_V1, env.VAULT_DEK_V2 ?? '', env.MASTER_SHA256, env.HUMAN_SHA256 ?? '']), state: i.state })) };
}
export async function createIssue(env: Env, tokenHash: string, raw: unknown): Promise<unknown> {
  if (env.ENABLE_GITHUB_WRITES !== 'true') throw new VaultError('writes_disabled');
  const args = createIssueSchema.parse(raw);
  const operation: Operation = { tool: 'github_create_issue', repository: args.repository };
  const admission = await authorize(env, tokenHash, args.key_label, operation);
  // Request ID covers exact key and arguments without persisting their contents.
  const fingerprint = await sha256(JSON.stringify([admission.key.id, args]));
  const old = await env.DB.prepare('SELECT fingerprint,status FROM write_operations WHERE agent_id=? AND request_id=?')
    .bind(admission.agent.id, args.request_id).first<{fingerprint: string; status: string}>();
  if (old) {
    if (old.fingerprint !== fingerprint) throw new VaultError('idempotency_conflict', 409);
    return { status: old.status, duplicate: true, instruction: 'Never resend with a new ID; Muse must reconcile uncertain writes.' };
  }
  const token = await decrypt(env, admission.key);
  const auditId = crypto.randomUUID();
  await env.DB.batch([
    auditStatement(env, { agent_id: admission.agent.id, key_id: admission.key.id, grant_id: admission.grant.id,
      operation: operation.tool, status: 'reserved', request_id: args.request_id }, auditId),
    env.DB.prepare(`INSERT INTO write_operations(agent_id,request_id,key_id,fingerprint,status,created_at)
      VALUES(?,?,?,?,'reserved',?)`).bind(admission.agent.id, args.request_id, admission.key.id, fingerprint, now())
  ]);
  let status = 'unknown';
  try {
    const response = await dispatch(env, tokenHash, args.key_label, operation, admission,
      endpoint(args.repository, 'issues'), token, JSON.stringify({ title: args.title, body: args.body }));
    // Consume only bounded selected response; a parsing failure leaves an uncertain operation.
    const issue = z.object({ number: z.number().int() }).parse(JSON.parse(await readBounded(response, 65536)));
    status = 'succeeded';
    await env.DB.prepare('UPDATE write_operations SET status=? WHERE agent_id=? AND request_id=?')
      .bind(status, admission.agent.id, args.request_id).run();
    await finishAudit(env, auditId, status);
    return { number: issue.number, status };
  } catch {
    // A timeout may mean GitHub committed. The durable reservation forbids redispatch.
    await env.DB.prepare('UPDATE write_operations SET status=? WHERE agent_id=? AND request_id=?')
      .bind(status, admission.agent.id, args.request_id).run();
    await finishAudit(env, auditId, status);
    throw new VaultError('write_outcome_unknown_reconcile_with_muse', 503);
  }
}

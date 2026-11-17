import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { z } from 'zod';
import { admin } from './admin.js';
import { authenticate } from './auth.js';
import { createIssue, createIssueSchema, listIssues, listIssuesSchema, readFile, readFileSchema } from './github.js';
import { type Env, json, readBounded, VaultError } from './types.js';

const CSP = "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
function secure(response: Response): Response {
  const result = new Response(response.body, response);
  result.headers.set('Cache-Control', 'no-store');
  result.headers.set('Content-Security-Policy', CSP);
  result.headers.set('X-Content-Type-Options', 'nosniff');
  result.headers.set('Referrer-Policy', 'no-referrer');
  result.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  return result;
}
async function mcp(request: Request, env: Env): Promise<Response> {
  const agent = await authenticate(request, env);
  // A fresh server and transport per HTTP request; no global transport/session state.
  const server = new McpServer({ name: 'cf-d1-vault', version: '1.0.0' });
  const invoke = (schema: z.ZodType, fn: (env: Env, hash: string, args: unknown) => Promise<unknown>) =>
    async (args: unknown) => {
      try {
        const result = await fn(env, agent.token_hash, schema.parse(args));
        return { content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
      } catch (error) {
        const label = z.object({ key_label: z.string().regex(/^[A-Za-z0-9_-]{1,80}$/) }).safeParse(args);
        const result = error instanceof VaultError && error.code === 'unlock_required'
          ? { error: 'unlock_required', service: 'github', label: label.success ? label.data.key_label : '',
              instruction: 'Ask Muse to unlock this exact key and scope.' }
          : { error: error instanceof VaultError ? error.code : 'operation_failed' };
        return { isError: true, content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
      }
    };
  server.registerTool('github_read_file', { description: 'Read one exact allowed UTF-8 file on an allowed branch using an exact key label.',
    inputSchema: readFileSchema, annotations: { readOnlyHint: true, openWorldHint: true } }, invoke(readFileSchema, readFile));
  server.registerTool('github_list_issues', { description: 'List up to 20 issue numbers, titles and states; pages 1–10, exact key label.',
    inputSchema: listIssuesSchema, annotations: { readOnlyHint: true, openWorldHint: true } }, invoke(listIssuesSchema, listIssues));
  if (env.ENABLE_GITHUB_WRITES === 'true') server.registerTool('github_create_issue', {
    description: 'Create one issue with a durable request UUID. Never retry uncertain results using another UUID.',
    inputSchema: createIssueSchema, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
  }, invoke(createIssueSchema, createIssue));
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined,
    enableJsonResponse: true, maxRequestBodySize: 32768 });
  await server.connect(transport);
  try {
    if (request.method === 'POST') {
      const parsed: unknown = JSON.parse(await readBounded(request, 32768));
      if (Array.isArray(parsed)) return json({ error: 'batches_not_supported' }, 400);
      return await transport.handleRequest(request, { parsedBody: parsed });
    }
    // Stateless server has no standalone SSE listener or resumable session.
    if (request.method === 'GET' || request.method === 'DELETE')
      return new Response(null, { status: 405, headers: { Allow: 'POST' } });
    return await transport.handleRequest(request);
  } finally { await server.close(); }
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const origin = new URL(env.PUBLIC_ORIGIN);
      if (origin.origin !== env.PUBLIC_ORIGIN || url.origin !== origin.origin) throw new VaultError('untrusted_host');
      const browserOrigin = request.headers.get('Origin');
      if (browserOrigin !== null && browserOrigin !== origin.origin) throw new VaultError('untrusted_origin');
      if (request.headers.get('Sec-Fetch-Site') === 'cross-site') throw new VaultError('cross_site');
      let response: Response;
      if (url.pathname === '/mcp') response = await mcp(request, env);
      else if (['/unlock', '/revoke', '/admin/keys', '/admin/agents'].includes(url.pathname))
        response = await admin(request, env, url.pathname);
      else if (request.method === 'GET' && ['/', '/index.html', '/manual', '/manual.js'].includes(url.pathname)) {
        const asset = new URL(url.pathname === '/manual' ? '/' : url.pathname, origin);
        response = await env.ASSETS.fetch(new Request(asset, { method: 'GET' }));
      } else response = json({ error: 'not_found' }, 404);
      return secure(response);
    } catch (error) {
      // Never serialize caught exceptions, input, upstream errors, or credentials.
      return secure(json({ error: error instanceof VaultError ? error.code :
        error instanceof z.ZodError || error instanceof SyntaxError ? 'invalid_request' : 'request_failed' },
      error instanceof VaultError ? error.status : error instanceof z.ZodError || error instanceof SyntaxError ? 400 : 503));
    }
  }
} satisfies ExportedHandler<Env>;

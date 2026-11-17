'use strict';
const field = id => document.getElementById(id);
const identifier = /^[A-Za-z0-9_-]{1,80}$/;
let writesEnabled = false;
let role = null;
let authGeneration = 0;
function showRole(next) {
  role = next;
  document.querySelectorAll('[data-master-only]').forEach(node => { node.hidden = next !== 'master'; });
  field('role-badge').textContent = next === 'master' ? 'Owner' : next === 'human' ? 'Key contributor' : 'Not signed in';
  field('role-badge').className = 'badge ' + (next === 'master' ? 'badge-owner' : next === 'human' ? 'badge-human' : 'badge-off');
  if (next !== 'master') field('key-action').value = 'add';
  field('key-action-label').hidden = next !== 'master';
  field('key-version-label').hidden = next !== 'master';
  field('key-version-hint').hidden = next !== 'master';
  if (next !== 'master') field('key-version').value = '1';
}
async function signIn() {
  const generation = ++authGeneration;
  showRole(null);
  field('keys-list').replaceChildren();
  message('auth-status', 'Checking password…');
  try {
    const result = await request('/whoami');
    if (generation !== authGeneration) return;
    if (!['master', 'human'].includes(result.role)) throw new Error('Unexpected sign-in response.');
    showRole(result.role);
    message('auth-status', result.role === 'human' ? 'You can add keys and view your key list.' : 'You have full access.');
    await refreshKeys();
  } catch (error) { if (generation === authGeneration) message('auth-status', error.message); }
}
let pageActive = true;
const controllers = new Set();

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function message(id, text) { if (pageActive) field(id).textContent = text; }
function addResource(builder, resource = {}) {
  const rows = builder.querySelector('.resources');
  if (rows.children.length >= 20) return;
  const row = field('resource-template').content.cloneNode(true);
  row.querySelector('.repository').value = resource.repository || '';
  row.querySelector('.branches').value = (resource.branches || []).join(', ');
  row.querySelector('.paths').value = (resource.paths || []).join(', ');
  row.querySelector('.remove-resource').addEventListener('click', event => {
    event.target.closest('.resource').remove();
    syncResources(builder);
  });
  rows.append(row);
  syncResources(builder);
}
function syncResources(builder) {
  const rows = [...builder.querySelectorAll('.resource')];
  rows.forEach((row, index) => {
    row.querySelector('legend').textContent = `Repository ${index + 1}`;
    row.querySelector('.remove-resource').disabled = rows.length === 1;
  });
  builder.querySelector('.add-resource').disabled = rows.length >= 20;
}
function setPolicy(builder, policy) {
  builder.querySelectorAll('.tools input').forEach(input => {
    input.checked = policy.allowed_tools.includes(input.value);
  });
  builder.querySelector('.resources').replaceChildren();
  policy.resources.forEach(resource => addResource(builder, resource));
}
for (const id of ['key-policy', 'unlock-policy']) {
  const builder = field(id);
  builder.append(field('policy-template').content.cloneNode(true));
  builder.querySelector('.add-resource').addEventListener('click', () => addResource(builder));
  addResource(builder);
}
function policyFrom(id) {
  const builder = field(id);
  const allowed_tools = [...builder.querySelectorAll('.tools input:checked')].map(input => input.value);
  if (!allowed_tools.length) throw new Error('Select at least one tool.');
  if (!writesEnabled && allowed_tools.includes('github_create_issue')) throw new Error('Issue creation is disabled on this Worker.');
  const resources = [...builder.querySelectorAll('.resource')].map(row => {
    const repository = row.querySelector('.repository').value.trim();
    if (!/^[a-z0-9][a-z0-9_.-]{0,99}\/[a-z0-9][a-z0-9_.-]{0,99}$/.test(repository)) {
      throw new Error('Use a lowercase owner/repo for each resource.');
    }
    const split = name => {
      const value = row.querySelector(`.${name}`).value.trim();
      return value === '' ? [] : value.split(',').map(item => item.trim());
    };
    const branches = split('branches');
    const paths = split('paths');
    if (branches.length > 20 || branches.some(s => !s || s.length > 200 || /[\s\\%?#\x00-\x1f]/.test(s) || s.includes('..') || s.startsWith('/') || s.endsWith('/'))) {
      throw new Error('Use up to 20 exact branches, each at most 200 characters; no spaces, traversal, backslashes or URL delimiters.');
    }
    if (paths.length > 100 || paths.some(s => !s || s.length > 500 || /[\\%?#\x00-\x1f]/.test(s) || !s.split('/').every(p => p && p !== '.' && p !== '..'))) {
      throw new Error('Use up to 100 exact paths, each at most 500 characters; no empty segments, traversal, backslashes or URL delimiters.');
    }
    return { repository, branches, paths };
  });
  if (!resources.length || resources.length > 20) throw new Error('Add between 1 and 20 resources.');
  return { allowed_tools, resources };
}

// Only fixed, locally authored messages are displayed for server/network errors.
const errors = {
  scope_exceeds_policy: 'The requested scope exceeds the agent or key policy.',
  disabled_or_missing: 'The agent or key is missing, disabled or revoked.',
  label_exists: 'That label already exists. Choose Rotate to replace it.',
  key_missing: 'No key exists with that label.',
  invalid_request: 'The Worker rejected the request format. Check the fields.',
  admin_request_already_used: 'This request ID has already been used. Refresh metadata before retrying.'
};
async function request(path, payload) {
  if (!pageActive) throw new Error('Page is inactive.');
  if (!field('master').value) throw new Error('Enter your password first.');
  const generation = authGeneration;
  const controller = new AbortController();
  controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const options = {
      method: payload ? 'POST' : 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error',
      signal: controller.signal,
      headers: { Authorization: `Bearer ${field('master').value}` }
    };
    if (payload) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify({ ...payload, request_id: crypto.randomUUID() });
      if ('secret' in payload) delete payload.secret;
    }
    let response;
    try { response = await fetch(path, options); }
    catch { throw new Error('No confirmed response. Refresh metadata before repeating a change.'); }
    let data;
    try { data = await response.json(); }
    catch { throw new Error('Unexpected response. Refresh metadata before repeating a change.'); }
    if (generation !== authGeneration) throw new Error('Password changed. Sign in again.');
    if (!response.ok) {
      throw new Error(response.status === 401 ? 'Password not recognized.' :
        Object.hasOwn(errors, data?.error) ? errors[data.error] :
          'Request refused. Check your password and the form, or contact the owner.');
    }
    if (!pageActive) throw new Error('Page is inactive.');
    return data;
  } finally {
    clearTimeout(timer);
    controllers.delete(controller);
  }
}
async function run(button, statusId, task) {
  button.disabled = true;
  message(statusId, 'Working…');
  try { await task(); }
  catch (error) { message(statusId, error.message); }
  finally { button.disabled = false; }
}
field('key-form').addEventListener('submit', event => {
  event.preventDefault();
  void run(event.submitter, 'key-status', async () => {
    const policy = policyFrom('key-policy');
    const secret = field('secret').value;
    if (!/^[\x21-\x7e]{1,2048}$/.test(secret)) throw new Error('The GitHub secret must contain 1–2048 printable ASCII characters without spaces.');
    const payload = { action: field('key-action').value, service: 'github', label: field('key-label').value,
      secret, enc_version: Number(field('key-version').value), policy };
    field('secret').value = '';
    await request('/admin/keys', payload);
    message('key-status', 'Key saved. Rotation revokes all existing grants for this key.');
    await refreshKeys();
  });
});
field('unlock-form').addEventListener('submit', event => {
  event.preventDefault();
  void run(event.submitter, 'unlock-status', async () => {
    const grant = await request('/unlock', { agent_id: field('agent-id').value,
      service: field('unlock-service').value, key_label: field('unlock-label').value, ...policyFrom('unlock-policy') });
    if (!identifier.test(grant.id) || !Number.isFinite(grant.expires_at)) throw new Error('Unexpected grant metadata.');
    message('unlock-status', `Grant ID: ${grant.id} · Expires: ${new Date(grant.expires_at * 1000).toISOString()} (${grant.expires_at} Unix seconds).`);
  });
});
field('revoke-form').addEventListener('submit', event => {
  event.preventDefault();
  void run(event.submitter, 'revoke-status', async () => {
    await request('/revoke', { target: field('revoke-target').value, id: field('revoke-id').value });
    message('revoke-status', 'Revocation completed. Requests already dispatched cannot be recalled.');
    await refreshKeys();
  });
});
async function refreshKeys() {
  await run(field('refresh-keys'), 'keys-status', async () => {
    const data = await request('/admin/keys');
    if (!Array.isArray(data.keys)) throw new Error('Unexpected key metadata.');
    const cards = data.keys.map(key => {
      const card = element('article', undefined, 'key-card');
      card.append(element('h3', `${key.service} / ${key.label}`),
        element('p', key.enabled ? 'Ready to use' : 'Disabled', key.enabled ? 'status-ready' : 'status-disabled'),
        element('p', `ID: ${key.id}`, 'hint'));
      const policy = JSON.parse(key.policy_json);
      const details = element('details');
      
      // Render policy metadata as readable text, never raw JSON.
      details.replaceChildren(element('summary', 'Access details'));
      const names = { github_read_file: 'Read files', github_list_issues: 'View issues', github_create_issue: 'Create issues' };
      details.append(element('p', policy.allowed_tools.map(tool => names[tool] || 'Unknown permission').join(' · ')));
      policy.resources.forEach(resource => {
        details.append(element('p', resource.repository), element('p', `Branches: ${resource.branches.join(', ') || 'None'} · Files: ${resource.paths.join(', ') || 'None'}`, 'hint'));
      });
      card.append(details);
      const actions = element('div', undefined, 'actions');
      const rotate = element('button', 'Rotate', 'secondary');
      rotate.type = 'button';
      rotate.addEventListener('click', () => {
        field('key-action').value = 'rotate';
        field('key-label').value = key.label;
        field('key-version').value = String(key.enc_version);
        field('secret').value = '';
        setPolicy(field('key-policy'), policy);
        field('key-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
        field('secret').focus({ preventScroll: true });
        message('key-status', 'Policy loaded. Enter a replacement secret and review the scope before saving.');
      });
      const disable = element('button', 'Disable', 'danger');
      disable.type = 'button';
      disable.disabled = !key.enabled;
      disable.addEventListener('click', () => void run(disable, 'keys-status', async () => {
        await request('/admin/keys', { action: 'disable', service: 'github', label: key.label });
        await refreshKeys();
      }));
      actions.append(rotate, disable);
      if (role === 'master') card.append(actions);
      return card;
    });
    field('keys-list').replaceChildren(...cards);
    message('keys-status', `${cards.length} key(s) shown. Maximum ${data.limit}. Metadata only.`);
  });
}
field('refresh-keys').addEventListener('click', () => void refreshKeys());
field('sign-in').addEventListener('click', () => void signIn());
field('master').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); void signIn(); } });
field('master').addEventListener('change', () => { if (field('master').value) void signIn(); });
field('master').addEventListener('input', () => {
  ++authGeneration;
  showRole(null);
  field('keys-list').replaceChildren();
  message('auth-status', 'Sign in to continue.');
});
field('clear-master').addEventListener('click', () => {
  ++authGeneration;
  field('master').value = '';
  field('secret').value = '';
  showRole(null);
  field('keys-list').replaceChildren();
  message('auth-status', 'Password cleared.');
  field('master').focus();
});
async function checkWorker() {
  await run(field('check-worker'), 'worker-status', async () => {
    let response;
    try { response = await fetch('/index.html', { credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000) }); }
    catch { throw new Error('Worker unreachable'); }
    const setting = response.headers.get('X-Vault-GitHub-Writes');
    writesEnabled = response.ok && setting === 'true';
    document.querySelectorAll('.tools input[value="github_create_issue"]').forEach(input => {
      input.disabled = !writesEnabled;
      if (!writesEnabled) input.checked = false;
    });
    document.querySelectorAll('.write-note').forEach(note => {
      note.textContent = writesEnabled ? '— available' : '— disabled by the owner';
    });
    if (!response.ok || setting === null) throw new Error('Worker configuration unavailable');
    message('worker-status', `Worker reachable · GitHub writes ${writesEnabled ? 'enabled' : 'disabled'}`);
  });
}
field('check-worker').addEventListener('click', () => void checkWorker());
showRole(null);
void checkWorker();
window.addEventListener('pagehide', () => {
  pageActive = false;
  ++authGeneration;
  showRole(null);
  field('keys-list').replaceChildren();
  field('master').value = '';
  field('secret').value = '';
  controllers.forEach(controller => controller.abort());
});
window.addEventListener('pageshow', () => { pageActive = true; });

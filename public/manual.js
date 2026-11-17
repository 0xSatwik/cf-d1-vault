'use strict';
const field = id => document.getElementById(id);
const identifier = /^[A-Za-z0-9_-]{1,80}$/;
// Key names may contain spaces: "GitHub work token" is a valid name.
const labelPattern = /^[A-Za-z0-9](?:[A-Za-z0-9_-]| [A-Za-z0-9_-])*$/;
// Pre-filled services from the Rakazo project (plus the ones we run on).
// The website is only a starting point — edit it for any service.
const SERVICES = {
  github: 'https://api.github.com',
  cloudflare: 'https://api.cloudflare.com',
  openrouter: 'https://openrouter.ai/api/v1',
  openai: 'https://api.openai.com/v1',
  anthropic: 'https://api.anthropic.com',
  google: 'https://generativelanguage.googleapis.com/v1beta',
  composio: 'https://backend.composio.dev',
  pipedream: 'https://api.pipedream.com',
  e2b: 'https://api.e2b.dev',
  daytona: 'https://app.daytona.io/api',
  slack: 'https://slack.com/api',
  telegram: 'https://api.telegram.org',
  gmail: 'https://gmail.googleapis.com/gmail/v1',
  'google-calendar': 'https://www.googleapis.com/calendar/v3',
  notion: 'https://api.notion.com',
  linear: 'https://api.linear.app',
  resend: 'https://api.resend.com',
  expo: 'https://exp.host'
};
let lastAutoWebsite = '';
let role = null;
let authGeneration = 0;
function setStatus(id, text, kind) {
  const node = field(id);
  node.textContent = text;
  node.className = 'status' + (kind ? ' ' + kind : '');
}
function showRole(next) {
  role = next;
  document.querySelectorAll('[data-master-only]').forEach(node => { node.hidden = next !== 'master'; });
  field('role-badge').textContent = next === 'master' ? 'Owner' : next === 'human' ? 'Key contributor' : 'Not signed in';
  field('role-badge').className = 'badge ' + (next === 'master' ? 'badge-owner' : next === 'human' ? 'badge-human' : 'badge-off');
  field('signin-state').hidden = !next;
  field('credential-row').hidden = !!next;
  document.querySelector('.signin').classList.toggle('signed-in', !!next);
  if (next) {
    field('signin-state-title').textContent = next === 'master' ? 'Signed in as Owner' : 'Signed in as Key contributor';
    field('signin-state-text').textContent = next === 'master'
      ? 'Full access — add, unlock, revoke and manage keys.'
      : 'You can add keys and view your key list.';
  }
  if (next !== 'master') field('key-action').value = 'add';
  // The unlock form is visible to everyone, but only the master can use it.
  // Human sign-in shows the note instead of hiding the card entirely.
  const locked = next !== 'master';
  field('unlock-form').querySelectorAll('input, button').forEach(el => { el.disabled = locked; });
  field('unlock-note').hidden = !locked;
}
function clearFormStatuses() {
  setStatus('key-status', '', '');
  setStatus('unlock-status', '', '');
  setStatus('revoke-status', '', '');
  setStatus('agent-status', '', '');
}
// Values typed into the forms must not survive a sign-out: the next person
// at this browser would otherwise see the previous key names and agent.
function resetForms() {
  field('key-form').reset();
  field('key-action').value = 'add';
  lastAutoWebsite = '';
  syncService('key-service', 'key-service-custom', 'key-website');
  field('unlock-form').reset();
  syncService('unlock-service', 'unlock-service-custom', null);
  field('revoke-form').reset();
  field('agent-form').reset();
  field('agents-list').replaceChildren();
  setStatus('agents-status', 'Sign in as Owner to see agents.', '');
}
function clearAuth() {
  ++authGeneration;
  field('master').value = '';
  field('secret').value = '';
  showRole(null);
  field('keys-list').replaceChildren();
  resetForms();
  clearFormStatuses();
  setStatus('auth-status', 'Signed out. Password cleared.', '');
  setStatus('keys-status', 'Sign in to see your keys.', '');
  field('master').focus();
}
async function signIn() {
  const generation = ++authGeneration;
  showRole(null);
  field('keys-list').replaceChildren();
  setStatus('auth-status', 'Checking password…', '');
  setStatus('keys-status', 'Sign in to see your keys.', '');
  field('sign-in').disabled = true;
  try {
    const result = await request('/whoami');
    if (generation !== authGeneration) return;
    if (!['master', 'human'].includes(result.role)) throw new Error('Unexpected sign-in response.');
    showRole(result.role);
    setStatus('auth-status', result.role === 'human' ? 'Signed in — you can add keys and view your key list.' : 'Signed in — you have full access.', 'ok');
    await refreshKeys();
    if (result.role === 'master') await refreshAgents();
  } catch (error) {
    if (generation === authGeneration) {
      setStatus('auth-status', error.message, 'error');
      setStatus('keys-status', 'Sign in to see your keys.', '');
    }
  } finally { field('sign-in').disabled = false; }
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

// Only fixed, locally authored messages are displayed for server/network errors.
const errors = {
  disabled_or_missing: 'The agent or key is missing, disabled or revoked.',
  label_exists: 'That label already exists. Use Rotate on its card to replace it.',
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
// Service is a real dropdown now (a datalist never opened on the user's phone).
// Picking a known service fills its website; Custom shows a free-text field.
function serviceValue(selectId, customId) {
  const selected = field(selectId).value;
  return selected === '__custom' ? field(customId).value.trim().toLowerCase() : selected;
}
function syncService(selectId, customId, websiteId) {
  const selected = field(selectId).value;
  field(customId + '-row').hidden = selected !== '__custom';
  if (!websiteId) return;
  const site = SERVICES[selected];
  const current = field(websiteId).value;
  if (site) {
    if (current === '' || current === lastAutoWebsite) {
      field(websiteId).value = site;
      lastAutoWebsite = site;
    }
  } else if (current === lastAutoWebsite) {
    field(websiteId).value = '';
    lastAutoWebsite = '';
  }
}
function setService(selectId, customId, service) {
  const select = field(selectId);
  const known = [...select.options].some(o => o.value === service);
  select.value = known ? service : '__custom';
  field(customId).value = known ? '' : service;
  syncService(selectId, customId, selectId === 'key-service' ? 'key-website' : null);
}
field('key-service').addEventListener('change', () => syncService('key-service', 'key-service-custom', 'key-website'));
field('unlock-service').addEventListener('change', () => syncService('unlock-service', 'unlock-service-custom', null));
syncService('key-service', 'key-service-custom', 'key-website');
field('key-form').addEventListener('submit', event => {
  event.preventDefault();
  void run(event.submitter, 'key-status', async () => {
    const service = serviceValue('key-service', 'key-service-custom');
    const label = field('key-label').value.trim();
    const website = field('key-website').value.trim();
    // Mobile paste often adds a trailing space or newline; tokens never need it.
    const secret = field('secret').value.trim();
    if (!identifier.test(service)) throw new Error('Use a short service name, letters, digits, _ or -.');
    if (!labelPattern.test(label) || label.length > 80) throw new Error('Key names can use letters, digits, spaces, _ and -, up to 80 characters.');
    if (!/^https:\/\/\S+$/.test(website)) throw new Error('Website must start with https:// and contain no spaces.');
    if (!/^[\x21-\x7e]{1,2048}$/.test(secret)) throw new Error('The key value must contain 1–2048 printable ASCII characters without spaces.');
    const action = field('key-action').value;
    const payload = { action, service, label, website, secret };
    await request('/admin/keys', payload);
    message('key-status', action === 'rotate'
      ? 'Key rotated. All existing grants for this key were revoked.'
      : 'Key saved.');
    field('key-form').reset();
    field('key-action').value = 'add';
    lastAutoWebsite = '';
    syncService('key-service', 'key-service-custom', 'key-website');
    await refreshKeys();
  });
});
field('unlock-form').addEventListener('submit', event => {
  event.preventDefault();
  void run(event.submitter, 'unlock-status', async () => {
    const agent = field('agent-id').value.trim();
    const service = serviceValue('unlock-service', 'unlock-service-custom');
    const label = field('unlock-label').value.trim();
    if (!identifier.test(agent)) throw new Error('Enter the agent name, letters, digits, _ or -.');
    if (!identifier.test(service)) throw new Error('Use a short service name, letters, digits, _ or -.');
    if (!labelPattern.test(label) || label.length > 80) throw new Error('Key names can use letters, digits, spaces, _ and -, up to 80 characters.');
    const grant = await request('/unlock', { agent_id: agent, service, key_label: label });
    if (!identifier.test(grant.id) || !Number.isFinite(grant.expires_at)) throw new Error('Unexpected grant metadata.');
    message('unlock-status', `Grant ID: ${grant.id} · Expires: ${new Date(grant.expires_at * 1000).toISOString()} (${grant.expires_at} Unix seconds).`);
  });
});
field('revoke-form').addEventListener('submit', event => {
  event.preventDefault();
  void run(event.submitter, 'revoke-status', async () => {
    const id = field('revoke-id').value.trim();
    if (!identifier.test(id)) throw new Error('Enter the ID to revoke — a grant, agent or key ID, not a key label.');
    await request('/revoke', { target: field('revoke-target').value, id });
    message('revoke-status', 'Revocation completed. Requests already dispatched cannot be recalled.');
    await refreshKeys();
  });
});
async function sha256hex(text) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function refreshAgents() {
  await run(field('refresh-agents'), 'agents-status', async () => {
    const data = await request('/admin/agents');
    if (!Array.isArray(data.agents)) throw new Error('Unexpected agent metadata.');
    const cards = data.agents.map(agent => {
      const card = element('article', undefined, 'key-card');
      card.append(element('h3', agent.id),
        element('p', agent.revoked ? 'Revoked' : 'Active', agent.revoked ? 'status-disabled' : 'status-ready'),
        element('p', agent.revoked ? 'Use Revoke above to remove it fully.' : 'May call /mcp with its token.', 'hint'));
      return card;
    });
    field('agents-list').replaceChildren(...cards);
    message('agents-status', `${cards.length} agent(s) shown. Maximum ${data.limit}.`);
  });
}
field('agent-form').addEventListener('submit', event => {
  event.preventDefault();
  void run(event.submitter, 'agent-status', async () => {
    const id = field('agent-name').value.trim();
    const token = field('agent-token').value.trim();
    if (!identifier.test(id)) throw new Error('Enter the agent name, letters, digits, _ or -.');
    if (!/^[\x21-\x7e]{1,2048}$/.test(token)) throw new Error('The token must contain 1–2048 printable ASCII characters without spaces.');
    // The raw token never leaves this browser: only its SHA-256 goes to the Worker.
    const token_hash = await sha256hex(token);
    await request('/admin/agents', { id, token_hash });
    message('agent-status', 'Agent added. Save its token — it cannot be shown again.');
    field('agent-form').reset();
    await refreshAgents();
  });
});
field('refresh-agents').addEventListener('click', () => void refreshAgents());
async function refreshKeys() {
  await run(field('refresh-keys'), 'keys-status', async () => {
    const data = await request('/admin/keys');
    if (!Array.isArray(data.keys)) throw new Error('Unexpected key metadata.');
    const cards = data.keys.map(key => {
      const card = element('article', undefined, 'key-card');
      card.append(element('h3', `${key.service} / ${key.label}`),
        element('p', key.enabled ? 'Ready to use' : 'Disabled', key.enabled ? 'status-ready' : 'status-disabled'),
        element('p', key.website, 'hint'),
        element('p', `ID: ${key.id}`, 'hint'));
      const actions = element('div', undefined, 'actions');
      const rotate = element('button', 'Rotate', 'secondary');
      rotate.type = 'button';
      rotate.addEventListener('click', () => {
        field('key-action').value = 'rotate';
        setService('key-service', 'key-service-custom', key.service);
        field('key-label').value = key.label;
        field('key-website').value = key.website;
        lastAutoWebsite = key.website;
        field('secret').value = '';
        field('key-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
        field('secret').focus({ preventScroll: true });
        message('key-status', 'Enter a replacement key value and save.');
      });
      const disable = element('button', 'Disable', 'danger');
      disable.type = 'button';
      disable.addEventListener('click', () => void run(disable, 'keys-status', async () => {
        await request('/admin/keys', { action: 'disable', service: key.service, label: key.label });
        await refreshKeys();
        message('keys-status', 'Key disabled.');
      }));
      const enable = element('button', 'Enable', 'primary');
      enable.type = 'button';
      enable.addEventListener('click', () => void run(enable, 'keys-status', async () => {
        await request('/admin/keys', { action: 'enable', service: key.service, label: key.label });
        await refreshKeys();
        message('keys-status', 'Key enabled.');
      }));
      const del = element('button', 'Delete', 'danger');
      del.type = 'button';
      // In-page two-step confirm: native confirm() is auto-dismissed by
      // automated browsers (and is a tiny, mis-tappable dialog on mobile),
      // so the first click arms the button and the second deletes.
      let deleteArmed = false;
      let deleteArmTimer = null;
      del.addEventListener('click', () => {
        if (!deleteArmed) {
          deleteArmed = true;
          del.textContent = 'Confirm delete?';
          del.classList.add('armed');
          deleteArmTimer = setTimeout(() => {
            deleteArmed = false;
            del.textContent = 'Delete';
            del.classList.remove('armed');
          }, 5000);
          return;
        }
        clearTimeout(deleteArmTimer);
        deleteArmed = false;
        del.textContent = 'Delete';
        del.classList.remove('armed');
        void run(del, 'keys-status', async () => {
          await request('/admin/keys', { action: 'delete', service: key.service, label: key.label });
          await refreshKeys();
          message('keys-status', 'Key deleted.');
        });
      });
      actions.append(rotate, key.enabled ? disable : enable, del);
      card.append(actions);
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
  resetForms();
  clearFormStatuses();
  setStatus('auth-status', 'Sign in to continue.', '');
  setStatus('keys-status', 'Sign in to see your keys.', '');
});
field('clear-master').addEventListener('click', () => clearAuth());
field('sign-out').addEventListener('click', () => clearAuth());
async function checkWorker() {
  await run(field('check-worker'), 'worker-status', async () => {
    let response;
    try { response = await fetch('/index.html', { credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000) }); }
    catch { throw new Error('Worker unreachable'); }
    const setting = response.headers.get('X-Vault-GitHub-Writes');
    if (!response.ok || setting === null) throw new Error('Worker configuration unavailable');
    message('worker-status', `Worker reachable · GitHub writes ${setting === 'true' ? 'enabled' : 'disabled'}`);
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
  setStatus('keys-status', 'Sign in to see your keys.', '');
  field('master').value = '';
  field('secret').value = '';
  controllers.forEach(controller => controller.abort());
});
window.addEventListener('pageshow', () => { pageActive = true; });

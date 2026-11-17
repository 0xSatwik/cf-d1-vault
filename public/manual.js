'use strict';
const form = document.getElementById('entry');
const status = document.getElementById('status');
const field = id => document.getElementById(id);
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = form.querySelector('button');
  button.disabled = true;
  status.textContent = 'Submitting…';
  try {
    const action = field('action').value;
    const payload = { action, service: 'github', label: field('label').value, request_id: crypto.randomUUID() };
    if (action !== 'disable') {
      payload.secret = field('secret').value;
      payload.policy = JSON.parse(field('policy').value);
      payload.enc_version = Number(field('version').value);
    }
    const pending = fetch('/admin/keys', {
      method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error',
      headers: { Authorization: `Bearer ${field('master').value}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    field('master').value = '';
    field('secret').value = '';
    delete payload.secret;
    const response = await pending;
    // Display fixed text only; never echo credentials or exception details.
    status.textContent = response.ok ? 'Saved. Existing grants were revoked on rotation/disable.' : 'Request refused. Check the policy, label and master credential.';
  } catch {
    status.textContent = 'Submission failed. Verify metadata before trying again.';
  } finally {
    field('master').value = '';
    field('secret').value = '';
    button.disabled = false;
  }
});
window.addEventListener('pagehide', () => { field('master').value = ''; field('secret').value = ''; });

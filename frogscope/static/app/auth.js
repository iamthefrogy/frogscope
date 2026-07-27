// App-wide access-key gate (v2).
//
// Frogscope has no user accounts — a single shared key stands between anyone
// who can reach this URL and every feature of the tool. Checked once per page
// load (the key itself lives in localStorage so it survives a refresh), and
// attached to every API request by store.js's fetch wrappers.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';

const html = htm.bind(h);

const STORAGE_KEY = 'frogscope.auth_key';

export function getStoredKey() {
  try {
    return window.localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

export function clearStoredKey() {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to clear if storage was never reachable in the first place.
  }
}

// Exported so the "Regenerate key" action in DangerZone (manage.js) can keep
// the browser tab that just rotated the key logged in — rotation
// necessarily invalidates the OLD key for everyone else, but there is no
// reason to also log out the person who deliberately triggered it.
export function setStoredKey(key) {
  try {
    window.localStorage.setItem(STORAGE_KEY, key);
  } catch {
    // Private browsing / localStorage disabled: the key still works for
    // this page load via React state, it just won't survive a refresh —
    // better than refusing to let the user in at all.
  }
}

async function verify(key) {
  const res = await fetch('/api/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  return res.ok;
}

export function AuthGate({ children }) {
  const [status, setStatus] = useState('checking'); // checking | needed | ok
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const stored = getStoredKey();
    if (!stored) {
      setStatus('needed');
      return;
    }
    verify(stored).then((ok) => setStatus(ok ? 'ok' : 'needed'));
  }, []);

  // A 401 from any API call (key rotated from elsewhere, or simply revoked)
  // drops straight back to the gate — store.js dispatches this event rather
  // than importing this module directly, so the data layer never has to
  // know the auth UI exists.
  useEffect(() => {
    const onUnauthorised = () => {
      clearStoredKey();
      setStatus('needed');
    };
    window.addEventListener('frogscope:unauthorised', onUnauthorised);
    return () => window.removeEventListener('frogscope:unauthorised', onUnauthorised);
  }, []);

  if (status === 'checking') {
    return html`<div class="loading">Loading…</div>`;
  }

  if (status === 'ok') {
    return children;
  }

  const submit = async (e) => {
    e.preventDefault();
    const key = input.trim();
    if (!key) return;
    setBusy(true);
    setError('');
    const ok = await verify(key);
    setBusy(false);
    if (!ok) {
      setError('That key was not accepted.');
      return;
    }
    setStoredKey(key);
    setStatus('ok');
  };

  return html`<div class="auth-gate">
    <form class="auth-gate-card card" onSubmit=${submit}>
      <div class="brand" style="margin-bottom:16px">
        <span class="brand-dot"></span>
        <div class="brand-text">
          <span class="brand-title">Frogscope</span>
          <span class="brand-sub">An honest map of your internet-facing estate, and what changed since last time</span>
        </div>
      </div>
      <h2 style="margin:0 0 4px;font-size:15px">Enter the access key</h2>
      <p class="muted" style="margin:0 0 14px;font-size:12px">
        Printed once in the container logs the first time this ran
        (<code>docker logs</code>), or set via <code>FROGSCOPE_AUTH_KEY</code>.
      </p>
      <input class="input" type="password" autofocus value=${input}
        onInput=${(e) => setInput(e.target.value)}
        placeholder="Access key" style="width:100%;box-sizing:border-box" />
      ${error ? html`<div class="banner error" style="margin-top:10px">${error}</div>` : null}
      <button class="btn btn-primary" type="submit" disabled=${busy}
        style="margin-top:14px;width:100%">
        ${busy ? 'Checking…' : 'Continue'}
      </button>
    </form>
  </div>`;
}

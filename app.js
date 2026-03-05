const ACCOUNT_DB_NAME = 'webauthn_account_db';
const ACCOUNT_STORE = 'public_accounts';
const SESSION_COOKIE = 'did_session';
const LAST_USER_KEY = 'did_last_username';

let didJwtModule;

/* =========================
   SW
   ========================= */
async function registerServiceWorker() {
  if (!['http:', 'https:'].includes(window.location.protocol)) {
    log('Service Worker dezactivat: Protocol nesuportat (rulezi fișierul local?).', true);
    return;
  }
  if ('serviceWorker' in navigator) {
    try {
      await navigator.serviceWorker.register('sw.js');
      log('Service Worker înregistrat.');
    } catch (e) {
      log('Eșec Service Worker: ' + e.message, true);
    }
  }
}

/* =========================
   MOCK "SERVER" (LOCAL)
   =========================
   passkey_db schema:
   {
     [username]: {
       id: string,
       rawId: base64,
       publicKey: base64 (optional),
       publicKeyAlgorithm: number|'unknown',
       userId: base64 (16 bytes)  <-- IMPORTANT for binding
     }
   }
*/
const MockServer = {
  getUsers: () => JSON.parse(localStorage.getItem('passkey_db') || '{}'),
  saveUser: (name, cred) => {
    const db = MockServer.getUsers();
    db[name] = { ...(db[name] || {}), ...cred };
    localStorage.setItem('passkey_db', JSON.stringify(db));
  },
  generateChallenge: () => crypto.getRandomValues(new Uint8Array(32))
};

/* =========================
   BASE64 HELPERS
   ========================= */
const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromBase64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));

function base64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlToBase64(s) {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad) b64 += '='.repeat(4 - pad);
  return b64;
}

function decodeJwtNoVerify(jwt) {
  try {
    const parts = String(jwt || '').split('.');
    if (parts.length !== 3) return null;
    const payloadJson = atob(base64UrlToBase64(parts[1]));
    return JSON.parse(payloadJson);
  } catch {
    return null;
  }
}

function bytesEqual(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/* =========================
   PROVIDER DETECT
   ========================= */
function detectProvider() {
  const ua = navigator.userAgent.toLowerCase();
  const platform =
    navigator.userAgentData?.platform?.toLowerCase() || navigator.platform.toLowerCase();

  if (ua.includes('android')) {
    return { provider: 'Google Password Manager', os: 'android', hints: ['client-device'] };
  }

  if (platform.includes('win') || ua.includes('windows')) {
    // "mai agresiv" spre platform: scoatem security-key ca hint
    return { provider: 'Windows Hello', os: 'windows', hints: ['client-device'] };
  }

  if (platform.includes('mac') || ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) {
    return { provider: 'Apple Passwords / iCloud Keychain', os: 'apple', hints: ['client-device'] };
  }

  return { provider: 'Provider platform implicit', os: 'other', hints: ['client-device'] };
}

/* =========================
   UI HELPERS
   ========================= */
function log(msg, err = false) {
  const d = document.getElementById('debug-log');
  d.innerHTML += `<div class="${err ? 'text-red-400' : ''}">> ${msg}</div>`;
  d.scrollTop = d.scrollHeight;
}

function showStatus(txt, err = false) {
  const s = document.getElementById('status-message');
  s.innerText = txt;
  s.className = `mb-4 p-3 rounded-lg text-sm text-center ${
    err ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'
  }`;
  s.classList.remove('hidden');
}

/* =========================
   COOKIES + SESSION
   ========================= */
function clearCookies() {
  document.cookie.split(';').forEach((cookie) => {
    const [name] = cookie.split('=');
    document.cookie = `${name.trim()}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
  });
}

function getCookie(name) {
  const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[2]) : null;
}

function setSessionCookie(jwt, maxAgeSeconds = 3600) {
  const isHttps = window.location.protocol === 'https:';
  const securePart = isHttps ? ';Secure' : '';
  document.cookie =
    `${SESSION_COOKIE}=${encodeURIComponent(jwt)};path=/;SameSite=Lax;Max-Age=${maxAgeSeconds}${securePart}`;
}

/* =========================
   STORAGE RESET
   ========================= */
function clearData() {
  localStorage.removeItem('passkey_db');
  localStorage.removeItem(LAST_USER_KEY);
  clearCookies();
  indexedDB.deleteDatabase(ACCOUNT_DB_NAME);
  location.reload();
}

/* =========================
   INDEXEDDB (PUBLIC ACCOUNT VIEW)
   ========================= */
function openAccountDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(ACCOUNT_DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(ACCOUNT_STORE)) {
        db.createObjectStore(ACCOUNT_STORE, { keyPath: 'username' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function savePublicAccountData(data) {
  const db = await openAccountDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(ACCOUNT_STORE, 'readwrite');
    tx.objectStore(ACCOUNT_STORE).put(data);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function getPublicAccountData(username) {
  const db = await openAccountDb();
  const result = await new Promise((resolve, reject) => {
    const tx = db.transaction(ACCOUNT_STORE, 'readonly');
    const req = tx.objectStore(ACCOUNT_STORE).get(username);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return result;
}

/* =========================
   DID-JWT
   ========================= */
async function initDidJwt() {
  if (!didJwtModule) {
    didJwtModule = await import('https://esm.sh/did-jwt@8.0.18');
  }
  return didJwtModule;
}

async function createDidSession(username, nonce) {
  const didJwt = await initDidJwt();

  // ES256KSigner expects Uint8Array(32)
  const privateKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const signer = didJwt.ES256KSigner(privateKeyBytes, true);
  const issuer = `did:example:${username}`;

  const jwt = await didJwt.createJWT(
    { sub: username, nonce, provider: detectProvider().provider, purpose: 'webauthn-session' },
    { issuer, signer, alg: 'ES256K', expiresIn: 60 * 60 }
  );

  setSessionCookie(jwt, 60 * 60);
  localStorage.setItem(LAST_USER_KEY, username);
  return jwt;
}

/* =========================
   RENDER
   ========================= */
function renderAccountView(accountData) {
  document.getElementById('auth-view').classList.add('hidden');
  document.getElementById('account-view').classList.remove('hidden');

  document.getElementById('account-username').innerText = accountData.username;
  document.getElementById('account-credential-id').innerText = accountData.credentialId;
  document.getElementById('account-public-key-alg').innerText = String(accountData.publicKeyAlgorithm);
  document.getElementById('account-provider').innerText = accountData.authenticatorProvider;
  document.getElementById('account-session').innerText = accountData.didSessionJwt;
}

/* =========================
   REGISTER
   ========================= */
async function handleRegister() {
  const user = document.getElementById('username').value.trim();
  if (!user) return showStatus('Introdu un utilizator', true);

  try {
    const providerInfo = detectProvider();
    log(`Inițiez crearea cheii prin ${providerInfo.provider}...`);

    const challenge = MockServer.generateChallenge();
    const userId = crypto.getRandomValues(new Uint8Array(16)); // we will store this

    const options = {
      publicKey: {
        challenge,
        rp: { name: 'Passkey PWA', id: window.location.hostname || 'localhost' },
        user: { id: userId, name: user, displayName: user },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },   // ES256
          { alg: -257, type: 'public-key' }  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'required'
        },
        hints: providerInfo.hints,
        timeout: 60000,
        attestation: 'none'
      }
    };

    const credential = await navigator.credentials.create(options);
    const response = credential.response;

    const alg =
      typeof response.getPublicKeyAlgorithm === 'function'
        ? response.getPublicKeyAlgorithm()
        : 'unknown';

    // Persist: rawId + userId (for later binding via userHandle)
    MockServer.saveUser(user, {
      id: credential.id,
      rawId: toBase64(credential.rawId),
      publicKey: toBase64(response.getPublicKey()),
      publicKeyAlgorithm: alg,
      userId: toBase64(userId) // IMPORTANT
    });

    log(`Passkey salvat. Alg: ${alg}`);
    showStatus(`Înregistrare finalizată prin ${providerInfo.provider}!`);
  } catch (e) {
    log(e.name + ': ' + e.message, true);
    showStatus('Eroare la înregistrare. Verifică log-ul.', true);
  }
}

/* =========================
   LOGIN (2-step)
   - If we know rawId => strict allowCredentials + transports internal
   - Else => discoverable login to "learn" rawId
   - Binding check: if we have stored userId, verify assertion.response.userHandle matches it
     (when userHandle is present)
   ========================= */
async function handleLogin() {
  const user = document.getElementById('username').value.trim();
  if (!user) return showStatus('Introdu un utilizator', true);

  const known = MockServer.getUsers()[user]; // may be undefined

  try {
    const providerInfo = detectProvider();
    log(`Solicit autentificare (platform) prin ${providerInfo.provider}...`);

    const challenge = MockServer.generateChallenge();
    const localNonce = base64Url(crypto.getRandomValues(new Uint8Array(16)));

    const hasRawId = !!known?.rawId;

    const allowCredentials = hasRawId
      ? [{
          id: fromBase64(known.rawId),
          type: 'public-key',
          transports: ['internal']
        }]
      : []; // discoverable picker (first-time bind)

    if (!hasRawId) {
      log(
        'Nu am credentialId (rawId) salvat pentru acest username. Permit login discoverable ca să îl învăț, apoi devine strict.',
        true
      );
    }

    const options = {
      publicKey: {
        challenge,
        rpId: window.location.hostname || 'localhost',
        userVerification: 'required',
        hints: providerInfo.hints,
        allowCredentials
      },
      mediation: 'required'
    };

    const assertion = await navigator.credentials.get(options);

    // ===== Binding check via userHandle (when available) =====
    // userHandle is a BufferSource or null; present especially for discoverable credentials.
    const userHandle = assertion?.response?.userHandle
      ? new Uint8Array(assertion.response.userHandle)
      : null;

    const storedUserIdBytes = known?.userId ? fromBase64(known.userId) : null;

    // If we have stored userId and we receive userHandle, they MUST match.
    // If they don't match -> user picked a different passkey than the username they typed.
    if (storedUserIdBytes && userHandle && !bytesEqual(userHandle, storedUserIdBytes)) {
      log('SECURITY: userHandle NU se potrivește cu userId salvat. Username pare legat de alt passkey.', true);
      showStatus('Ai ales o altă cheie decât cea înregistrată pentru acest username. Verifică username-ul.', true);
      return;
    }

    // If we didn't have userId stored yet (e.g., username existed without prior register),
    // and we got userHandle now, bind it (safe-ish) to this username.
    if (!storedUserIdBytes && userHandle) {
      MockServer.saveUser(user, { userId: toBase64(userHandle) });
      log('Am salvat userId (din userHandle) pentru binding-ul username <-> passkey.');
    }

    // ===== Learn rawId after successful assertion (for future strict logins) =====
    if (!hasRawId) {
      MockServer.saveUser(user, {
        id: assertion.id,
        rawId: toBase64(assertion.rawId)
      });
      log(`Am învățat și salvat rawId pentru "${user}". De acum login-ul poate fi strict (internal).`);
    }

    const sessionJwt = await createDidSession(user, localNonce);

    const updated = MockServer.getUsers()[user] || {};

    const publicAccountData = {
      username: user,
      credentialId: assertion.id,
      type: assertion.type,
      rawId: toBase64(assertion.rawId),

      authenticatorAttachment: 'platform',
      authenticatorProvider: providerInfo.provider,
      clientExtensionResults: assertion.getClientExtensionResults(),
      publicKeyAlgorithm: updated.publicKeyAlgorithm ?? 'unknown',

      lastLoginAt: new Date().toISOString(),
      didSessionJwt: sessionJwt,
      webauthn: 'https://www.w3.org/TR/webauthn-3/'
    };

    await savePublicAccountData(publicAccountData);
    const account = await getPublicAccountData(user);
    renderAccountView(account);

    log(`Login OK. Nonce DID: ${localNonce}`);
    showStatus('Te-ai logat cu succes!');
  } catch (e) {
    log(e.name + ': ' + e.message, true);
    showStatus('Eroare la autentificare', true);
  }
}

/* =========================
   LOGOUT
   ========================= */
async function handleLogout() {
  clearCookies();
  localStorage.removeItem(LAST_USER_KEY);

  await new Promise((resolve) => {
    const req = indexedDB.deleteDatabase(ACCOUNT_DB_NAME);
    req.onsuccess = resolve;
    req.onerror = resolve;
    req.onblocked = resolve;
  });

  document.getElementById('account-view').classList.add('hidden');
  document.getElementById('auth-view').classList.remove('hidden');
  showStatus('Logout realizat. Cookies + IndexedDB au fost curățate.');
  log('Logout: sesiune locală ștearsă.');
}

/* =========================
   RESTORE SESSION
   ========================= */
async function tryRestoreSessionFromCookie() {
  const jwt = getCookie(SESSION_COOKIE);
  if (!jwt) return false;

  const payload = decodeJwtNoVerify(jwt);
  const jwtUser = payload?.sub;
  const lastUser = localStorage.getItem(LAST_USER_KEY);

  const username = (jwtUser || lastUser || '').trim();
  if (!username) return false;

  const account = await getPublicAccountData(username);
  if (!account) return false;

  account.didSessionJwt = jwt;
  renderAccountView(account);
  showStatus('Sesiune restaurată automat din cookie.');
  log(`Restore: username="${username}", provider="${payload?.provider || 'n/a'}"`);
  return true;
}

/* =========================
   EXPOSE
   ========================= */
window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.handleLogout = handleLogout;
window.clearData = clearData;

/* =========================
   ONLOAD
   ========================= */
window.onload = async () => {
  const providerInfo = detectProvider();
  document.getElementById('provider-name').innerText = providerInfo.provider;

  const isLocalFile = window.location.protocol === 'file:' || window.location.protocol === 'null';
  const isSecure = window.isSecureContext;

  if (isLocalFile || !isSecure) {
    document.getElementById('security-warning').classList.remove('hidden');
  }

  registerServiceWorker();
  await tryRestoreSessionFromCookie();
};

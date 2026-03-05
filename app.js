const ACCOUNT_DB_NAME = 'webauthn_account_db';
const ACCOUNT_STORE = 'public_accounts';
const SESSION_COOKIE = 'did_session';
const LAST_USER_KEY = 'did_last_username';

let didJwtModule;

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

const MockServer = {
  getUsers: () => JSON.parse(localStorage.getItem('passkey_db') || '{}'),
  saveUser: (name, cred) => {
    const db = MockServer.getUsers();
    db[name] = cred;
    localStorage.setItem('passkey_db', JSON.stringify(db));
  },
  generateChallenge: () => crypto.getRandomValues(new Uint8Array(32))
};

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

function detectProvider() {
  const ua = navigator.userAgent.toLowerCase();
  const platform =
    navigator.userAgentData?.platform?.toLowerCase() || navigator.platform.toLowerCase();

  if (ua.includes('android')) {
    return { provider: 'Google Password Manager', os: 'android', hints: ['client-device'] };
  }

  if (platform.includes('win') || ua.includes('windows')) {
    // AGRESIV: scoatem hint-ul "security-key" ca să nu împingă spre roaming
    return { provider: 'Windows Hello', os: 'windows', hints: ['client-device'] };
  }

  if (platform.includes('mac') || ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) {
    return { provider: 'Apple Passwords / iCloud Keychain', os: 'apple', hints: ['client-device'] };
  }

  return { provider: 'Provider platform implicit', os: 'other', hints: ['client-device'] };
}

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

function clearData() {
  localStorage.removeItem('passkey_db');
  localStorage.removeItem(LAST_USER_KEY);
  clearCookies();
  indexedDB.deleteDatabase(ACCOUNT_DB_NAME);
  location.reload();
}

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

async function initDidJwt() {
  if (!didJwtModule) {
    didJwtModule = await import('https://esm.sh/did-jwt@8.0.18');
  }
  return didJwtModule;
}

async function createDidSession(username, nonce) {
  const didJwt = await initDidJwt();

  // ES256KSigner => Uint8Array(32)
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

function renderAccountView(accountData) {
  document.getElementById('auth-view').classList.add('hidden');
  document.getElementById('account-view').classList.remove('hidden');

  document.getElementById('account-username').innerText = accountData.username;
  document.getElementById('account-credential-id').innerText = accountData.credentialId;
  document.getElementById('account-public-key-alg').innerText = String(accountData.publicKeyAlgorithm);
  document.getElementById('account-provider').innerText = accountData.authenticatorProvider;
  document.getElementById('account-session').innerText = accountData.didSessionJwt;
}

async function handleRegister() {
  const user = document.getElementById('username').value.trim();
  if (!user) return showStatus('Introdu un utilizator', true);

  try {
    const providerInfo = detectProvider();
    log(`Inițiez crearea cheii prin ${providerInfo.provider}...`);

    const challenge = MockServer.generateChallenge();
    const userId = crypto.getRandomValues(new Uint8Array(16));

    const options = {
      publicKey: {
        challenge,
        rp: { name: 'Passkey PWA', id: window.location.hostname || 'localhost' },
        user: { id: userId, name: user, displayName: user },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' }
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

    MockServer.saveUser(user, {
      id: credential.id,
      rawId: toBase64(credential.rawId),
      publicKey: toBase64(response.getPublicKey()),
      publicKeyAlgorithm: alg
    });

    log(`Passkey salvat. Alg: ${alg}`);
    showStatus(`Înregistrare finalizată prin ${providerInfo.provider}!`);
  } catch (e) {
    log(e.name + ': ' + e.message, true);
    showStatus('Eroare la înregistrare. Verifică log-ul.', true);
  }
}

function requireLocalCredential(user, data) {
  // AGRESIV: fără allowCredentials => refuzăm login
  if (!data?.rawId) {
    showStatus(
      'Nu există passkey local pentru acest user pe device-ul curent. Fă Register pe acest device (platform/Windows Hello) înainte de Login.',
      true
    );
    log('Login refuzat: allowCredentials ar fi gol (nu permitem discoverable/cloud picker).', true);
    return false;
  }
  return true;
}

async function handleLogin() {
  const user = document.getElementById('username').value.trim();
  const data = MockServer.getUsers()[user];
  if (!user) return showStatus('Introdu un utilizator', true);

  if (!requireLocalCredential(user, data)) return;

  try {
    const providerInfo = detectProvider();
    log(`Solicit autentificare (platform) prin ${providerInfo.provider}...`);

    const challenge = MockServer.generateChallenge();
    const localNonce = base64Url(crypto.getRandomValues(new Uint8Array(16)));

    // AGRESIV: allowCredentials obligatoriu + transports internal
    const allowCredentials = [{
      id: fromBase64(data.rawId),
      type: 'public-key',
      transports: ['internal']
    }];

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
    const sessionJwt = await createDidSession(user, localNonce);

    const publicAccountData = {
      username: user,
      credentialId: assertion.id,
      type: assertion.type,
      rawId: toBase64(assertion.rawId),

      authenticatorAttachment: 'platform',
      authenticatorProvider: providerInfo.provider,
      clientExtensionResults: assertion.getClientExtensionResults(),
      publicKeyAlgorithm: data?.publicKeyAlgorithm ?? 'unknown',

      lastLoginAt: new Date().toISOString(),
      didSessionJwt: sessionJwt,
      webauthn: 'https://www.w3.org/TR/webauthn-3/'
    };

    await savePublicAccountData(publicAccountData);
    const account = await getPublicAccountData(user);
    renderAccountView(account);

    log(`Login OK. Nonce DID: ${localNonce}`);
    showStatus('Te-ai logat cu succes (platform/internal)!');

  } catch (e) {
    log(e.name + ': ' + e.message, true);
    showStatus('Eroare la autentificare', true);
  }
}

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

window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.handleLogout = handleLogout;
window.clearData = clearData;

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

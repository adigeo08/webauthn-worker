// --- LOGICA SERVICE WORKER ---
async function registerServiceWorker() {
    // Verificăm dacă suntem pe un protocol valid pentru SW (http/https)
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

// --- LOGICA WEBAUTHN ---
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
const fromBase64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

function log(msg, err = false) {
    const d = document.getElementById('debug-log');
    d.innerHTML += `<div class="${err ? 'text-red-400' : ''}">> ${msg}</div>`;
    d.scrollTop = d.scrollHeight;
}

function showStatus(txt, err = false) {
    const s = document.getElementById('status-message');
    s.innerText = txt;
    s.className = `mb-4 p-3 rounded-lg text-sm text-center ${err ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`;
    s.classList.remove('hidden');
}

function clearData() {
    localStorage.removeItem('passkey_db');
    location.reload();
}

async function handleRegister() {
    const user = document.getElementById('username').value;
    if (!user) return showStatus('Introdu un utilizator', true);

    try {
        log('Inițiez crearea cheii...');
        const challenge = MockServer.generateChallenge();
        const userId = crypto.getRandomValues(new Uint8Array(16));

        const options = {
            publicKey: {
                challenge: challenge,
                rp: { name: 'Passkey PWA', id: window.location.hostname || 'localhost' },
                user: { id: userId, name: user, displayName: user },
                pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    userVerification: 'required',
                    residentKey: 'required'
                },
                timeout: 60000
            }
        };

        const credential = await navigator.credentials.create(options);

        MockServer.saveUser(user, {
            id: credential.id,
            rawId: toBase64(credential.rawId),
            publicKey: toBase64(credential.response.getPublicKey())
        });

        log('Passkey salvat în sistem!');
        showStatus('Înregistrare finalizată!');
    } catch (e) {
        log(e.name + ': ' + e.message, true);
        showStatus('Eroare la înregistrare. Verifică log-ul.', true);
    }
}

async function handleLogin() {
    const user = document.getElementById('username').value;
    const data = MockServer.getUsers()[user];

    try {
        log('Solicit autentificare...');
        const challenge = MockServer.generateChallenge();

        const options = {
            publicKey: {
                challenge: challenge,
                rpId: window.location.hostname || 'localhost',
                userVerification: 'required',
                allowCredentials: data ? [{ id: fromBase64(data.rawId), type: 'public-key' }] : []
            }
        };

        await navigator.credentials.get(options);
        log('Autentificare reușită!');
        showStatus('Te-ai logat cu succes!');
    } catch (e) {
        log(e.name + ': ' + e.message, true);
        showStatus('Eroare la autentificare', true);
    }
}

window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.clearData = clearData;

window.onload = () => {
    const isLocalFile = window.location.protocol === 'file:' || window.location.protocol === 'null';
    const isSecure = window.isSecureContext;

    if (isLocalFile || !isSecure) {
        document.getElementById('security-warning').classList.remove('hidden');
    }

    registerServiceWorker();
};

// Signal catalog shared by the JavaScript and Python scanners.
// A signal is a capability or indicator found in published code. The package diff
// reports signals present in the new version and absent from the old one.

export const SEVERITY_RANK = { high: 3, medium: 2, low: 1, info: 0 };

// kind -> [severity when newly introduced, human label]
export const KINDS = {
    'install-script': ['high', 'Install-time script'],
    'install-script-capability': ['high', 'Install-time code gained a capability'],
    'startup-hook': ['high', 'Code that runs automatically at interpreter start-up'],
    obfuscation: ['high', 'Obfuscated code'],
    'encoded-exec': ['high', 'Executes decoded or downloaded code'],
    'credential-path': ['high', 'Reads credential or wallet locations'],
    'key-exfil': ['high', 'Sends keys or seed phrases to a hard-coded address'],
    'exfil-endpoint': ['high', 'Hard-coded exfiltration-style endpoint'],
    'self-publish': ['high', 'Publishes packages, reads tokens or edits CI workflows'],
    persistence: ['high', 'Installs persistence (shell rc, cron, services, autostart)'],
    'global-hook': ['high', 'Overrides global network or wallet functions'],
    'crypto-wallet': ['high', 'Handles cryptocurrency wallets or addresses'],
    'secret-harvest': ['high', 'Collects the whole environment and has network access in the same file'],
    'binary-executable': ['high', 'Ships a new executable binary'],
    network: ['medium', 'Network access'],
    shell: ['medium', 'Runs shell commands or child processes'],
    'python-spawn': ['medium', 'Starts a new Python process'],
    eval: ['medium', 'Dynamic code evaluation'],
    'env-bulk': ['medium', 'Reads the whole environment'],
    'native-code': ['medium', 'Ships native code (.node, .so, .dll, .wasm)'],
    'ip-literal-url': ['medium', 'URL with a raw IP address'],
    'dynamic-require': ['low', 'Loads a module whose name is computed at run time'],
    'new-host': ['low', 'New hard-coded host name'],
    'minified-blob': ['low', 'New minified or generated file'],
};

const re = (s) => new RegExp(s, 'i');

// Indicators applied to string literals (and template-literal text).
export const STRING_INDICATORS = [
    ['credential-path', re(String.raw`(^|[\\/~"'\s.])\.npmrc\b|\.ssh[\\/](id_|authorized_keys|known_hosts)|\bid_(rsa|ed25519|ecdsa)\b|\.aws[\\/]credentials|\.git-credentials|\.config[\\/]gh\b|\.docker[\\/]config\.json|\.kube[\\/]config|\.pypirc|\.netrc\b|Login Data|Local Storage[\\/]leveldb|\bwallet\.dat\b|\.bitcoin[\\/]|Exodus[\\/]exodus\.wallet|\.config[\\/]solana|keystore[\\/]UTC--|\.gnupg[\\/]|\.vault-token|gcloud[\\/](credentials|application_default)|\.azure[\\/]`)],
    ['exfil-endpoint', re(String.raw`webhook\.site|discord(app)?\.com[\\/]api[\\/]webhooks|api\.telegram\.org[\\/]bot|pastebin\.com|paste\.ee|hastebin|ngrok(-free)?\.(io|app|dev)|pipedream\.net|requestbin|beeceptor\.com|interact\.sh|\boast\.(fun|me|pro|live|site|online)|burpcollaborator\.net|canarytokens\.com|\btransfer\.sh|169\.254\.169\.254|metadata\.google\.internal|ipinfo\.io|ip-api\.com|api\.ipify\.org|ifconfig\.me|trycloudflare\.com|workers\.dev[\\/]|bashupload\.com|0x0\.st|temp\.sh|file\.io|anonfiles|gofile\.io`)],
    ['self-publish', re(String.raw`\bnpm\s+(publish|whoami|token|adduser|login)\b|registry\.npmjs\.org[\\/]-[\\/](whoami|npm[\\/]v1[\\/]tokens)|\/-\/v1\/search\?text=maintainer|\bgh\s+auth\s+token\b|\btrufflehog\b|\.github[\\/]workflows[\\/]|NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|TWINE_PASSWORD|PYPI_API_TOKEN|upload\.pypi\.org[\\/]legacy|api\.github\.com[\\/](user[\\/]repos|repos[\\/][^"'\s]*[\\/]actions[\\/]secrets)`)],
    ['persistence', re(String.raw`\bcrontab\b|\.bashrc\b|\.zshrc\b|\.bash_profile\b|[\\/~]\.profile\b|systemctl\s+(enable|--user)|[\\/]etc[\\/]systemd[\\/]|\.config[\\/]systemd[\\/]user|LaunchAgents|LaunchDaemons|CurrentVersion[\\/\\]+Run\b|schtasks\b|\\Startup\\|Start Menu[\\/\\]+Programs[\\/\\]+Startup`)],
    ['crypto-wallet', re(String.raw`\bwindow\.ethereum\b|\bethereum\.request\b|eth_sendTransaction|eth_requestAccounts|solana\.signTransaction|\bmetamask\b|phantom\.app|trustwallet|\bseed phrase\b|\bmnemonic\b.*\bwallet\b`)],
    ['ip-literal-url', re(String.raw`\b(https?|wss?|ftp|tcp)://(?!(127|10|0)\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|255\.)(\d{1,3}\.){3}\d{1,3}(?![\d.])`)],
];

// Strings that look like crypto addresses; many of them in one file = address swapping.
export const WALLET_ADDRESS = /^(0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33}|[1-9A-HJ-NP-Za-km-z]{43,44})$/;

const HOST_RE = /\b(?:https?|wss?):\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi;
const BENIGN_HOSTS = /(^|\.)(github\.com|githubusercontent\.com|npmjs\.(com|org)|nodejs\.org|mozilla\.org|w3\.org|whatwg\.org|python\.org|pypi\.org|readthedocs\.io|ietf\.org|wikipedia\.org|example\.(com|org|net)|localhost|schema\.org|json-schema\.org|opensource\.org|apache\.org|microsoft\.com|google\.com|stackoverflow\.com|unpkg\.com|jsdelivr\.net|semver\.org|ecma-international\.org|tc39\.es|developer\.apple\.com|mdn\.io|caniuse\.com|gnu\.org|spdx\.org|reactjs\.org|react\.dev|typescriptlang\.org|eslint\.org|babeljs\.io|webpack\.js\.org|yarnpkg\.com|pnpm\.io|docs\.python\.org|peps\.python\.org|bugs\.python\.org|git\.io|goo\.gl|bit\.ly)$/i;

export function hostsIn(s) {
    const out = new Set();
    for (const m of s.matchAll(HOST_RE)) {
        const h = m[1].toLowerCase().replace(/\.$/, '');
        if (!BENIGN_HOSTS.test(h) && !/\.(png|svg|js|json|html|md|css)$/.test(h)) out.add(h);
    }
    return out;
}

export const NETWORK_MODULES_JS = new Set(['http', 'https', 'http2', 'net', 'tls', 'dgram', 'dns', 'undici', 'node-fetch', 'axios', 'got', 'request', 'cross-fetch', 'isomorphic-fetch', 'ws', 'socket.io-client', 'superagent', 'needle', 'phin', 'ky', 'ofetch', 'make-fetch-happen', 'minipass-fetch', 'https-proxy-agent', 'http-proxy-agent', 'socks-proxy-agent', 'ftp', 'basic-ftp', 'ssh2', 'nodemailer']);
export const SHELL_MODULES_JS = new Set(['child_process', 'execa', 'shelljs', 'cross-spawn', 'node-pty', 'spawn-sync', 'zx']);
export const EVAL_MODULES_JS = new Set(['vm', 'vm2', 'isolated-vm']);

export function stripNodePrefix(m) {
    return m.startsWith('node:') ? m.slice(5) : m;
}

// A config file under a directory named by a variable other than the home directory
// ("$NODE_VIRTUAL_ENV/.npmrc", "${PREFIX}/.npmrc", "__ENV_DIR__/.npmrc") is a project's or an
// environment's own config, not the user's stored credentials. "$HOME/.npmrc" and "~/.npmrc" still count.
const CONFIG_FILE = /\.(npmrc|pypirc|netrc)$/i;
const VAR_DIR = /(?:\$\{?|%|__)([A-Za-z_][A-Za-z0-9_]*?)(?:\}|%|__)?[\\/]$/;
const HOME_VAR = /HOME|PROFILE|APPDATA|USER/i;
const MAX_CREDENTIAL_MATCHES = 50;
let credentialAll;

function credentialMatch(t, rx) {
    credentialAll ??= new RegExp(rx.source, 'gi');
    let n = 0;
    for (const m of t.matchAll(credentialAll)) {
        if (++n > MAX_CREDENTIAL_MATCHES) break;
        const file = m[0].match(CONFIG_FILE);
        if (file) {
            const at = m.index + file.index;
            const dir = t.slice(Math.max(0, at - 40), at).match(VAR_DIR);
            if (dir && !HOME_VAR.test(dir[1])) continue;
        }
        return m;
    }
    return null;
}

/** Apply string indicators to a string literal; push signals. */
export function scanString(s, push) {
    if (typeof s !== 'string' || s.length < 4) return;
    const t = s.length > 20000 ? s.slice(0, 20000) : s;
    for (const [kind, rx] of STRING_INDICATORS) {
        const m = kind === 'credential-path' ? credentialMatch(t, rx) : t.match(rx);
        if (m) push(kind, m[0].slice(0, 80));
    }
    for (const h of hostsIn(t)) push('new-host', h);
}

const INVISIBLE_RUN = /(?:[\u200B-\u200D\u2060\uFE00-\uFE0F]|\uDB40[\uDC00-\uDDEF]){20,}/;

/** Whole-file text checks that work for any source language. */
export function scanSourceText(src, push) {
    // Code pushed off-screen after a long run of spaces on the same line.
    const hidden = src.match(/\S[ \t]{150,}(?=\S)/);
    if (hidden) {
        const line = src.slice(0, hidden.index).split('\n').length;
        push('obfuscation', `code hidden after ${hidden[0].length - 1} spaces on one line`, line);
    }
    // Data hidden in invisible characters (variation selectors, tags, zero-width).
    const inv = src.match(INVISIBLE_RUN);
    if (inv) push('obfuscation', `run of ${[...inv[0]].length}+ invisible Unicode characters`, src.slice(0, inv.index).split('\n').length);
}

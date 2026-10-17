// Static scan of one JavaScript file: capabilities, indicators and exported names.
// The code is parsed, never run.
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import * as nodeModule from 'node:module';
import {
    NETWORK_MODULES_JS, SHELL_MODULES_JS, EVAL_MODULES_JS, WALLET_ADDRESS, hostsIn, scanString, stripNodePrefix,
} from './signals.js';

export const AST_LIMIT = 6 * 1024 * 1024;
const PARSE_OPTS = {
    ecmaVersion: 'latest',
    allowHashBang: true,
    allowReturnOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowAwaitOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowReserved: true,
    locations: true,
};

/**
 * TypeScript source as JavaScript, or null when Node cannot convert it (or is too old to).
 * Strip mode blanks the types and keeps every other character in place, so lines stay
 * right. Enums, namespaces and `<T>x` casts need transform mode, which moves lines, so
 * `exactLines` is false and callers must not quote line numbers. Files above TRANSFORM_LIMIT get
 * strip mode only.
 */
// Transform mode takes superlinear time on some input (20,000 enums: 4 s), so it is tried only on
// files up to this size. The largest of 191 such files in happy-dom 21 was 116 KB.
export const TRANSFORM_LIMIT = 128 * 1024;

export function stripTypes(src) {
    if (typeof nodeModule.stripTypeScriptTypes !== 'function') return null;
    for (const mode of src.length <= TRANSFORM_LIMIT ? ['strip', 'transform'] : ['strip']) {
        try { return { code: nodeModule.stripTypeScriptTypes(src, { mode }), exactLines: mode === 'strip' }; } catch { /* try next */ }
    }
    return null;
}

// An array literal of at least this many entries, nearly all bare host names, is data (a public
// suffix list, a list of disposable mail domains), not an address the code sends to.
export const NAME_LIST_MIN = 100;
const listSizes = new WeakMap();

// A bare host or public-suffix name ("ngrok.io", "*.ck", "!www.ck"): no scheme, port, path or
// credentials. A full URL in a list is an address, whatever the list looks like. IPv4 addresses
// are not names.
const LABEL = String.raw`[\p{L}\p{N}_][\p{L}\p{M}\p{N}_-]{0,62}`;
const HOST_NAME = new RegExp(String.raw`^!?(?:\*\.)?${LABEL}(?:\.${LABEL})*\.?$`, 'u');
export const isHostName = (s) => s.length <= 253 && HOST_NAME.test(s) && !/^[\d.]+$/.test(s);
const nameLiteral = (e) => e && e.type === 'Literal' && typeof e.value === 'string' && isHostName(e.value);

/** Entry count when `node` is a long array of host-name literals, else 0. */
function listSize(node) {
    if (!node || node.type !== 'ArrayExpression' || node.elements.length < NAME_LIST_MIN) return 0;
    if (!listSizes.has(node)) {
        const names = node.elements.filter(nameLiteral).length;
        listSizes.set(node, names >= 0.9 * node.elements.length ? node.elements.length : 0);
    }
    return listSizes.get(node);
}

function parse(src) {
    for (const sourceType of ['module', 'script']) {
        try {
            return acorn.parse(src, { ...PARSE_OPTS, sourceType });
        } catch { /* try next */ }
    }
    return null;
}

function memberName(n) {
    // Flatten a.b.c (non-computed or string-literal computed) into "a.b.c"
    const parts = [];
    let cur = n;
    while (cur) {
        if (cur.type === 'MemberExpression') {
            if (!cur.computed && cur.property.type === 'Identifier') parts.unshift(cur.property.name);
            else if (cur.property.type === 'Literal' && typeof cur.property.value === 'string') parts.unshift(cur.property.value);
            else parts.unshift('[]');
            cur = cur.object;
        } else if (cur.type === 'Identifier') { parts.unshift(cur.name); break; }
        else if (cur.type === 'ThisExpression') { parts.unshift('this'); break; }
        else if (cur.type === 'ChainExpression') { cur = cur.expression; }
        else { parts.unshift('?'); break; }
    }
    return parts.join('.');
}

function literalString(n) {
    if (!n) return null;
    if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
    if (n.type === 'TemplateLiteral' && n.expressions.length === 0) return n.quasis[0].value.cooked;
    return null;
}

const NETWORK_GLOBALS = new Set(['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource']);
const SHELL_CALLS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']);
const HOOK_TARGETS = /^(window|globalThis|global|self)\.(fetch|XMLHttpRequest|WebSocket|ethereum)$|^XMLHttpRequest\.prototype\.(open|send|setRequestHeader)$|^(window\.)?ethereum\.(request|send|sendAsync)$/;

// Key material: a seed or recovery phrase, or a secret or private key ("this._secretKey" too).
const KEY_NAME = /^_*(seed|seedPhrase|mnemonic|mnemonicPhrase|recoveryPhrase|secretKey|secret_key|privateKey|private_key|privKey|priv_key)$/i;
const SEND_CALL = /(^|\.)(fetch|sendBeacon|post|put|patch|request|ajax)$/;
const KEY_SCAN_NODES = 400;

/** The host of a hard-coded URL in a request's first two arguments, if it is not a well-known site. */
function sendHost(args) {
    for (const a of args.slice(0, 2)) {
        const s = a?.type === 'Literal' && typeof a.value === 'string' ? a.value : a?.type === 'TemplateLiteral' ? a.quasis[0].value.cooked : null;
        if (s && /^(https?|wss?):\/\//i.test(s)) {
            const [h] = hostsIn(s.slice(0, 300));
            if (h) return h;
        }
    }
    return null;
}

/** The first key-material name read by these expressions. Object keys and nested functions are not read. */
function keyNameIn(nodes) {
    const stack = [...nodes].reverse();
    for (let seen = 0; stack.length && seen < KEY_SCAN_NODES; seen++) {
        const n = stack.pop();
        if (!n || typeof n.type !== 'string' || /Function/.test(n.type)) continue;
        if (n.type === 'Identifier') {
            if (KEY_NAME.test(n.name)) return n.name;
        } else if (n.type === 'Property') {
            stack.push(n.value);
            if (n.computed) stack.push(n.key);
        } else {
            const kids = [];
            for (const [k, v] of Object.entries(n)) {
                if (k === 'loc' || k === 'type') continue;
                if (Array.isArray(v)) kids.push(...v); else if (v && typeof v.type === 'string') kids.push(v);
            }
            stack.push(...kids.reverse());
        }
    }
    return null;
}

/** Name of the innermost function around a node: its own name, or the method, property or variable it is assigned to. */
function enclosingName(ancestors) {
    for (let i = ancestors.length - 2; i >= 0; i--) {
        const a = ancestors[i];
        if (!/Function/.test(a.type)) continue;
        if (a.id?.name) return a.id.name;
        const p = ancestors[i - 1];
        if (p?.type === 'MethodDefinition' || p?.type === 'Property' || p?.type === 'PropertyDefinition') return p.key?.name ?? (typeof p.key?.value === 'string' ? p.key.value : null);
        if (p?.type === 'VariableDeclarator' && p.id.type === 'Identifier') return p.id.name;
        if (p?.type === 'AssignmentExpression' && p.left.type === 'MemberExpression') return memberName(p.left).split('.').pop();
        return null;
    }
    return null;
}

/**
 * Scan JS source. Returns { signals: [{kind, detail, line}], exports: {names:Set, reexports:[], cjsRequire:[]}, parsed }
 */
export function scanJs(src, { wantExports = false, typescript = false } = {}) {
    const signals = [];
    const ts = typescript && src.length <= AST_LIMIT ? stripTypes(src) : null;
    const exactLines = !ts || ts.exactLines;
    const push = (kind, detail, line = 0, list = 0) => signals.push({ kind, detail: String(detail).slice(0, 120), line: exactLines ? line : 0, ...(list ? { list } : {}) });
    const exp = { names: new Set(), reexports: [], cjsTargets: [] };
    let obfuscatedIds = 0;
    let walletStrings = 0;
    let longEncoded = 0;
    const stats = { evalLike: false, envBulk: false, network: false };

    // Cheap whole-file checks first (work even when parsing fails).
    const obf = src.match(/\b_0x[0-9a-f]{4,6}\b/gi);
    if (obf && new Set(obf).size >= 15) push('obfuscation', `${new Set(obf).size} _0x-style identifiers`);
    const lines = src.split('\n');
    const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
    const minified = src.length > 3000 && (longest > 2000 && lines.length < src.length / 300);

    const ast = src.length <= AST_LIMIT && (!typescript || ts) ? parse(typescript ? ts.code : src) : null;
    if (!ast) {
        regexFallback(src, push);
        return { signals, exports: exp, parsed: false, minified };
    }

    const onString = (s, line, list = 0) => {
        scanString(s, (k, d) => push(k, d, line, list));
        if (WALLET_ADDRESS.test(s)) walletStrings++;
        if (s.length > 1500 && /^[A-Za-z0-9+/=\s]+$/.test(s.slice(0, 4000))) longEncoded++;
        else if (s.length > 1500 && /^(\\x[0-9a-f]{2}|[0-9a-f]{2}){500}/i.test(s)) longEncoded++;
    };

    const onModule = (name, line) => {
        const m = stripNodePrefix(name);
        const base = m.startsWith('@') ? m.split('/').slice(0, 2).join('/') : m.split('/')[0];
        if (NETWORK_MODULES_JS.has(base)) { push('network', `module ${base}`, line); stats.network = true; }
        if (SHELL_MODULES_JS.has(base)) push('shell', `module ${base}`, line);
        if (EVAL_MODULES_JS.has(base)) { push('eval', `module ${base}`, line); stats.evalLike = true; }
    };

    const shellCalls = new Map();
    const senders = new Map();
    const keyExfil = new Set();
    const pushKeyExfil = (detail, line) => { if (!keyExfil.has(detail)) { keyExfil.add(detail); push('key-exfil', detail, line); } };
    walk.fullAncestor(ast, (node, _state, ancestors) => {
        const line = node.loc?.start.line ?? 0;
        switch (node.type) {
            case 'Identifier':
                if (/^_0x[0-9a-f]{3,}$/i.test(node.name)) obfuscatedIds++;
                break;
            case 'Literal':
                if (typeof node.value === 'string') onString(node.value, line, isHostName(node.value) ? listSize(ancestors[ancestors.length - 2]) : 0);
                break;
            case 'TemplateElement':
                if (node.value.cooked) onString(node.value.cooked, line);
                break;
            case 'ImportDeclaration':
                if (typeof node.source.value === 'string') onModule(node.source.value, line);
                break;
            case 'ImportExpression': {
                const s = literalString(node.source);
                if (s) onModule(s, line); else push('dynamic-require', 'import(<computed>)', line);
                break;
            }
            case 'NewExpression':
            case 'CallExpression': {
                const callee = node.callee.type === 'ChainExpression' ? node.callee.expression : node.callee;
                const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? memberName(callee) : '';
                if (name === 'require' || name === 'module.require' || name === 'process.mainModule.require') {
                    const s = literalString(node.arguments[0]);
                    if (s) onModule(s, line);
                    else if (node.arguments.length) push('dynamic-require', 'require(<computed>)', line);
                } else if (name === 'eval' || name === 'window.eval' || name === 'globalThis.eval') {
                    const s = literalString(node.arguments[0]);
                    if (!(s && s.length < 40 && /^[\w.]+$/.test(s))) { push('eval', 'eval()', line); stats.evalLike = true; }
                    const dec = decoderIn(node.arguments);
                    if (dec) push('encoded-exec', `eval(${dec}(...))`, line);
                } else if (name === 'Function' || name === 'window.Function' || name === 'globalThis.Function') {
                    push('eval', `${node.type === 'NewExpression' ? 'new ' : ''}Function()`, line); stats.evalLike = true;
                    const dec = decoderIn(node.arguments);
                    if (dec) push('encoded-exec', `Function(${dec}(...))`, line);
                } else if (/(^|\.)(setTimeout|setInterval)$/.test(name) && literalString(node.arguments[0])?.length > 20) {
                    push('eval', `${name}(<string>)`, line); stats.evalLike = true;
                } else if (NETWORK_GLOBALS.has(name) || /^(window|globalThis|self|global)\.(fetch|XMLHttpRequest|WebSocket)$/.test(name) || name === 'navigator.sendBeacon') {
                    push('network', `${name.split('.').pop()}()`, line); stats.network = true;
                } else if (/(^|\.)(_compile|_load)$/.test(name) && /module|Module/.test(name)) {
                    push('eval', `${name}()`, line); stats.evalLike = true;
                } else if (/^process\.binding$|^process\.dlopen$/.test(name)) {
                    push('native-code', name, line);
                } else if (callee.type === 'MemberExpression' && SHELL_CALLS.has(name.split('.').pop()) && /child_process|cp\b|childProcess|proc/i.test(name)) {
                    push('shell', `${name.split('.').pop()}()`, line);
                }
                if (SHELL_CALLS.has(name.split('.').pop())) {
                    const inline = inlineIn(node.arguments, shellCalls);
                    shellCalls.set(node, inline);
                    if (inline) push('encoded-exec', `${name.split('.').pop()}() launched with inline code: ${inline}`, line);
                }
                // A request to a hard-coded address that carries key material, directly or through the
                // function the request is in ("Loader.addToQueue(secretKey)"; that function is checked after the walk).
                if (SEND_CALL.test(name)) {
                    const host = sendHost(node.arguments);
                    if (host) {
                        const call = `${name.split('.').pop()}()`;
                        const key = keyNameIn(node.arguments);
                        if (key) pushKeyExfil(`${call} sends ${key} to ${host}`, line);
                        const fn = enclosingName(ancestors);
                        if (fn && !senders.has(fn)) senders.set(fn, { call, host, line });
                    }
                }
                // whole-environment use: JSON.stringify(process.env), Object.entries(process.env), send(process.env)
                for (const a of node.arguments || []) {
                    if (a.type === 'MemberExpression' && memberName(a) === 'process.env') {
                        if (!/^(Object\.assign|Object\.create)$/.test(name)) { push('env-bulk', `${name || 'call'}(process.env)`, line); stats.envBulk = true; }
                    }
                }
                // Buffer.from(x, 'base64') / atob() fed straight into eval or Function
                if (stats.evalLike && /^(Buffer\.from|atob|window\.atob)$/.test(name)) {
                    const parentCall = ancestors.slice(0, -1).reverse().find((a) => a.type === 'CallExpression' || a.type === 'NewExpression');
                    const pn = parentCall && (parentCall.callee.type === 'Identifier' ? parentCall.callee.name : memberName(parentCall.callee));
                    if (pn && /^(eval|Function|.*\.runIn\w*Context|.*\.runInThisContext)$/.test(pn)) push('encoded-exec', `${pn}(${name}(...))`, line);
                }
                break;
            }
            case 'AssignmentExpression': {
                if (node.left.type === 'MemberExpression') {
                    const t = memberName(node.left);
                    if (HOOK_TARGETS.test(t)) push('global-hook', `${t} = ...`, line);
                    if (wantExports) {
                        if (t === 'module.exports') {
                            if (node.right.type === 'ObjectExpression') {
                                for (const p of node.right.properties) {
                                    if (p.type === 'Property' && !p.computed) exp.names.add(p.key.name ?? String(p.key.value));
                                }
                            } else if (node.right.type === 'CallExpression' && node.right.callee.name === 'require') {
                                const s = literalString(node.right.arguments[0]);
                                if (s) exp.cjsTargets.push(s);
                            } else {
                                exp.names.add('default');
                            }
                        } else {
                            const m = t.match(/^(?:module\.)?exports\.([\w$]+)$/);
                            if (m && m[1] !== '__esModule') exp.names.add(m[1]);
                        }
                    }
                }
                break;
            }
            case 'VariableDeclarator':
                if (node.init?.type === 'MemberExpression' && memberName(node.init) === 'process.env' && node.id.type === 'Identifier') {
                    push('env-bulk', `const ${node.id.name} = process.env`, line); stats.envBulk = true;
                }
                break;
            case 'MemberExpression': {
                const t = memberName(node);
                if (/^(window\.)?ethereum$/.test(t) && node.object.type !== 'Identifier') break;
                if (t === 'window.ethereum') push('crypto-wallet', 'window.ethereum', line);
                break;
            }
            case 'ExportNamedDeclaration':
                if (!wantExports) break;
                if (node.declaration) {
                    const d = node.declaration;
                    if (d.id?.name) exp.names.add(d.id.name);
                    for (const v of d.declarations || []) if (v.id.type === 'Identifier') exp.names.add(v.id.name);
                }
                if (node.source) {
                    exp.reexports.push({ from: node.source.value, names: node.specifiers.map((s) => s.exported.name ?? s.exported.value) });
                    onModule(node.source.value, line);
                } else {
                    for (const s of node.specifiers) exp.names.add(s.exported.name ?? s.exported.value);
                }
                break;
            case 'ExportDefaultDeclaration':
                if (wantExports) exp.names.add('default');
                break;
            case 'ExportAllDeclaration':
                if (wantExports) {
                    if (node.exported) exp.names.add(node.exported.name ?? node.exported.value);
                    else exp.reexports.push({ from: node.source.value, names: '*' });
                }
                break;
            default:
        }
        // tsc CommonJS: Object.defineProperty(exports, "x", ...) and __exportStar(require("./x"), exports)
        if (wantExports && node.type === 'CallExpression') {
            const n = node.callee.type === 'MemberExpression' ? memberName(node.callee) : node.callee.name;
            if (n === 'Object.defineProperty' && node.arguments[0]?.type === 'Identifier' && node.arguments[0].name === 'exports') {
                const s = literalString(node.arguments[1]);
                if (s && s !== '__esModule') exp.names.add(s);
            } else if (/(^|\.)__exportStar$|^__export$/.test(n || '')) {
                const r = node.arguments[0];
                if (r?.type === 'CallExpression' && r.callee.name === 'require') {
                    const s = literalString(r.arguments[0]);
                    if (s) exp.reexports.push({ from: s, names: '*' });
                }
            }
        }
    });

    if (senders.size) {
        walk.simple(ast, {
            CallExpression(node) {
                const callee = node.callee.type === 'ChainExpression' ? node.callee.expression : node.callee;
                const fn = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' && !callee.computed ? callee.property.name : '';
                const s = senders.get(fn);
                const key = s && keyNameIn(node.arguments);
                if (key) pushKeyExfil(`${s.call} sends ${key} to ${s.host} through ${fn}()`, s.line);
            },
        });
    }
    if (obfuscatedIds >= 40 && !signals.some((s) => s.kind === 'obfuscation')) push('obfuscation', `${obfuscatedIds} _0x-style identifier uses`);
    if (walletStrings >= 5) push('crypto-wallet', `${walletStrings} wallet-address-like strings`);
    if (longEncoded && stats.evalLike) push('encoded-exec', `${longEncoded} long encoded string(s) plus dynamic evaluation`);
    if (stats.envBulk && stats.network) push('secret-harvest', 'whole environment + network in one file');
    return { signals, exports: exp, parsed: true, minified };
}

// Inline code in a shell command. One pattern used to be
// /\beval\(|base64\s+-d|(curl|wget)\b[^|]{0,200}\|\s*(ba)?sh\b|powershell[^\n]*\s-e(nc|ncodedcommand)?\b|\bnode\s+-e\s|python[0-9.]*\s+-c\s/i;
// its powershell branch rescanned the rest of the line from every "powershell" on it, so the
// work grew with the square of a string's length. That branch is now found by encodedPowershell().
// Each branch begins with a different fixed word, so at most one can match at any index, and
// the leftmost match of the whole pattern is the leftmost of the two searches below.
const INLINE_CODE = /\beval\(|base64\s+-d|(curl|wget)\b[^|]{0,200}\|\s*(ba)?sh\b|\bnode\s+-e\s|python[0-9.]*\s+-c\s/i;

/** What the one combined pattern above matched in s, or null; linear in the length of s. */
export function inlineCode(s) {
    const other = s.match(INLINE_CODE);
    const ps = encodedPowershell(s, other ? other.index : s.length);
    return ps ?? (other ? other[0] : null);
}

/**
 * The match of that pattern's powershell[^\n]*\s-e(nc|ncodedcommand)?\b branch starting before
 * `stop`, or null.
 * Only the first "powershell" on a line can start it: any later one sees a part of the same rest.
 * Greedy [^\n]* makes it end at the last flag after that word, which may start at the line's
 * own \n. Each line is read once.
 */
function encodedPowershell(s, stop) {
    const word = /powershell/gi;
    const flagAt = /\s-e(nc|ncodedcommand)?\b/iy;
    for (let m; (m = word.exec(s)) && m.index < stop;) {
        const from = word.lastIndex;
        let eol = s.indexOf('\n', from);
        if (eol < 0) eol = s.length;
        let end = -1;
        flagAt.lastIndex = eol;
        const atEol = eol < s.length ? flagAt.exec(s) : null;
        if (atEol) end = eol + atEol[0].length;
        else for (const f of s.slice(from, eol).matchAll(/\s-e(nc|ncodedcommand)?\b/gi)) end = from + f.index + f[0].length;
        if (end >= 0) return s.slice(m.index, end);
        word.lastIndex = eol;
    }
    return null;
}

/**
 * Inline code in the first argument string that has any, in the walker's order. The scan walk
 * is post-order, so every shell call nested in these arguments already has its own result in
 * `shellCalls`: that result stands in for its arguments, and each string is read once per file.
 */
function inlineIn(args, shellCalls) {
    let found = null;
    const nested = (n, st, c) => {
        if (!shellCalls.has(n)) return walk.base[n.type](n, st, c);
        c(n.callee, st, 'Expression');
        found ??= shellCalls.get(n);
    };
    const visitors = {
        Literal(n) { if (found === null && typeof n.value === 'string') found = inlineCode(n.value); },
        TemplateElement(n) { if (found === null && n.value.cooked) found = inlineCode(n.value.cooked); },
        CallExpression: nested,
        NewExpression: nested,
    };
    for (const a of args || []) walk.recursive(a, null, visitors);
    return found;
}

const DECODERS = /^(Buffer\.from|atob|window\.atob|globalThis\.atob|decodeURIComponent|unescape|String\.fromCharCode|String\.fromCodePoint|.*\.toString)$/;

/** Name of a decoding call inside eval/Function arguments, if any. */
function decoderIn(args) {
    let found = null;
    for (const a of args || []) {
        walk.full(a, (n) => {
            if (found || (n.type !== 'CallExpression' && n.type !== 'NewExpression')) return;
            const nm = n.callee.type === 'Identifier' ? n.callee.name : n.callee.type === 'MemberExpression' ? memberName(n.callee) : '';
            if (DECODERS.test(nm) && !(nm.endsWith('.toString') && n.arguments.length === 0)) found = nm;
        });
    }
    return found;
}

function regexFallback(src, push) {
    const s = src.length > AST_LIMIT ? src.slice(0, AST_LIMIT) : src;
    for (const m of s.matchAll(/(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"]([^'"]+)['"]/g)) {
        const base = stripNodePrefix(m[1]).split('/')[0];
        if (NETWORK_MODULES_JS.has(base)) push('network', `module ${base}`);
        if (SHELL_MODULES_JS.has(base)) push('shell', `module ${base}`);
        if (EVAL_MODULES_JS.has(base)) push('eval', `module ${base}`);
    }
    if (/\beval\s*\(/.test(s)) push('eval', 'eval()');
    if (/\bnew\s+Function\s*\(/.test(s)) push('eval', 'new Function()');
    if (/\bfetch\s*\(/.test(s)) push('network', 'fetch()');
    if (/JSON\.stringify\s*\(\s*process\.env\s*\)/.test(s)) push('env-bulk', 'JSON.stringify(process.env)');
    for (const m of s.matchAll(/(['"`])((?:(?!\1)[^\\\n]|\\.){4,2000})\1/g)) scanString(m[2], (k, d) => push(k, d));
}

/**
 * Exported names from a TypeScript declaration file (regex based).
 */
export function scanDts(src) {
    const names = new Set();
    const reexports = [];
    const body = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    // `^` then white space without line breaks: with /m every position of a run of blank lines
    // starts a line, and \s* re-read the rest of the run from each one.
    for (const m of body.matchAll(/^[^\S\n\r\u2028\u2029]*export\s+(?:declare\s+)?(?:default\s+)?(?:abstract\s+)?(?:async\s+)?(function\*?|class|const|let|var|interface|type|enum|namespace|module)\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[2]);
    if (/^[^\S\n\r\u2028\u2029]*export\s+default\b/m.test(body)) names.add('default');
    for (const m of body.matchAll(/export\s+(type\s+)?\{([^}]*)\}\s*(?:from\s*['"]([^'"]+)['"])?/g)) {
        // (?<!\s): a separator starts only where its white space starts, as the first match always
        // does; otherwise each position of a long run is tried and fails after reading the rest.
        const list = m[2].split(',').map((x) => x.trim()).filter(Boolean).map((x) => x.replace(/^type\s+/, '').split(/(?<!\s)\s+as\s+/).pop().trim());
        if (m[3]) reexports.push({ from: m[3], names: list });
        else list.forEach((n) => names.add(n));
    }
    for (const m of body.matchAll(/export\s+\*\s+(?:as\s+([\w$]+)\s+)?from\s*['"]([^'"]+)['"]/g)) {
        if (m[1]) names.add(m[1]); else reexports.push({ from: m[2], names: '*' });
    }
    for (const m of body.matchAll(/export\s*=\s*([\w$]+)/g)) names.add(`=${m[1]}`);
    return { names, reexports, cjsTargets: [] };
}

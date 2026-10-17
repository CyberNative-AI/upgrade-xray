// Static scan of one JavaScript file: capabilities, indicators and exported names.
// The code is parsed, never run.
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import * as nodeModule from 'node:module';
import {
    NETWORK_MODULES_JS, SHELL_MODULES_JS, EVAL_MODULES_JS, WALLET_ADDRESS, scanString, stripNodePrefix,
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
                    const inline = stringsIn(node.arguments).find((x) => INLINE_CODE.test(x));
                    if (inline) push('encoded-exec', `${name.split('.').pop()}() launched with inline code: ${inline.match(INLINE_CODE)[0]}`, line);
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

    if (obfuscatedIds >= 40 && !signals.some((s) => s.kind === 'obfuscation')) push('obfuscation', `${obfuscatedIds} _0x-style identifier uses`);
    if (walletStrings >= 5) push('crypto-wallet', `${walletStrings} wallet-address-like strings`);
    if (longEncoded && stats.evalLike) push('encoded-exec', `${longEncoded} long encoded string(s) plus dynamic evaluation`);
    if (stats.envBulk && stats.network) push('secret-harvest', 'whole environment + network in one file');
    return { signals, exports: exp, parsed: true, minified };
}

const INLINE_CODE = /\beval\(|base64\s+-d|(curl|wget)\b[^|]{0,200}\|\s*(ba)?sh\b|powershell[^\n]*\s-e(nc|ncodedcommand)?\b|\bnode\s+-e\s|python[0-9.]*\s+-c\s/i;

function stringsIn(args) {
    const out = [];
    for (const a of args || []) {
        walk.full(a, (n) => {
            if (n.type === 'Literal' && typeof n.value === 'string') out.push(n.value);
            else if (n.type === 'TemplateElement' && n.value.cooked) out.push(n.value.cooked);
        });
    }
    return out;
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
    for (const m of body.matchAll(/^\s*export\s+(?:declare\s+)?(?:default\s+)?(?:abstract\s+)?(?:async\s+)?(function\*?|class|const|let|var|interface|type|enum|namespace|module)\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[2]);
    if (/^\s*export\s+default\b/m.test(body)) names.add('default');
    for (const m of body.matchAll(/export\s+(type\s+)?\{([^}]*)\}\s*(?:from\s*['"]([^'"]+)['"])?/g)) {
        const list = m[2].split(',').map((x) => x.trim()).filter(Boolean).map((x) => x.replace(/^type\s+/, '').split(/\s+as\s+/).pop().trim());
        if (m[3]) reexports.push({ from: m[3], names: list });
        else list.forEach((n) => names.add(n));
    }
    for (const m of body.matchAll(/export\s+\*\s+(?:as\s+([\w$]+)\s+)?from\s*['"]([^'"]+)['"]/g)) {
        if (m[1]) names.add(m[1]); else reexports.push({ from: m[2], names: '*' });
    }
    for (const m of body.matchAll(/export\s*=\s*([\w$]+)/g)) names.add(`=${m[1]}`);
    return { names, reexports, cjsTargets: [] };
}

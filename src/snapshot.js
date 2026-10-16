// Build a static "snapshot" of one published package version from its files.
import crypto from 'node:crypto';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse as parseToml } from 'smol-toml';
import { scanJs, scanDts, AST_LIMIT as JS_AST_LIMIT } from './js-scan.js';
import { scanString, scanSourceText } from './signals.js';
import { addNote, mark as v } from './prose.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const JS_EXT = /\.(c|m)?jsx?$|\.(c|m)?tsx?$/i;
const PY_EXT = /\.pyw?$/i;
const NPM_LIFECYCLE = ['preinstall', 'install', 'postinstall'];
const SKIP_DIR = /(^|\/)(__tests__|__mocks__)\//;

export const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function binaryKind(buf) {
    if (buf.length < 4) return null;
    if (buf[0] === 0x7f && buf.toString('latin1', 1, 4) === 'ELF') return 'ELF executable';
    if (buf[0] === 0x4d && buf[1] === 0x5a) return 'Windows PE executable';
    const m = buf.readUInt32BE(0);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(m)) return 'Mach-O executable';
    return null;
}

function isText(buf) {
    const n = Math.min(buf.length, 8000);
    for (let i = 0; i < n; i++) if (buf[i] === 0) return false;
    return true;
}

/** Run the Python helper over many files in one process. Cache by content hash. */
const pyCache = new Map();
export async function scanPython(files, exportPaths = new Set()) {
    const todo = [];
    const out = {};
    for (const f of files) {
        const key = `${f.hash}:${exportPaths.has(f.path) ? 1 : 0}`;
        if (pyCache.has(key)) out[f.path] = pyCache.get(key);
        else todo.push({ ...f, key });
    }
    for (let i = 0; i < todo.length; i += 400) {
        const batch = todo.slice(i, i + 400);
        const req = JSON.stringify({ files: batch.map((f) => ({ path: f.path, source: f.source })), exports: batch.filter((f) => exportPaths.has(f.path)).map((f) => f.path) });
        const res = await runPython(req);
        for (const f of batch) {
            const r = res.results[f.path] || { signals: [], strings: [], parsed: false };
            pyCache.set(f.key, r);
            out[f.path] = r;
        }
    }
    if (pyCache.size > 20000) pyCache.clear();
    return out;
}

function runPython(input) {
    return new Promise((resolve, reject) => {
        const p = spawn(process.env.PYTHON || 'python3', ['-I', path.join(HERE, 'py_scan.py')], { stdio: ['pipe', 'pipe', 'pipe'] });
        const chunks = [];
        let err = '';
        const timer = setTimeout(() => p.kill('SIGKILL'), 120000);
        p.stdout.on('data', (d) => chunks.push(d));
        p.stderr.on('data', (d) => { err += d; });
        p.on('error', reject);
        p.on('close', (code) => {
            clearTimeout(timer);
            if (code !== 0) return reject(new Error(`python scanner exited ${code}: ${err.slice(0, 300)}`));
            try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); }
        });
        p.stdin.end(input);
    });
}

const jsCache = new Map();
function scanJsCached(hash, src, opts) {
    if (jsCache.has(hash)) return jsCache.get(hash);
    let r;
    try { r = scanJs(src, opts); } catch (e) { r = { signals: [], exports: { names: new Set(), reexports: [], cjsTargets: [] }, parsed: false, error: e.message }; }
    jsCache.set(hash, r);
    if (jsCache.size > 20000) jsCache.clear();
    return r;
}

const MAX_COVERAGE_ITEMS = 20;

/** Record a file that was skipped or only pattern-scanned, so "nothing new found" is never silent about it. */
function gap(snap, list, file, reason) {
    const c = snap.coverage;
    c[`${list}Count`]++;
    c.complete = false;
    if (c[list].length < MAX_COVERAGE_ITEMS) c[list].push({ file, reason });
}

/** Skip files the archive reader could not or would not extract. Returns true when skipped. */
function skipUnread(snap, p, buf) {
    if (buf.oversize) { gap(snap, 'skippedFiles', p, `${buf.oversize} bytes, above the per-file limit`); addNote(snap, `${v(p)} skipped (${v(buf.oversize)} bytes)`); return true; }
    if (buf.encrypted) { gap(snap, 'skippedFiles', p, 'encrypted'); addNote(snap, `${v(p)} skipped (encrypted)`); return true; }
    if (buf.unsupported !== undefined) { gap(snap, 'skippedFiles', p, `unsupported compression method ${buf.unsupported}`); addNote(snap, `${v(p)} skipped (compression method ${v(buf.unsupported)})`); return true; }
    return false;
}

const newCoverage = () => ({ complete: true, unparsedFiles: [], unparsedFilesCount: 0, skippedFiles: [], skippedFilesCount: 0 });

function addSignals(snap, file, list) {
    for (const s of list) snap.signals.push({ ...s, file });
}

function installScriptFiles(cmd) {
    const out = [];
    for (const m of String(cmd).matchAll(/(?:^|[\s;&|])(?:node|nodejs|bun|deno run|sh|bash|python3?)\s+(?:-[\w-]+\s+)*["']?([\w./@-]+\.(?:c|m)?js|[\w./@-]+\.sh|[\w./@-]+\.py|[\w./@-]+)["']?/g)) {
        out.push(m[1].replace(/^\.\//, ''));
    }
    return out;
}

function resolveInPkg(files, from, spec) {
    if (!spec.startsWith('.')) return null;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), spec));
    for (const c of [base, `${base}.js`, `${base}.cjs`, `${base}.mjs`, `${base}/index.js`, `${base}/index.cjs`, `${base}/index.mjs`, base.replace(/\.js$/, '.ts'), `${base}.d.ts`, base.replace(/\.(c|m)?js$/, '.d.ts'), `${base}/index.d.ts`]) {
        if (files.has(c)) return c;
    }
    return null;
}

function pickTarget(v, conds) {
    if (typeof v === 'string') return v;
    if (Array.isArray(v)) { for (const x of v) { const t = pickTarget(x, conds); if (t) return t; } return null; }
    if (v && typeof v === 'object') {
        for (const c of conds) if (c in v) { const t = pickTarget(v[c], conds); if (t) return t; }
    }
    return null;
}

function npmEntryPoints(pkg) {
    const entries = {}; // subpath -> {js, dts}
    const ex = pkg.exports;
    const jsConds = ['node', 'require', 'import', 'module', 'default'];
    const dtsConds = ['types', 'typings', 'node', 'require', 'import', 'default'];
    if (ex && typeof ex === 'object' && !Array.isArray(ex) && Object.keys(ex).some((k) => k.startsWith('.'))) {
        for (const [k, v] of Object.entries(ex)) {
            if (k.includes('*') || k.endsWith('/') || k === './package.json') continue;
            entries[k] = { js: pickTarget(v, jsConds), dts: pickTarget(v, ['types', 'typings']) || null };
        }
    } else if (ex) {
        entries['.'] = { js: pickTarget(ex, jsConds), dts: pickTarget(ex, dtsConds.slice(0, 2)) };
    } else {
        entries['.'] = { js: pkg.main || 'index.js', dts: pkg.types || pkg.typings || null };
    }
    for (const e of Object.values(entries)) {
        if (e.js) e.js = e.js.replace(/^\.\//, '');
        if (e.dts) e.dts = e.dts.replace(/^\.\//, '');
    }
    return entries;
}

function collectExports(files, start, getScan, depth = 0, seen = new Set()) {
    const names = new Set();
    if (!start || seen.has(start) || depth > 6) return names;
    seen.add(start);
    const r = getScan(start);
    if (!r) return names;
    for (const n of r.names) names.add(n);
    for (const re of r.reexports) {
        const target = resolveInPkg(files, start, re.from);
        if (re.names === '*') {
            if (target) for (const n of collectExports(files, target, getScan, depth + 1, seen)) if (n !== 'default') names.add(n);
        } else re.names.forEach((n) => names.add(n));
    }
    for (const t of r.cjsTargets || []) {
        const target = resolveInPkg(files, start, t);
        if (target) for (const n of collectExports(files, target, getScan, depth + 1, seen)) names.add(n);
    }
    return names;
}

/** Snapshot of an npm package version from its tarball files (root = package/ stripped). */
export async function npmSnapshot(files) {
    const snap = { ecosystem: 'npm', files: new Map(), signals: [], installScripts: {}, installFiles: new Set(), deps: {}, api: {}, meta: {}, notes: [], coverage: newCoverage() };
    let pkg = {};
    if (files.has('package.json')) {
        try { pkg = JSON.parse(files.get('package.json').toString('utf8')); } catch { addNote(snap, 'package.json is not valid JSON'); }
    } else addNote(snap, 'no package.json in the published tarball');
    snap.meta = {
        name: pkg.name, version: pkg.version, type: pkg.type || 'commonjs', engines: pkg.engines?.node || null,
        bin: typeof pkg.bin === 'string' ? { [pkg.name]: pkg.bin } : pkg.bin || {},
        exportsKeys: pkg.exports && typeof pkg.exports === 'object' && !Array.isArray(pkg.exports) ? Object.keys(pkg.exports).filter((k) => k.startsWith('.')) : null,
        main: pkg.main || null,
    };
    for (const k of NPM_LIFECYCLE) if (pkg.scripts?.[k]) snap.installScripts[k] = String(pkg.scripts[k]);
    if (files.has('binding.gyp') && !snap.installScripts.install && !snap.installScripts.preinstall) snap.installScripts['install (implicit node-gyp rebuild)'] = 'node-gyp rebuild';
    for (const cmd of Object.values(snap.installScripts)) for (const f of installScriptFiles(cmd)) {
        const r = resolveInPkg(files, 'package.json', `./${f}`) || (files.has(f) ? f : null);
        if (r) snap.installFiles.add(r);
    }
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
        for (const [n, v] of Object.entries(pkg[field] || {})) {
            if (field === 'peerDependencies' && pkg.peerDependenciesMeta?.[n]?.optional) continue;
            snap.deps[n] = { spec: String(v), field };
        }
    }
    for (const n of [].concat(pkg.bundleDependencies || pkg.bundledDependencies || [])) if (typeof n === 'string' && snap.deps[n]) snap.deps[n].bundled = true;
    for (const s of Object.values(snap.installScripts)) scanString(s, (k, d) => snap.signals.push({ kind: k, detail: d, file: 'package.json', line: 0 }));

    const binFiles = new Set(Object.values(snap.meta.bin).map((b) => String(b).replace(/^\.\//, '')));
    const dtsScans = new Map();
    const jsScans = new Map();
    for (const [p, buf] of files) {
        const h = sha(buf);
        snap.files.set(p, { size: buf.oversize || buf.length, hash: h });
        if (skipUnread(snap, p, buf)) continue;
        const bk = binaryKind(buf);
        if (bk) { snap.signals.push({ kind: 'binary-executable', detail: bk, file: p, line: 0 }); continue; }
        if (/\.(node|so|dll|dylib|wasm)$/i.test(p)) { snap.signals.push({ kind: 'native-code', detail: path.extname(p).toLowerCase(), file: p, line: 0 }); continue; }
        if (/\.d\.(c|m)?ts$/.test(p)) { dtsScans.set(p, scanDts(buf.toString('utf8'))); continue; }
        if (SKIP_DIR.test(p) && !snap.installFiles.has(p)) continue;
        if (JS_EXT.test(p) || binFiles.has(p) || snap.installFiles.has(p) || (isText(buf) && buf.toString('latin1', 0, 30).startsWith('#!/usr/bin/env node'))) {
            if (!isText(buf)) continue;
            const text = buf.toString('utf8');
            const r = scanJsCached(h, text, { wantExports: true });
            jsScans.set(p, r);
            if (!r.parsed) gap(snap, 'unparsedFiles', p, r.error ? `not parsed (${String(r.error).slice(0, 80)}); pattern scan only` : /\.(c|m)?tsx?$/i.test(p) ? 'TypeScript source; pattern scan only' : text.length > JS_AST_LIMIT ? 'above the 6 MB parser limit; pattern scan only' : 'not parsed; pattern scan only');
            addSignals(snap, p, r.signals);
            scanSourceText(text, (k, d, line) => snap.signals.push({ kind: k, detail: d, file: p, line }));
            if (r.minified && buf.length > 50000 && !/\.min\.(c|m)?js$|[/.-](dist|umd|bundle|browser|esm|cjs)[/.-]/i.test(p)) snap.signals.push({ kind: 'minified-blob', detail: p, file: p, line: 0 });
        } else if (/\.(sh|bat|cmd|ps1)$/i.test(p) && isText(buf)) {
            const t = buf.toString('utf8');
            if (/\b(curl|wget|Invoke-WebRequest|iwr)\b/.test(t)) snap.signals.push({ kind: 'network', detail: `script ${path.extname(p)} downloads`, file: p, line: 0 });
            scanString(t, (k, d) => snap.signals.push({ kind: k, detail: d, file: p, line: 0 }));
        }
    }
    // Exported API per entry point
    const getScan = (p) => (p.endsWith('.ts') && dtsScans.get(p)) || (jsScans.get(p) && jsScans.get(p).exports) || null;
    for (const [sub, e] of Object.entries(npmEntryPoints(pkg))) {
        const js = e.js && (files.has(e.js) ? e.js : resolveInPkg(files, 'package.json', `./${e.js}`));
        const dtsGuess = e.dts || (js ? js.replace(/\.(c|m)?js$/, '.d.ts') : null);
        const dts = dtsGuess && files.has(dtsGuess) ? dtsGuess : null;
        const names = new Set([...collectExports(files, js, getScan), ...collectExports(files, dts, getScan)]);
        snap.api[sub] = { names, resolved: Boolean(js || dts), source: [js, dts].filter(Boolean) };
    }
    return snap;
}

function normPy(n) { return n.toLowerCase().replace(/[-_.]+/g, '-'); }

function parseRequiresDist(text) {
    const deps = {};
    for (const line of text.split('\n')) {
        const m = line.match(/^Requires-Dist:\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
        if (m) {
            const extra = /extra\s*==/.test(m[3]);
            const k = normPy(m[1]);
            if (!deps[k] || !extra) deps[k] = { spec: m[3].trim(), field: extra ? 'extra' : 'requires' };
        }
    }
    return deps;
}

function pyDepsFromSpecList(list, field = 'requires') {
    const deps = {};
    for (const s of list || []) {
        const m = String(s).match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
        if (m) deps[normPy(m[1])] = { spec: m[3].trim(), field };
    }
    return deps;
}

/** Snapshot of a PyPI distribution (wheel or sdist), root directory stripped. */
export async function pypiSnapshot(files, kind) {
    const snap = { ecosystem: 'pypi', kind, files: new Map(), signals: [], installScripts: {}, installFiles: new Set(), deps: {}, api: {}, meta: {}, notes: [], coverage: newCoverage() };
    const pyFiles = [];
    let metadataText = '';
    let pyproject = null;
    for (const [p, buf] of files) {
        const h = sha(buf);
        snap.files.set(p, { size: buf.oversize || buf.length, hash: h });
        if (skipUnread(snap, p, buf)) continue;
        if (/\.dist-info\/METADATA$/.test(p) || p === 'PKG-INFO') metadataText = metadataText || buf.toString('utf8');
        if (p === 'pyproject.toml') { try { pyproject = parseToml(buf.toString('utf8')); } catch { addNote(snap, 'pyproject.toml did not parse'); } }
        const bk = binaryKind(buf);
        if (bk) { snap.signals.push({ kind: 'binary-executable', detail: bk, file: p, line: 0 }); continue; }
        if (/\.(so|pyd|dll|dylib|wasm)$/i.test(p) || /\.so\.\d/.test(p)) { snap.signals.push({ kind: 'native-code', detail: path.extname(p).toLowerCase(), file: p, line: 0 }); continue; }
        if (/\.pth$/i.test(p) && !p.includes('/')) {
            const t = buf.toString('utf8');
            if (/^\s*import[\s;]/m.test(t)) {
                snap.signals.push({ kind: 'startup-hook', detail: `${p} (runs at every Python start-up)`, file: p, line: 0 });
                pyFiles.push({ path: p, source: t.split('\n').filter((l) => /^\s*import[\s;]/.test(l)).join('\n'), hash: sha(buf) });
                snap.installFiles.add(p);
            }
            continue;
        }
        if (/(^|\/)(sitecustomize|usercustomize)\.py$/.test(p) && p.split('/').length <= 2) {
            snap.signals.push({ kind: 'startup-hook', detail: `${path.basename(p)} (runs at every Python start-up)`, file: p, line: 0 });
            snap.installFiles.add(p);
        }
        if (PY_EXT.test(p) && isText(buf)) pyFiles.push({ path: p, source: buf.toString('utf8'), hash: h });
        else if (/\.(sh|bat|ps1)$/i.test(p) && isText(buf)) scanString(buf.toString('utf8'), (k, d) => snap.signals.push({ kind: k, detail: d, file: p, line: 0 }));
    }
    // Install-time code (sdist only): setup.py and an in-tree build backend
    if (kind === 'sdist') {
        if (files.has('setup.py')) {
            snap.installFiles.add('setup.py');
            const t = files.get('setup.py').toString('utf8');
            if (/cmdclass\s*=/.test(t)) snap.installScripts['setup.py cmdclass'] = (t.match(/cmdclass\s*=\s*([^\n]{0,120})/) || [])[1] || 'custom commands';
            const cls = [...t.matchAll(/class\s+(\w+)\s*\(\s*([\w.]*(install|develop|egg_info|build_py|build_ext|sdist|bdist_wheel)\w*)\s*\)/g)].map((m) => `${m[1]}(${m[2]})`);
            if (cls.length) snap.installScripts['setup.py command classes'] = cls.sort().join(', ');
        }
        const bs = pyproject?.['build-system'];
        if (bs?.['backend-path']) {
            snap.installScripts['in-tree build backend'] = `${bs['build-backend']} from ${[].concat(bs['backend-path']).join(',')}`;
            const mod = String(bs['build-backend'] || '').split(':')[0].replace(/\./g, '/');
            for (const bp of [].concat(bs['backend-path'])) for (const c of [`${bp}/${mod}.py`, `${bp}/${mod}/__init__.py`].map((x) => x.replace(/^\.\//, ''))) if (files.has(c)) snap.installFiles.add(c);
        }
        if (bs) snap.meta.buildBackend = bs['build-backend'] || null;
    }
    // Dependencies
    if (metadataText) {
        snap.deps = parseRequiresDist(metadataText);
        snap.meta.requiresPython = (metadataText.match(/^Requires-Python:\s*(.+)$/m) || [])[1] || null;
        snap.meta.name = (metadataText.match(/^Name:\s*(.+)$/m) || [])[1] || null;
        snap.meta.version = (metadataText.match(/^Version:\s*(.+)$/m) || [])[1] || null;
    }
    if (!Object.keys(snap.deps).length && pyproject?.project?.dependencies) {
        snap.deps = pyDepsFromSpecList(pyproject.project.dependencies);
        for (const [ex, list] of Object.entries(pyproject.project['optional-dependencies'] || {})) for (const [k, v] of Object.entries(pyDepsFromSpecList(list, 'extra'))) if (!snap.deps[k]) snap.deps[k] = { ...v, extra: ex };
        snap.meta.requiresPython = snap.meta.requiresPython || pyproject.project['requires-python'] || null;
    }
    if (!Object.keys(snap.deps).length && pyproject?.tool?.poetry?.dependencies) {
        for (const [k, v] of Object.entries(pyproject.tool.poetry.dependencies)) if (k !== 'python') snap.deps[normPy(k)] = { spec: typeof v === 'string' ? v : JSON.stringify(v), field: 'requires' };
    }
    if (!Object.keys(snap.deps).length && files.has('setup.py')) {
        const m = files.get('setup.py').toString('utf8').match(/install_requires\s*=\s*\[([^\]]*)\]/);
        if (m) snap.deps = pyDepsFromSpecList([...m[1].matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]));
    }
    // Public API: modules inside importable packages
    const modules = new Map(); // dotted -> path
    for (const f of pyFiles) {
        if (!/\.py$/.test(f.path)) continue;
        let rel = f.path.replace(/^src\//, '');
        if (/(^|\/)(tests?|testing|docs?|examples?|benchmarks?|scripts)\//.test(rel) || /\.(dist|egg)-info\//.test(rel) || rel === 'setup.py' || rel === 'conftest.py') continue;
        const parts = rel.replace(/\.py$/, '').split('/');
        if (parts[parts.length - 1] === '__init__') parts.pop();
        if (!parts.length || parts.some((x) => x.startsWith('_') || !/^[A-Za-z_]\w*$/.test(x))) continue;
        const dir = f.path.split('/').slice(0, -1).join('/');
        if (parts.length > 1 && !files.has(`${dir}/__init__.py`) && !rel.endsWith('__init__.py')) continue;
        modules.set(parts.join('.'), f.path);
    }
    const exportPaths = new Set(modules.values());
    const res = pyFiles.length ? await scanPython(pyFiles, exportPaths) : {};
    for (const f of pyFiles) {
        const r = res[f.path];
        if (!r) continue;
        if (!r.parsed) gap(snap, 'unparsedFiles', f.path, `Python source not parsed${r.error ? ` (${r.error})` : ''}; pattern scan only`);
        addSignals(snap, f.path, r.signals);
        scanSourceText(f.source, (k, d, line) => snap.signals.push({ kind: k, detail: d, file: f.path, line }));
        for (const s of r.strings || []) scanString(s, (k, d) => snap.signals.push({ kind: k, detail: d, file: f.path, line: 0 }));
    }
    for (const [mod, p] of modules) {
        const r = res[p];
        if (r?.exports) snap.api[mod] = { names: new Set(r.exports), resolved: true, source: [p] };
    }
    return snap;
}

export { normPy };

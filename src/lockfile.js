// Parse npm, pnpm, uv and poetry lockfiles and list the package versions that changed.
import YAML from 'yaml';
import { parse as parseToml } from 'smol-toml';
import semver from 'semver';

export class LockfileError extends Error {}

export function detectType(text, hint = '') {
    const h = hint.toLowerCase();
    if (/package-lock\.json|npm-shrinkwrap\.json/.test(h)) return 'npm';
    if (/pnpm-lock\.ya?ml/.test(h)) return 'pnpm';
    if (/uv\.lock/.test(h)) return 'uv';
    if (/poetry\.lock/.test(h)) return 'poetry';
    const t = text.trimStart();
    if (t.startsWith('{')) return 'npm';
    if (/^lockfileVersion:\s*['"]?\d/m.test(text)) return 'pnpm';
    if (/^\[\[package\]\]/m.test(text)) {
        if (/^revision\s*=|^requires-python\s*=/m.test(text) || /source\s*=\s*\{\s*(registry|editable|virtual)\s*=/.test(text)) return 'uv';
        return 'poetry';
    }
    throw new LockfileError('could not recognise the lockfile format (supported: package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, uv.lock, poetry.lock)');
}

const ecosystemOf = (type) => (type === 'npm' || type === 'pnpm' ? 'npm' : 'pypi');

function addVer(map, name, version, extra) {
    if (!name || !version) return;
    if (!map.has(name)) map.set(name, new Map());
    map.get(name).set(version, extra || {});
}

function parseNpm(text) {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { throw new LockfileError(`package-lock.json is not valid JSON: ${e.message}`); }
    const map = new Map();
    if (doc.packages) {
        for (const [p, v] of Object.entries(doc.packages)) {
            if (!p || v.link || !p.includes('node_modules/')) continue;
            const name = v.name || p.slice(p.lastIndexOf('node_modules/') + 'node_modules/'.length);
            const registry = !v.resolved || (/^https?:\/\/[^/]+\/.*\.tgz(#.*)?$/.test(v.resolved) && !/codeload\.github|gitlab\.com|bitbucket\.org/.test(v.resolved));
            addVer(map, name, v.version, { resolved: v.resolved, registry, dev: Boolean(v.dev) });
        }
    } else if (doc.dependencies) {
        const walk = (deps) => {
            for (const [n, v] of Object.entries(deps || {})) {
                addVer(map, n, v.version, { resolved: v.resolved, registry: !v.resolved || /registry/.test(v.resolved), dev: Boolean(v.dev) });
                walk(v.dependencies);
            }
        };
        walk(doc.dependencies);
    }
    return map;
}

function parsePnpmKey(key) {
    let k = key.replace(/^\//, '');
    k = k.replace(/\(.*$/, ''); // v6+/v9 peer suffix
    // v5: /name/1.2.3_peer
    const v5 = k.match(/^((?:@[^/]+\/)?[^/@]+)\/(\d[^/_]*)(?:_.*)?$/);
    if (v5) return [v5[1], v5[2]];
    const at = k.lastIndexOf('@');
    if (at <= 0) return [null, null];
    return [k.slice(0, at), k.slice(at + 1).replace(/_.*$/, '')];
}

function parsePnpm(text) {
    let doc;
    try { doc = YAML.parse(text, { maxAliasCount: 10000 }); } catch (e) { throw new LockfileError(`pnpm-lock.yaml did not parse: ${e.message}`); }
    const map = new Map();
    for (const [key, v] of Object.entries({ ...(doc?.packages || {}) })) {
        const [name, version] = parsePnpmKey(key);
        const tarball = v?.resolution?.tarball;
        const registry = !tarball || /registry/.test(tarball);
        const realVersion = v?.version && !/^\d/.test(version) ? v.version : version;
        if (name && /^\d/.test(realVersion || '')) addVer(map, v?.name || name, realVersion, { registry, dev: Boolean(v?.dev) });
    }
    return map;
}

function parseToml2(text, label) {
    try { return parseToml(text); } catch (e) { throw new LockfileError(`${label} did not parse: ${e.message}`); }
}

const normPy = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

function parseUv(text) {
    const doc = parseToml2(text, 'uv.lock');
    const map = new Map();
    for (const p of doc.package || []) {
        const src = p.source || {};
        if (src.editable || src.virtual || src.path || src.directory) continue; // the project itself / local paths
        addVer(map, normPy(p.name), p.version, { registry: Boolean(src.registry), source: src.git || src.url || src.registry || null });
    }
    return map;
}

function parsePoetry(text) {
    const doc = parseToml2(text, 'poetry.lock');
    const map = new Map();
    for (const p of doc.package || []) {
        const src = p.source || {};
        if (src.type === 'directory' || src.type === 'file') continue;
        addVer(map, normPy(p.name), p.version, { registry: !src.type || src.type === 'legacy', source: src.url || null });
    }
    return map;
}

export function parseLockfile(text, hint = '') {
    const type = detectType(text, hint);
    const map = type === 'npm' ? parseNpm(text) : type === 'pnpm' ? parsePnpm(text) : type === 'uv' ? parseUv(text) : parsePoetry(text);
    return { type, ecosystem: ecosystemOf(type), packages: map };
}

function cmpVersions(ecosystem, a, b) {
    if (ecosystem === 'npm' && semver.valid(a) && semver.valid(b)) return semver.compare(a, b);
    const pa = a.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
    const pb = b.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const x = pa[i] ?? 0; const y = pb[i] ?? 0;
        if (x === y) continue;
        if (typeof x === 'number' && typeof y === 'number') return x - y;
        return String(x) < String(y) ? -1 : 1;
    }
    return 0;
}

/**
 * Compare two parsed lockfiles. Returns { updated: [{name, from, to}], added: [{name, to}], removed: [{name, from}], nonRegistry: [...] }
 */
export function diffLockfiles(before, after) {
    if (before.ecosystem !== after.ecosystem) throw new LockfileError(`lockfiles are for different ecosystems (${before.type} vs ${after.type})`);
    const eco = after.ecosystem;
    const updated = []; const added = []; const removed = []; const nonRegistry = [];
    for (const [name, vers] of after.packages) {
        const old = before.packages.get(name);
        for (const [v, meta] of vers) {
            if (old?.has(v)) continue;
            if (meta.registry === false) { nonRegistry.push({ name, to: v, source: meta.source || meta.resolved || 'non-registry' }); continue; }
            if (old && old.size) {
                const olds = [...old.keys()].sort((a, b) => cmpVersions(eco, a, b));
                const lower = olds.filter((o) => cmpVersions(eco, o, v) < 0);
                const from = lower.length ? lower[lower.length - 1] : olds[0];
                updated.push({ name, from, to: v, dev: Boolean(meta.dev) });
            } else added.push({ name, to: v, dev: Boolean(meta.dev) });
        }
    }
    for (const [name, vers] of before.packages) {
        const now = after.packages.get(name);
        for (const v of vers.keys()) if (!now?.has(v) && !(now && now.size)) removed.push({ name, from: v });
    }
    const byName = (a, b) => a.name.localeCompare(b.name);
    return { ecosystem: eco, type: after.type, updated: updated.sort(byName), added: added.sort(byName), removed: removed.sort(byName), nonRegistry };
}

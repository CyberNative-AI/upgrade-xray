// Parse npm, pnpm, uv and poetry lockfiles and pip requirements files, and list the package versions that changed.
import YAML from 'yaml';
import { parse as parseToml } from 'smol-toml';
import semver from 'semver';

export class LockfileError extends Error {}

// Only packages whose recorded origin is one of the public registries are looked up.
// Private registries, git, URLs, local paths and entries with no recorded origin are listed,
// and their names are not sent anywhere. Entries with no recorded origin can be looked up only
// when the caller confirms that they come from the public registry (assumePublic).
const PUBLIC_HOSTS = {
    npm: new Set(['registry.npmjs.org', 'registry.yarnpkg.com']),
    pypi: new Set(['pypi.org', 'files.pythonhosted.org']),
};

/** Classify a recorded origin: 'public' | 'private' | 'git' | 'local' | 'url' | 'unknown'. */
export function classifyOrigin(raw, ecosystem) {
    if (raw === undefined || raw === null || raw === '') return 'unknown';
    const s = String(raw).trim();
    if (/^(git\+|git:|github:|gitlab:|bitbucket:|gist:)/i.test(s) || /\.git(#|$)/i.test(s)) return 'git';
    if (/^(file:|link:|workspace:|\.{0,2}\/|~\/)/i.test(s)) return 'local';
    let u;
    try { u = new URL(s); } catch { return 'url'; }
    if (u.protocol !== 'https:' || u.username || u.password || u.port) return 'private';
    return PUBLIC_HOSTS[ecosystem].has(u.hostname.toLowerCase()) ? 'public' : 'private';
}

export function detectType(text, hint = '') {
    const h = hint.toLowerCase();
    if (/package-lock\.json|npm-shrinkwrap\.json/.test(h)) return 'npm';
    if (/pnpm-lock\.ya?ml/.test(h)) return 'pnpm';
    if (/uv\.lock/.test(h)) return 'uv';
    if (/poetry\.lock/.test(h)) return 'poetry';
    if (/\.txt$/.test(h)) return 'requirements';
    const t = text.trimStart();
    if (t.startsWith('{')) return 'npm';
    if (/^lockfileVersion:\s*['"]?\d/m.test(text)) return 'pnpm';
    if (/^\[\[package\]\]/m.test(text)) {
        if (/^revision\s*=|^requires-python\s*=/m.test(text) || /source\s*=\s*\{\s*(registry|editable|virtual)\s*=/.test(text)) return 'uv';
        return 'poetry';
    }
    if (looksLikeRequirements(text)) return 'requirements';
    throw new LockfileError('could not recognise the lockfile format (supported: package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, uv.lock, poetry.lock, requirements.txt)');
}

/** Strip credentials and query strings (tokens, signed-URL parameters) from a recorded source before it is reported. */
export function redactSource(raw) {
    if (raw === undefined || raw === null) return null;
    const s = String(raw).slice(0, 500);
    return s.replace(/^([a-z][\w+.-]*:\/\/)[^/@\s]*@/i, '$1').replace(/\?[^#\s]*/, '');
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
    const add = (name, v) => {
        if (typeof v?.version !== 'string') return;
        // npm v1 records git/URL/local dependencies in "version"; v2/v3 in "resolved".
        const recorded = v.resolved || (/^[\w.+-]+:|^[./~]/.test(v.version) ? v.version : undefined);
        addVer(map, name, v.version, { origin: classifyOrigin(recorded, 'npm'), source: recorded || null, dev: Boolean(v.dev) });
    };
    if (doc.packages && typeof doc.packages === 'object') {
        for (const [p, v] of Object.entries(doc.packages)) {
            if (!p || v?.link || !p.includes('node_modules/')) continue;
            add(v.name || p.slice(p.lastIndexOf('node_modules/') + 'node_modules/'.length), v);
        }
    } else if (doc.dependencies && typeof doc.dependencies === 'object') {
        const walk = (deps) => {
            for (const [n, v] of Object.entries(deps || {})) { add(n, v); walk(v?.dependencies); }
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

/** Every document of a YAML stream, as plain data. Throws on the first syntax error. */
export function yamlDocuments(text) {
    const docs = YAML.parseAllDocuments(text);
    if (!Array.isArray(docs)) return [];
    for (const d of docs) if (d.errors.length) throw d.errors[0];
    return docs.map((d) => d.toJS({ maxAliasCount: 10000 }));
}

function parsePnpm(text) {
    let docs;
    try { docs = yamlDocuments(text); } catch (e) { throw new LockfileError(`pnpm-lock.yaml did not parse: ${e.message}`); }
    const map = new Map();
    // pnpm 11 and later write the package manager's own lockfile as a first document, then the
    // project's; packages from every document count.
    for (const [key, v] of docs.flatMap((doc) => Object.entries({ ...(doc?.packages || {}) }))) {
        const [name, version] = parsePnpmKey(key);
        const res = v?.resolution || {};
        // pnpm omits the tarball for packages from the configured default registry, which may be
        // private, so a missing tarball is an unknown origin.
        const recorded = res.tarball || res.repo || res.directory || (res.type === 'git' ? 'git:' : undefined);
        const origin = res.type === 'directory' ? 'local' : res.type === 'git' || res.repo ? 'git' : classifyOrigin(recorded, 'npm');
        const realVersion = v?.version && !/^\d/.test(version) ? v.version : version;
        if (name && /^\d/.test(realVersion || '')) addVer(map, v?.name || name, realVersion, { origin, source: recorded || null, dev: Boolean(v?.dev) });
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
        if (src.editable || src.virtual) continue; // the project itself
        let origin; let source;
        if (src.registry) { origin = classifyOrigin(src.registry, 'pypi'); source = src.registry; }
        else if (src.git) { origin = 'git'; source = src.git; }
        else if (src.path || src.directory) { origin = 'local'; source = src.path || src.directory; }
        else if (src.url) { origin = 'url'; source = src.url; }
        else { origin = 'unknown'; source = null; }
        addVer(map, normPy(p.name), p.version, { origin, source });
    }
    return map;
}

function parsePoetry(text) {
    const doc = parseToml2(text, 'poetry.lock');
    const map = new Map();
    for (const p of doc.package || []) {
        const src = p.source || {};
        let origin; let source = src.url || null;
        if (!p.source) origin = 'unknown'; // Poetry's default source; not recorded in the lockfile
        else if (src.type === 'legacy') origin = classifyOrigin(src.url, 'pypi');
        else if (src.type === 'git') origin = 'git';
        else if (src.type === 'directory' || src.type === 'file') origin = 'local';
        else { origin = 'url'; source = src.url || src.type || null; }
        addVer(map, normPy(p.name), p.version, { origin, source });
    }
    return map;
}

// ---- pip requirements files ----
// Only exact pins (name==1.2.3 or name===1.2.3) name a version that can be compared. A range
// (name>=1.2) or an unpinned name is listed, not looked up.
// Origin: pip's index can be set outside the file (pip.conf, PIP_INDEX_URL), so a file with no
// index option has no recorded origin. A file whose only index is https://pypi.org/simple is
// public. Any other index, an extra index or --find-links makes every pin private: pip may take
// any name from any of them, so no name of the file may be sent to the public registry. Includes
// (-r, -c) are not read and may set any of these, and so may an option written with ${VAR}; a
// file with either has no name that can be looked up, even with assumePublicRegistry.
// The file is read as pip reads it, and anything this cannot read the same way refuses the file.

const REQ_NAME = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*/;
// Line breaks other than \n and \r\n, and white space other than space and tab: pip (Python) and
// JavaScript split and trim these differently.
const REQ_ODD_CHAR = /[\0-\x08\x0b\x0c\x0e-\x1f\x7f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]|\r(?!\n)/;

/**
 * Logical lines, as pip's preprocess makes them: a line ending in a backslash is joined to the
 * next with the backslashes at both of its ends removed, unless it is a comment line; then a
 * comment ("#" at the start or after white space) is removed from the joined line, so a comment
 * continued by a backslash also removes the line after it.
 */
export function requirementLines(text) {
    const body = text.replace(/^\ufeff/, '');
    if (REQ_ODD_CHAR.test(body)) throw new LockfileError('requirements file: it has a control character, an unusual line break or an unusual space');
    const joined = [];
    let cur = null;
    for (const line of body.split(/\r?\n/)) {
        const comment = /^\s*#/.test(line);
        if (line.endsWith('\\') && !comment) { cur = (cur ?? '') + line.replace(/^\\+|\\+$/g, ''); continue; }
        joined.push((cur ?? '') + (comment ? ` ${line}` : line));
        cur = null;
    }
    if (cur !== null) joined.push(cur);
    return joined.map((l) => l.replace(/(^|\s+)#.*$/, '').trim()).filter(Boolean);
}

// The options pip reads in a requirements file, spelled in full. pip also takes abbreviations
// (--extra-index-u) and a few other options; a file with one of those is refused.
const REQ_OPTIONS = new Map([
    ['-i', 'index'], ['--index-url', 'index'], ['--extra-index-url', 'extra'], ['-f', 'extra'], ['--find-links', 'extra'],
    ['--no-index', 'no-index'], ['-r', 'include'], ['--requirement', 'include'], ['-c', 'include'], ['--constraint', 'include'],
    ['-e', 'editable'], ['--editable', 'editable'], ['--no-binary', 'other'], ['--only-binary', 'other'],
    ['--trusted-host', 'other'], ['--use-feature', 'other'], ['--pre', 'flag'], ['--prefer-binary', 'flag'], ['--require-hashes', 'flag'],
]);
const REQ_FLAGS = new Set(['no-index', 'flag']);
const REQ_OP = String.raw`(?:===?|~=|!=|<=?|>=?)\s*[^\s;,]+`;
// name [extras] [version specifiers | @ url] [; marker]
const REQ_ARGS = new RegExp(String.raw`^[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*(?:${REQ_OP}(?:\s*,\s*${REQ_OP})*|@\s*\S+)?\s*(?:;.*)?$`);

/** Options as [kind, value] pairs; null for anything else (pip splits these with shlex, so quotes and backslashes are refused). */
function requirementOptions(text) {
    if (/["'\\]/.test(text)) return null;
    const tokens = text.split(/[ \t]+/).filter(Boolean);
    const out = [];
    for (let i = 0; i < tokens.length; i++) {
        const eq = tokens[i].startsWith('--') ? tokens[i].indexOf('=') : -1;
        const kind = REQ_OPTIONS.get(eq < 0 ? tokens[i] : tokens[i].slice(0, eq));
        if (!kind) return null;
        if (REQ_FLAGS.has(kind)) { if (eq >= 0) return null; out.push([kind, '']); continue; }
        const value = eq < 0 ? tokens[++i] : tokens[i].slice(eq + 1);
        if (!value) return null;
        out.push([kind, value]);
    }
    return out;
}

/**
 * One logical line: { options } for an option line, { requirement } for a requirement (its
 * --hash options checked and dropped), or null when it is outside this grammar. As in pip, a
 * line's options start at its first space-separated word that starts with "-".
 */
export function readRequirementLine(line) {
    if (line.includes('\\')) return null;
    const words = line.split(' ');
    const at = words.findIndex((w) => w.startsWith('-'));
    if (at === 0) {
        const options = requirementOptions(line);
        // pip ignores the other options of an editable line; reading them could make a file public.
        if (!options || (options.length > 1 && options.some(([k]) => k === 'editable'))) return null;
        return { options };
    }
    const requirement = (at < 0 ? words : words.slice(0, at)).join(' ');
    if (!REQ_ARGS.test(requirement)) return null;
    if (at > 0) {
        const opts = words.slice(at).join(' ');
        if (/["'\\]/.test(opts)) return null;
        const tokens = opts.split(/[ \t]+/).filter(Boolean);
        for (let i = 0; i < tokens.length; i++) {
            if (/^--hash=\S/.test(tokens[i])) continue;
            if (tokens[i] === '--hash' && tokens[i + 1]) { i++; continue; }
            return null;
        }
    }
    return { requirement };
}

function looksLikeRequirements(text) {
    try {
        const lines = requirementLines(text);
        return lines.length > 0 && lines.every((l) => readRequirementLine(l));
    } catch { return false; }
}

const isPypiIndex = (url) => /^https:\/\/pypi\.org\/simple\/?$/.test(url);

function parseRequirements(text) {
    const lines = requirementLines(text);
    const indexes = []; let extra = false; let noIndex = false; let include = false; let envVar = false;
    const pins = []; const other = [];
    for (const [i, line] of lines.entries()) {
        const read = readRequirementLine(line);
        if (!read) throw new LockfileError(`requirements file: requirement ${i + 1} is not in a form this tool reads (name, extras, version specifiers, @ URL, marker, hashes, or options spelled in full)`);
        if (read.options) {
            if (line.includes('${')) envVar = true;
            for (const [kind, val] of read.options) {
                if (kind === 'index') indexes.push(val);
                else if (kind === 'extra') extra = true;
                else if (kind === 'no-index') noIndex = true;
                else if (kind === 'include') include = true;
                else if (kind === 'editable') {
                    const name = (val.match(/[#&]egg=([A-Za-z0-9._-]+)/) || [])[1];
                    if (name) other.push({ name, origin: classifyOrigin(val, 'pypi') === 'git' ? 'git' : 'local', source: val });
                }
            }
            continue;
        }
        const m = read.requirement.match(REQ_NAME);
        const name = normPy(m[1]);
        const rest = read.requirement.slice(m[0].length).replace(/;.*$/, '').trim();
        if (rest.startsWith('@')) {
            const url = rest.slice(1).trim().split(/\s+/)[0];
            const o = classifyOrigin(url, 'pypi');
            other.push({ name, origin: o === 'public' ? 'url' : o, source: url });
            continue;
        }
        const pin = rest.match(/^===?\s*([0-9][A-Za-z0-9.!+_-]*)$/);
        if (pin && !pin[1].includes('*')) pins.push({ name, version: pin[1] });
        else other.push({ name, origin: 'range', spec: rest || 'any version' });
    }
    let origin; let source = null;
    if (include || envVar) { origin = 'private'; source = include ? 'a -r or -c file, which is not read' : 'an option set from an environment variable'; }
    else if (noIndex) origin = 'local';
    else if (extra || indexes.length > 1 || (indexes.length === 1 && !isPypiIndex(indexes[0]))) {
        origin = 'private';
        source = indexes.find((u) => !isPypiIndex(u)) || 'an extra index or --find-links';
    } else if (indexes.length === 1) { origin = 'public'; source = indexes[0]; }
    else origin = 'unknown';
    const map = new Map();
    for (const p of pins) addVer(map, p.name, p.version, { origin, source });
    // Unpinned and non-index entries are never looked up. They are keyed by their spec or cleaned
    // source, so a change to one is listed.
    for (const o of other) {
        const key = o.origin === 'range' ? o.spec.slice(0, 200) : redactSource(o.source);
        addVer(map, o.name, key, { origin: o.origin, source: o.origin === 'range' ? null : o.source });
    }
    return map;
}

export function parseLockfile(text, hint = '') {
    const type = detectType(text, hint);
    const map = type === 'npm' ? parseNpm(text) : type === 'pnpm' ? parsePnpm(text) : type === 'uv' ? parseUv(text)
        : type === 'requirements' ? parseRequirements(text) : parsePoetry(text);
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

const ORIGIN_LABEL = { private: 'another registry or host', git: 'git', local: 'a local path', url: 'a URL', unknown: 'no recorded origin', range: 'no exact version' };

/**
 * Compare two parsed lockfiles. Returns { updated: [{name, from, to}], added: [{name, to}], removed: [{name, from}],
 * nonRegistry: [{name, to, origin, source}], originChanges: [{name, to, fromOrigin}] }.
 * Only "updated" and "added" entries may be looked up on a public registry. An entry with no recorded
 * origin is looked up only with assumePublic; everything else that is not public goes to nonRegistry.
 */
export function diffLockfiles(before, after, { assumePublic = false } = {}) {
    if (before.ecosystem !== after.ecosystem) throw new LockfileError(`lockfiles are for different ecosystems (${before.type} vs ${after.type})`);
    const eco = after.ecosystem;
    const updated = []; const added = []; const removed = []; const nonRegistry = []; const originChanges = [];
    const lookable = (meta) => meta.origin === 'public' || (assumePublic && meta.origin === 'unknown');
    for (const [name, vers] of after.packages) {
        const old = before.packages.get(name);
        for (const [v, meta] of vers) {
            if (old?.has(v) && old.get(v).origin === meta.origin) continue;
            if (!lookable(meta)) {
                nonRegistry.push({ name, to: v, origin: meta.origin, source: redactSource(meta.source) || ORIGIN_LABEL[meta.origin] || meta.origin });
                continue;
            }
            // Earlier versions to compare with must themselves be public; a name that moved from
            // another origin to the public registry is scanned as a new package and listed.
            const oldPublic = old ? [...old.entries()].filter(([, m]) => lookable(m)).map(([o]) => o) : [];
            const oldOther = old ? [...old.values()].filter((m) => !lookable(m)) : [];
            if (oldOther.length) originChanges.push({ name, to: v, fromOrigin: oldOther[0].origin });
            if (oldPublic.length) {
                const olds = oldPublic.filter((o) => o !== v).sort((a, b) => cmpVersions(eco, a, b));
                if (!olds.length) continue;
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
    return { ecosystem: eco, type: after.type, updated: updated.sort(byName), added: added.sort(byName), removed: removed.sort(byName), nonRegistry: nonRegistry.sort(byName), originChanges: originChanges.sort(byName) };
}

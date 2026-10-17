// Fetch published artifacts from the npm registry and PyPI. Downloads go only to the public
// registry hosts, must match a registry digest, and are kept in memory.
import crypto from 'node:crypto';
import semver from 'semver';
import { LIMITS } from './archive.js';

const UA = 'upgrade-xray/0.1 (+https://github.com/CyberNative-AI/upgrade-xray)';
export const NPM_REGISTRY = (process.env.NPM_REGISTRY || 'https://registry.npmjs.org').replace(/\/$/, '');
export const PYPI = (process.env.PYPI_URL || 'https://pypi.org').replace(/\/$/, '');

export class NotFound extends Error {}
export class DestinationError extends Error {}

// Every request, and every redirect it follows, must go to one of these hosts over HTTPS on the
// default port. Package metadata decides where tarballs live, so it is checked here too.
const ALLOWED_HOSTS = new Set([
    'registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org', 'files.pythonhosted.org',
    ...[NPM_REGISTRY, PYPI].map((u) => new URL(u).hostname),
]);
const MAX_REDIRECTS = 3;

export function checkDestination(raw) {
    let u;
    try { u = new URL(raw); } catch { throw new DestinationError(`not a valid URL: ${String(raw).slice(0, 200)}`); }
    if (u.protocol !== 'https:' || u.port) throw new DestinationError(`refused non-HTTPS or custom-port URL: ${u.origin}`);
    if (u.username || u.password) throw new DestinationError(`refused URL with credentials: ${u.hostname}`);
    if (!ALLOWED_HOSTS.has(u.hostname)) throw new DestinationError(`refused download from ${u.hostname}: not a public registry host`);
    return u;
}

async function get(url, { accept, maxBytes = LIMITS.maxCompressedBytes, tries = 3 } = {}) {
    let lastErr;
    for (let i = 0; i < tries; i++) {
        try {
            let target = checkDestination(url);
            let res;
            for (let hop = 0; ; hop++) {
                res = await fetch(target, { headers: { 'user-agent': UA, ...(accept ? { accept } : {}) }, signal: AbortSignal.timeout(60000), redirect: 'manual' });
                if (![301, 302, 303, 307, 308].includes(res.status)) break;
                const loc = res.headers.get('location');
                try { await res.body?.cancel(); } catch { /* nothing to release */ }
                if (!loc || hop >= MAX_REDIRECTS) throw new DestinationError(`too many or empty redirects from ${url}`);
                target = checkDestination(new URL(loc, target).href);
            }
            if (res.status === 404) throw new NotFound(`not found: ${url}`);
            if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
            const len = Number(res.headers.get('content-length') || 0);
            if (len > maxBytes) throw new Error(`response larger than ${maxBytes} bytes: ${url}`);
            const chunks = [];
            let total = 0;
            for await (const c of res.body) {
                total += c.length;
                if (total > maxBytes) throw new Error(`response larger than ${maxBytes} bytes: ${url}`);
                chunks.push(c);
            }
            return Buffer.concat(chunks);
        } catch (e) {
            lastErr = e;
            if (e instanceof NotFound || e instanceof DestinationError || /larger than/.test(e.message)) throw e;
            await new Promise((r) => setTimeout(r, 500 * 2 ** i));
        }
    }
    throw lastErr;
}

const getJson = async (url, opts) => JSON.parse((await get(url, opts)).toString('utf8'));

const npmName = (name) => (name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name));

const packuments = new Map();
export async function npmPackument(name, { full = false } = {}) {
    const key = `${full ? 'f' : 'a'}:${name}`;
    if (!packuments.has(key)) {
        packuments.set(key, getJson(`${NPM_REGISTRY}/${npmName(name)}`, { accept: full ? 'application/json' : 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8', maxBytes: 80 * 1024 * 1024 }));
    }
    try { return await packuments.get(key); } catch (e) { packuments.delete(key); throw e; }
}

/**
 * Why an exact npm version is missing: the full packument keeps the publish time of a version
 * npm later removed (a malware takedown or the publisher's request). Returns a sentence, or null
 * when the registry has no record of the version.
 */
async function npmRemovedReason(name, version) {
    const v = semver.valid(version);
    if (!v) return null;
    let doc;
    try { doc = await npmPackument(name, { full: true }); } catch { return null; }
    if (!Object.hasOwn(doc.time || {}, v) || Object.hasOwn(doc.versions || {}, v)) return null;
    const t = new Date(doc.time[v]);
    const when = Number.isNaN(t.getTime()) ? '' : ` on ${t.toISOString().slice(0, 10)}`;
    return `${name}@${v} was published${when} and later removed from the npm registry, so its files can no longer be downloaded and compared. npm removes a version after a security takedown or at its publisher's request; a lockfile or pull request that still pins it needs a closer look.`;
}

/** Resolve "from"/"to" versions of an npm package. */
export async function npmResolve(name, from, to, { added = false } = {}) {
    const doc = await npmPackument(name);
    const versions = Object.keys(doc.versions || {});
    const pick = async (v, label) => {
        if (!v) return null;
        if (doc.versions[v]) return v;
        if (doc['dist-tags']?.[v]) return doc['dist-tags'][v];
        const r = semver.maxSatisfying(versions, v);
        if (!r) throw new NotFound(await npmRemovedReason(name, v) || `${name}: no published version matches ${label} "${v}"`);
        return r;
    };
    const toV = await pick(to || 'latest', 'to');
    let fromV = await pick(from, 'from');
    if (added) return { from: null, to: toV, fromMeta: null, toMeta: doc.versions[toV] };
    if (!fromV) {
        const pre = semver.prerelease(toV);
        fromV = semver.rsort(versions.filter((v) => semver.valid(v) && semver.lt(v, toV) && (pre || !semver.prerelease(v))))[0];
        if (!fromV) throw new NotFound(`${name}@${toV} has no earlier version to compare with`);
    }
    return { from: fromV, to: toV, fromMeta: doc.versions[fromV], toMeta: doc.versions[toV] };
}

export class IntegrityError extends Error {}

const SRI_BYTES = { sha512: 64, sha384: 48, sha256: 32 };

/**
 * Verify downloaded bytes against the registry's digest. A supported, well-formed digest is
 * required; a missing, malformed or unsupported one is an error, never a pass. npm's legacy
 * SHA-1 "shasum" is used only when no SRI integrity is published, and is labelled as such.
 * Returns the digest used: 'sha512' | 'sha384' | 'sha256' | 'sha1 (legacy npm shasum)'.
 */
export function verifyNpmIntegrity(buf, dist, label) {
    if (dist?.integrity !== undefined) {
        const entries = String(dist.integrity).trim().split(/\s+/).map((e) => e.match(/^(sha512|sha384|sha256)-([A-Za-z0-9+/]+={0,2})(\?.*)?$/))
            .filter((m) => m && Buffer.from(m[2], 'base64').length === SRI_BYTES[m[1]]);
        if (!entries.length) throw new IntegrityError(`${label}: unsupported or malformed integrity value`);
        entries.sort((x, y) => SRI_BYTES[y[1]] - SRI_BYTES[x[1]]);
        const [, algo, b64] = entries[0];
        if (crypto.createHash(algo).update(buf).digest('base64') !== b64) throw new IntegrityError(`${label}: integrity mismatch (${algo})`);
        return algo;
    }
    if (typeof dist?.shasum === 'string' && /^[0-9a-f]{40}$/i.test(dist.shasum)) {
        if (crypto.createHash('sha1').update(buf).digest('hex') !== dist.shasum.toLowerCase()) throw new IntegrityError(`${label}: shasum mismatch`);
        return 'sha1 (legacy npm shasum)';
    }
    throw new IntegrityError(`${label}: the registry published no usable checksum`);
}

export function verifyPypiDigest(buf, f) {
    const want = f?.digests?.sha256;
    if (typeof want !== 'string' || !/^[0-9a-f]{64}$/i.test(want)) throw new IntegrityError(`${f?.filename}: PyPI published no well-formed sha256 digest`);
    if (crypto.createHash('sha256').update(buf).digest('hex') !== want.toLowerCase()) throw new IntegrityError(`${f.filename}: sha256 mismatch`);
    return 'sha256';
}

export async function npmTarball(name, version, meta) {
    const m = meta || (await npmPackument(name)).versions[version];
    if (!m?.dist?.tarball) throw new NotFound(`${name}@${version} has no tarball`);
    const buf = await get(m.dist.tarball);
    const digest = verifyNpmIntegrity(buf, m.dist, `${name}@${version}`);
    return { buf, filename: m.dist.tarball.split('/').pop(), digest };
}

export function npmOwners(doc) {
    const out = new Set();
    for (const m of doc?.maintainers || []) { if (m.name) out.add(`n:${m.name.toLowerCase()}`); if (m.email) out.add(`e:${m.email.toLowerCase()}`); }
    const repo = String(doc?.repository?.url || doc?.repository || '').match(/github\.com[/:]([\w.-]+)\//i);
    if (repo) out.add(`gh:${repo[1].toLowerCase()}`);
    return [...out];
}

/**
 * The addresses /[\w.+-]+@[\w.-]+/g finds in s, in one pass. That regex restarts at every character
 * of a long run with no "@" after it; PyPI sets no documented size for these fields, and the JSON
 * response is only capped at 80 MB. A match can start only where a run of [\w.+-] starts (or where
 * the previous match ended), and only if "@" and a domain character follow that whole run.
 */
export function emailsIn(s) {
    const local = /[\w.+-]+/g;
    const domain = /@[\w.-]+/y;
    const out = [];
    for (let m; (m = local.exec(s));) {
        domain.lastIndex = local.lastIndex;
        const d = domain.exec(s);
        if (d) { out.push(m[0] + d[0]); local.lastIndex = domain.lastIndex; }
    }
    return out;
}

export function pypiOwners(info) {
    const out = new Set();
    for (const k of ['author_email', 'maintainer_email']) for (const e of emailsIn(String(info?.[k] || '').toLowerCase())) out.add(`e:${e}`);
    for (const u of Object.values(info?.project_urls || {}).concat(info?.home_page || [])) {
        const m = String(u).match(/github\.com\/([\w.-]+)\//i);
        if (m) out.add(`gh:${m[1].toLowerCase()}`);
    }
    return [...out];
}

/** Age and existence of an npm dependency newly added in a version. */
export async function npmDepInfo(name) {
    try {
        const doc = await npmPackument(name, { full: true });
        const created = doc.time?.created ? new Date(doc.time.created) : null;
        return { exists: true, created: created?.toISOString() || null, versions: Object.keys(doc.versions || {}).length, owners: npmOwners(doc) };
    } catch (e) {
        if (e instanceof NotFound) return { exists: false };
        return { error: e.message };
    }
}

// ---------------- PyPI ----------------

const pyDocs = new Map();
export async function pypiProject(name) {
    if (!pyDocs.has(name)) pyDocs.set(name, getJson(`${PYPI}/pypi/${encodeURIComponent(name)}/json`, { maxBytes: 80 * 1024 * 1024 }));
    try { return await pyDocs.get(name); } catch (e) { pyDocs.delete(name); throw e; }
}

const PRE = /(a|b|rc|alpha|beta|c|pre|preview|dev)\d*|\.dev/i;

function releaseTime(files) {
    const t = (files || []).map((f) => f.upload_time_iso_8601 || f.upload_time).filter(Boolean).sort()[0];
    return t ? new Date(t).getTime() : null;
}

/** Resolve from/to versions on PyPI; "previous" is the latest release uploaded before "to". */
export async function pypiResolve(name, from, to, { added = false } = {}) {
    const doc = await pypiProject(name);
    const rel = doc.releases || {};
    const norm = (v) => v.replace(/^v/, '');
    const find = (v) => (rel[v] ? v : Object.keys(rel).find((k) => k.toLowerCase() === norm(v).toLowerCase()));
    const toV = to && to !== 'latest' ? find(to) : doc.info.version;
    if (!toV || !rel[toV]?.length) throw new NotFound(`${name}: version "${to}" not found on PyPI (or has no files)`);
    let fromV = from ? find(from) : null;
    if (from && !fromV) throw new NotFound(`${name}: version "${from}" not found on PyPI`);
    if (added) return { from: null, to: toV, fromFiles: [], toFiles: rel[toV], toTime: releaseTime(rel[toV]) };
    if (!fromV) {
        const tt = releaseTime(rel[toV]);
        const pre = PRE.test(toV);
        const cands = Object.entries(rel).filter(([v, files]) => v !== toV && files.length && !files.every((f) => f.yanked) && (pre || !PRE.test(v)) && releaseTime(files) < tt);
        cands.sort((a, b) => releaseTime(b[1]) - releaseTime(a[1]));
        fromV = cands[0]?.[0];
        if (!fromV) throw new NotFound(`${name}==${toV} has no earlier release to compare with`);
    }
    return { from: fromV, to: toV, fromFiles: rel[fromV], toFiles: rel[toV], toTime: releaseTime(rel[toV]) };
}

function wheelRank(fn) {
    if (/-none-any\.whl$/.test(fn)) return 100;
    if (/manylinux.*x86_64\.whl$/.test(fn)) {
        const cp = Number((fn.match(/-cp3(\d+)-/) || [])[1] || 0);
        return 50 + Math.min(cp, 40);
    }
    if (/\.whl$/.test(fn)) return 10;
    return -1;
}

/** The kinds of PyPI artifact compared (the `kind` of each pair below and of each finding's `artifact`). */
export const ARTIFACT_KINDS = ['wheel', 'sdist'];

/** Choose comparable artifacts: best wheel and the sdist, for both versions. */
export function pypiPickArtifacts(fromFiles, toFiles) {
    const pairs = [];
    const sd = (files) => files.find((f) => f.packagetype === 'sdist' && /\.(tar\.gz|zip|tgz)$/.test(f.filename));
    const bestWheel = (files) => files.filter((f) => f.packagetype === 'bdist_wheel').sort((a, b) => wheelRank(b.filename) - wheelRank(a.filename))[0];
    const fw = bestWheel(fromFiles); const tw = bestWheel(toFiles);
    if (fw && tw) pairs.push({ kind: 'wheel', from: fw, to: tw });
    const fs = sd(fromFiles); const ts = sd(toFiles);
    if (fs && ts) pairs.push({ kind: 'sdist', from: fs, to: ts });
    if (!pairs.length) {
        if (tw) pairs.push({ kind: 'wheel', from: null, to: tw });
        else if (ts) pairs.push({ kind: 'sdist', from: null, to: ts });
    }
    return pairs;
}

export async function pypiFile(f) {
    if (f.size > LIMITS.maxCompressedBytes) throw new Error(`${f.filename} is ${Math.round(f.size / 1e6)} MB, above the ${LIMITS.maxCompressedBytes / 1e6} MB limit`);
    const buf = await get(f.url);
    const digest = verifyPypiDigest(buf, f);
    return { buf, filename: f.filename, digest };
}

export async function pypiDepInfo(name) {
    try {
        const doc = await pypiProject(name);
        const times = Object.values(doc.releases || {}).map(releaseTime).filter(Boolean).sort((a, b) => a - b);
        return { exists: true, created: times[0] ? new Date(times[0]).toISOString() : null, versions: Object.keys(doc.releases || {}).length, owners: pypiOwners(doc.info) };
    } catch (e) {
        if (e instanceof NotFound) return { exists: false };
        return { error: e.message };
    }
}

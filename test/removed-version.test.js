// A version npm removed (a malware takedown or the publisher's request) is still listed in the
// full packument's "time". Asking for it must say so plainly, stay uncharged and "not analysed",
// and never turn a registry string into report markup. Runs the real runInput → registry path
// against a fake public registry.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { runInput } from '../src/main.js';
import { stubFetch, memoryIo, tgz } from './helpers.js';

const NPM = 'https://registry.npmjs.org';

/** versions: published versions; removed: { version: time } kept only in "time". */
function packument(name, { versions, removed = {}, latest }) {
    const doc = { name, 'dist-tags': { latest: latest || versions.at(-1) }, versions: {}, time: { created: '2020-01-01T00:00:00.000Z' }, maintainers: [{ name: 'owner' }] };
    const blobs = new Map();
    versions.forEach((v, i) => {
        const buf = tgz([{ name: 'package/package.json', data: JSON.stringify({ name, version: v }) }, { name: 'package/index.js', data: `module.exports = ${i};\n` }]);
        const url = `${NPM}/${name}/-/${name}-${v}.tgz`;
        blobs.set(url, buf);
        doc.versions[v] = { name, version: v, dist: { tarball: url, integrity: `sha512-${crypto.createHash('sha512').update(buf).digest('base64')}` } };
        doc.time[v] = `2020-01-0${i + 2}T00:00:00.000Z`;
    });
    Object.assign(doc.time, removed);
    return { doc, blobs };
}

// Names are unique to this file because the registry client caches packuments per name.
const PKGS = {
    'rv-chalk': packument('rv-chalk', { versions: ['5.6.0', '5.6.2'], removed: { '5.6.1': '2025-09-08T13:00:00.000Z' } }),
    'rv-from': packument('rv-from', { versions: ['1.0.0', '1.0.2'], removed: { '1.0.1': '2025-09-08T13:00:00.000Z' } }),
    'rv-hold': packument('rv-hold', { versions: ['0.0.1-security'], removed: { '2.0.0': '2024-03-01T00:00:00.000Z' }, latest: '0.0.1-security' }),
    'rv-never': packument('rv-never', { versions: ['1.0.0', '1.0.1'] }),
    'rv-odd': packument('rv-odd', { versions: ['1.0.0'], removed: { '1.0.1': '<img src=x onerror=alert(1)>' } }),
    'rv-lock': packument('rv-lock', { versions: ['1.0.0', '1.0.2'], removed: { '1.0.1': '2025-09-08T13:00:00.000Z' } }),
    'rv-ok': packument('rv-ok', { versions: ['1.0.0', '1.0.1'] }),
    'rv-range': packument('rv-range', { versions: ['1.0.0', '1.0.1'] }),
    'rv-stale': { ...packument('rv-stale', { versions: ['1.0.0', '1.0.1'] }), staleAbbreviated: '1.0.1' },
    'rv-nofull': packument('rv-nofull', { versions: ['1.0.0'], removed: { '1.0.1': '2025-09-08T13:00:00.000Z' } }),
};

async function run(input, { fullDown = [] } = {}) {
    const f = stubFetch((url, opts) => {
        for (const p of Object.values(PKGS)) if (p.blobs.has(url)) return new Response(p.blobs.get(url));
        const u = new URL(url);
        const name = decodeURIComponent(u.pathname.slice(1));
        const full = opts.headers?.accept === 'application/json';
        // The abbreviated (install) packument has no "time", as on the real registry.
        if (u.hostname !== 'registry.npmjs.org' || !PKGS[name] || (full && fullDown.includes(name))) return undefined;
        const { doc, staleAbbreviated } = PKGS[name];
        if (full) return new Response(JSON.stringify(doc));
        const versions = { ...doc.versions };
        delete versions[staleAbbreviated];
        return new Response(JSON.stringify({ name, 'dist-tags': doc['dist-tags'], versions, modified: '2025-09-09T00:00:00.000Z' }));
    });
    try {
        const io = memoryIo();
        await runInput({ concurrency: 1, ...input }, io);
        assert.equal(io.failed, null, io.failed);
        return { io, calls: f.calls };
    } finally { f.restore(); }
}

const item = (io, name) => io.items.find((i) => i.name === name);
const REMOVED = /was published on 2025-09-08 and later removed from the npm registry, so its files can no longer be downloaded and compared/;

test('removed "to" version: named as removed with its publish date, not analysed, not charged', async () => {
    const { io } = await run({ packages: ['npm:rv-chalk@5.6.0..5.6.1', 'npm:rv-ok@1.0.0..1.0.1'] });
    const it = item(io, 'rv-chalk');
    assert.equal(it.verdict, 'error');
    assert.match(it.error, /^rv-chalk@5\.6\.1 /);
    assert.match(it.error, REMOVED);
    assert.match(it.error, /security takedown or at its publisher's request/);
    assert.doesNotMatch(it.error, /no published version matches|holding package/);
    assert.equal(item(io, 'rv-ok').verdict, 'clean');
    assert.deepEqual(io.charges.map((c) => c.eventName), ['package-diff']);
    // The report code-quotes name@version so it can never mention a GitHub account.
    assert.match(io.kv.REPORT, /Could not analyse: `rv-chalk@5\.6\.1` was published on 2025-09-08 and later removed/);
});

test('removed "from" version and a "v" prefix are recognised', async () => {
    const { io } = await run({ packages: ['npm:rv-from@v1.0.1..1.0.2'] });
    assert.match(item(io, 'rv-from').error, /^rv-from@1\.0\.1 was published on 2025-09-08 and later removed/);
    assert.equal(io.charges.length, 0);
});

test('a package npm replaced with a security holding package says so', async () => {
    const { io } = await run({ packages: ['npm:rv-hold@2.0.0'] });
    const e = item(io, 'rv-hold').error;
    assert.match(e, /^rv-hold@2\.0\.0 was published on 2024-03-01 and later removed/);
    assert.match(e, /replaced the whole package with a security holding package \(0\.0\.1-security\)/);
});

test('a version the registry never had, or a range, keeps the original message', async () => {
    const { io } = await run({ packages: ['npm:rv-never@1.0.0..1.0.9', 'npm:rv-ok@1.0.0..^7'] });
    assert.equal(item(io, 'rv-never').error, 'rv-never: no published version matches to "1.0.9"');
    assert.equal(item(io, 'rv-ok').error, 'rv-ok: no published version matches to "^7"');
});

test('a range never fetches the full packument', async () => {
    const { calls } = await run({ packages: ['npm:rv-range@1.0.0..^9'] });
    assert.deepEqual(calls.map((c) => c.url), [`${NPM}/rv-range`]);
});

test('an unreadable full packument falls back to the original message', async () => {
    const { io } = await run({ packages: ['npm:rv-nofull@1.0.0..1.0.1'] }, { fullDown: ['rv-nofull'] });
    assert.equal(item(io, 'rv-nofull').error, 'rv-nofull: no published version matches to "1.0.1"');
});

test('a version the full packument still lists is never called removed (stale install packument)', async () => {
    const { io } = await run({ packages: ['npm:rv-stale@1.0.0..1.0.1'] });
    assert.equal(item(io, 'rv-stale').error, 'rv-stale: no published version matches to "1.0.1"');
});

test('a non-date "time" value is dropped, never copied into the message', async () => {
    const { io } = await run({ packages: ['npm:rv-odd@1.0.0..1.0.1'] });
    const e = item(io, 'rv-odd').error;
    assert.match(e, /^rv-odd@1\.0\.1 was published and later removed from the npm registry/);
    assert.doesNotMatch(e, /img|onerror|</);
    assert.doesNotMatch(io.kv.REPORT, /onerror/);
});

test('lockfile mode: an update to a removed version is reported as removed', async () => {
    const lock = (v) => JSON.stringify({
        name: 'app', lockfileVersion: 3,
        packages: { '': { name: 'app', dependencies: { 'rv-lock': v } }, 'node_modules/rv-lock': { version: v, resolved: `${NPM}/rv-lock/-/rv-lock-${v}.tgz` } },
    });
    const { io } = await run({ lockfileBefore: lock('1.0.0'), lockfileAfter: lock('1.0.1'), lockfileName: 'package-lock.json' });
    assert.match(item(io, 'rv-lock').error, /^rv-lock@1\.0\.1 was published on 2025-09-08 and later removed/);
    assert.equal(io.kv.OUTPUT.verdict, 'error');
    assert.equal(io.charges.length, 0);
    assert.match(io.kv.REPORT, /a lockfile or pull request that still pins it needs a closer look/);
});

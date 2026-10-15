// Only names with a proven public-registry origin may leave the run. Every test runs the real
// lockfile → analysis path and records every outbound request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runInput } from '../src/main.js';
import { classifyOrigin, parseLockfile, diffLockfiles, redactSource } from '../src/lockfile.js';
import { stubFetch, lookedUpNames, memoryIo } from './helpers.js';

async function outbound(before, after, extra = {}) {
    const f = stubFetch();
    try {
        const io = memoryIo();
        await runInput({ lockfileBefore: before, lockfileAfter: after, concurrency: 1, ...extra }, io);
        return { names: lookedUpNames(f.calls), io };
    } finally { f.restore(); }
}

const npmV1 = (deps) => JSON.stringify({ lockfileVersion: 1, dependencies: deps });
const npmV3 = (pkgs) => JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' }, ...pkgs } });

test('origin classification: exact public hosts over HTTPS only', () => {
    assert.equal(classifyOrigin('https://registry.npmjs.org/a/-/a-1.0.0.tgz', 'npm'), 'public');
    assert.equal(classifyOrigin('https://registry.yarnpkg.com/a/-/a-1.0.0.tgz', 'npm'), 'public');
    assert.equal(classifyOrigin('https://npm.corp.example/registry/a/-/a-1.0.0.tgz', 'npm'), 'private');
    assert.equal(classifyOrigin('https://registry.npmjs.org.evil.example/a.tgz', 'npm'), 'private');
    assert.equal(classifyOrigin('https://evil.example/registry.npmjs.org/a.tgz', 'npm'), 'private');
    assert.equal(classifyOrigin('https://user:tok@registry.npmjs.org/a.tgz', 'npm'), 'private');
    assert.equal(classifyOrigin('http://registry.npmjs.org/a.tgz', 'npm'), 'private');
    assert.equal(classifyOrigin('https://registry.npmjs.org:8443/a.tgz', 'npm'), 'private');
    assert.equal(classifyOrigin('https://pypi.org/simple', 'npm'), 'private');
    assert.equal(classifyOrigin('git+ssh://git@github.com/o/r.git#abc', 'npm'), 'git');
    assert.equal(classifyOrigin('file:../local', 'npm'), 'local');
    assert.equal(classifyOrigin(undefined, 'npm'), 'unknown');
    assert.equal(classifyOrigin('https://pypi.org/simple', 'pypi'), 'public');
    assert.equal(classifyOrigin('https://pypi.corp.example/simple', 'pypi'), 'private');
});

test('npm v1: private URL containing "registry" is not looked up; public control is', async () => {
    const before = npmV1({ 'secret-pkg': { version: '1.0.0', resolved: 'https://npm.corp.example/registry/secret-pkg/-/secret-pkg-1.0.0.tgz' }, 'left-pad': { version: '1.2.0', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz' } });
    const after = npmV1({ 'secret-pkg': { version: '1.1.0', resolved: 'https://npm.corp.example/registry/secret-pkg/-/secret-pkg-1.1.0.tgz' }, 'left-pad': { version: '1.3.0', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz' } });
    const { names, io } = await outbound(before, after);
    assert.deepEqual(names, ['left-pad']);
    assert.deepEqual(io.kv.OUTPUT.nonRegistry.map((n) => [n.name, n.origin]), [['secret-pkg', 'private']]);
});

test('npm: lookalike, credentialed, plain-HTTP and custom-port origins are not looked up', async () => {
    const urls = {
        'look-a': 'https://registry.npmjs.org.evil.example/look-a/-/look-a-2.0.0.tgz',
        'look-b': 'https://user:token@registry.npmjs.org/look-b/-/look-b-2.0.0.tgz',
        'look-c': 'http://registry.npmjs.org/look-c/-/look-c-2.0.0.tgz',
        'look-d': 'https://registry.npmjs.org:8443/look-d/-/look-d-2.0.0.tgz',
    };
    const before = npmV3({});
    const after = npmV3(Object.fromEntries(Object.entries(urls).map(([n, u]) => [`node_modules/${n}`, { version: '2.0.0', resolved: u }])));
    for (const fmt of [after, npmV1(Object.fromEntries(Object.entries(urls).map(([n, u]) => [n, { version: '2.0.0', resolved: u }])))]) {
        const { names, io } = await outbound(fmt === after ? before : npmV1({}), fmt);
        assert.deepEqual(names, []);
        assert.equal(io.kv.OUTPUT.nonRegistry.length, 4);
        assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
    }
});

test('npm v2/v3: missing "resolved" is unknown and needs explicit confirmation', async () => {
    const before = npmV3({ 'node_modules/quiet': { version: '1.0.0' } });
    const after = npmV3({ 'node_modules/quiet': { version: '1.0.1' } });
    assert.deepEqual((await outbound(before, after)).names, []);
    assert.deepEqual((await outbound(before, after, { assumePublicRegistry: true })).names, ['quiet']);
});

test('npm v1: git, URL and local versions are not looked up', async () => {
    const after = npmV1({
        g: { version: 'git+ssh://git@github.com/o/g.git#abc', from: 'github:o/g' },
        u: { version: 'https://cdn.example/u-1.0.0.tgz' },
        l: { version: 'file:../l' },
    });
    const { names, io } = await outbound(npmV1({}), after);
    assert.deepEqual(names, []);
    assert.deepEqual(io.kv.OUTPUT.nonRegistry.map((n) => n.origin).sort(), ['git', 'local', 'private']);
});

test('pnpm: missing tarball is unknown; private tarball host is never looked up', async () => {
    const lock = (v, extra = '') => `lockfileVersion: '9.0'\npackages:\n  quiet@${v}:\n    resolution: {integrity: sha512-x}\n  internal-lib@${v}:\n    resolution: {integrity: sha512-x, tarball: https://npm.corp.example/internal-lib/-/internal-lib-${v}.tgz}\n${extra}`;
    const before = lock('1.0.0'); const after = lock('1.0.1');
    assert.deepEqual((await outbound(before, after, { lockfileName: 'pnpm-lock.yaml' })).names, []);
    assert.deepEqual((await outbound(before, after, { lockfileName: 'pnpm-lock.yaml', assumePublicRegistry: true })).names, ['quiet']);
});

test('uv: only the public PyPI index is looked up; missing source is unknown', async () => {
    const lock = (v) => `version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "pubpkg"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "corp-secret"\nversion = "${v}"\nsource = { registry = "https://pypi.corp.example/simple" }\n\n[[package]]\nname = "nosource"\nversion = "${v}"\n\n[[package]]\nname = "gitdep"\nversion = "${v}"\nsource = { git = "https://github.com/o/gitdep?rev=abc" }\n`;
    const { names, io } = await outbound(lock('1.0.0'), lock('1.1.0'), { lockfileName: 'uv.lock' });
    assert.deepEqual(names, ['pubpkg']);
    assert.deepEqual(io.kv.OUTPUT.nonRegistry.map((n) => n.name).sort(), ['corp-secret', 'gitdep', 'nosource']);
});

test('poetry: absent source is unknown; legacy private source is never looked up', async () => {
    const lock = (v) => `[[package]]\nname = "default-src"\nversion = "${v}"\n\n[[package]]\nname = "corp-lib"\nversion = "${v}"\n\n[package.source]\ntype = "legacy"\nurl = "https://pypi.corp.example/simple"\nreference = "corp"\n\n[[package]]\nname = "pub-legacy"\nversion = "${v}"\n\n[package.source]\ntype = "legacy"\nurl = "https://pypi.org/simple"\nreference = "pypi"\n`;
    assert.deepEqual((await outbound(lock('1.0.0'), lock('1.1.0'), { lockfileName: 'poetry.lock' })).names, ['pub-legacy']);
    assert.deepEqual((await outbound(lock('1.0.0'), lock('1.1.0'), { lockfileName: 'poetry.lock', assumePublicRegistry: true })).names, ['default-src', 'pub-legacy']);
});

test('private-to-public moves are scanned as new and listed; public-to-private is not looked up', async () => {
    const pub = (n, v) => ({ version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` });
    const priv = (n, v) => ({ version: v, resolved: `https://npm.corp.example/${n}/-/${n}-${v}.tgz` });
    const before = npmV3({ 'node_modules/moved-out': priv('moved-out', '1.0.0'), 'node_modules/moved-in': pub('moved-in', '1.0.0') });
    const after = npmV3({ 'node_modules/moved-out': pub('moved-out', '1.0.1'), 'node_modules/moved-in': priv('moved-in', '1.0.1') });
    const { names, io } = await outbound(before, after);
    assert.deepEqual(names, ['moved-out']);
    assert.deepEqual(io.kv.OUTPUT.originChanges, [{ name: 'moved-out', to: '1.0.1', fromOrigin: 'private' }]);
    assert.equal(io.items.find((i) => i.name === 'moved-out').addedPackage, true); // analysed as a new package (fails offline)
    const diff = diffLockfiles(parseLockfile(before), parseLockfile(after));
    assert.deepEqual(diff.added.map((a) => a.name), ['moved-out']);
    assert.deepEqual(diff.updated, []);
});

test('reported sources drop credentials and query tokens', async () => {
    assert.equal(redactSource('https://user:s3cret@npm.corp.example/a.tgz?token=abc#frag'), 'https://npm.corp.example/a.tgz#frag');
    const after = npmV3({ 'node_modules/p': { version: '1.0.0', resolved: 'https://bot:ghp_SECRET@npm.corp.example/p/-/p-1.0.0.tgz?X-Amz-Signature=deadbeef' } });
    const { io } = await outbound(npmV3({}), after);
    const out = JSON.stringify(io.kv.OUTPUT) + io.kv.REPORT;
    assert.ok(!out.includes('ghp_SECRET') && !out.includes('deadbeef'));
});

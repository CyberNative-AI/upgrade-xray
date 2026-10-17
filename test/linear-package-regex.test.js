// Package files and inputs that once took seconds to minutes per kilobyte: each is read in
// linear time, and ordinary files still give the same result.
import test from 'node:test';
import assert from 'node:assert/strict';
import { npmSnapshot, pypiSnapshot } from '../src/snapshot.js';
import { scanDts } from '../src/js-scan.js';
import { parsePackageSpec } from '../src/main.js';
import { parseLockfile } from '../src/lockfile.js';

const B = (s) => Buffer.from(s);
async function fast(label, fn) {
    const t0 = performance.now();
    const out = await fn();
    const ms = performance.now() - t0;
    assert.ok(ms < 2000, `${label} took ${Math.round(ms)} ms`);
    return out;
}

test('pyproject.toml and setup.py dependency strings with a line break and a long white-space run', async () => {
    const tabs = '\t'.repeat(3200);
    const toml = `[project]\nname = "x"\nversion = "1"\ndependencies = ["a\\n${'\\t'.repeat(3200)}\\ta\\n", "requests [socks] >=2.31"]\n`;
    const p = await fast('pyproject.toml', () => pypiSnapshot(new Map([['pyproject.toml', B(toml)]]), 'sdist'));
    assert.deepEqual(p.deps, { requests: { spec: '>=2.31', field: 'requires' } });
    const setup = `setup(install_requires=['a\n${tabs}\ta\n', "django>=4.2"])\n`;
    const s = await fast('setup.py', () => pypiSnapshot(new Map([['setup.py', B(setup)]]), 'sdist'));
    assert.deepEqual(s.deps, { django: { spec: '>=4.2', field: 'requires' } });
});

test('METADATA Requires-Dist with a carriage return after long white-space runs', async () => {
    const meta = `Name: x\nVersion: 1\nRequires-Dist: a${' '.repeat(4000)}[${' '.repeat(4000)}\r\nRequires-Dist: idna (>=2.5) ; extra == "socks"\nRequires-Dist: urllib3<3,>=1.21.1\n`;
    const s = await fast('METADATA', () => pypiSnapshot(new Map([['x-1.dist-info/METADATA', B(meta)]]), 'wheel'));
    assert.deepEqual(s.deps, { idna: { spec: '(>=2.5) ; extra == "socks"', field: 'extra' }, urllib3: { spec: '<3,>=1.21.1', field: 'requires' } });
});

test('setup.py: an unclosed install_requires list repeated, and a long command-class base', async () => {
    const open = await fast('install_requires', () => pypiSnapshot(new Map([['setup.py', B('install_requires=['.repeat(40000))]]), 'sdist'));
    assert.deepEqual(open.deps, {});
    const longBase = `class g(f${'bsdistv'.repeat(60000)}\0)\n`;
    const classes = 'class A(install):\n    pass\nclass B ( setuptools.command.build_ext.build_ext ) :\n    pass\nclass C(install.Helper):\n    pass\nclass D(my_sdist2):\n    pass\n';
    const s = await fast('command classes', () => pypiSnapshot(new Map([['setup.py', B(longBase + classes)]]), 'sdist'));
    assert.equal(s.installScripts['setup.py command classes'], 'A(install), B(setuptools.command.build_ext.build_ext), D(my_sdist2)');
});

test('a top-level .pth file of blank lines; an import line is still a start-up hook', async () => {
    const blank = await fast('.pth', () => pypiSnapshot(new Map([['x.pth', B(`${'\n'.repeat(200000)}x`)]]), 'wheel'));
    assert.equal(blank.signals.filter((s) => s.kind === 'startup-hook').length, 0);
    const hook = await pypiSnapshot(new Map([['x.pth', B(`${'\n'.repeat(1000)}\t import os;os.system("id")\n`)]]), 'wheel');
    assert.equal(hook.signals.filter((s) => s.kind === 'startup-hook').length, 1);
});

test('.d.ts: blank-line runs and white-space runs inside export lists', async () => {
    const pkg = B(JSON.stringify({ name: 'x', version: '1.0.0', main: 'index.js', types: 'index.d.ts' }));
    // The blank lines end in a line that is not an export, so no match can start at the first one.
    const dts = `${'\n'.repeat(80000)}declare const x: number;\nexport declare function f(): void;\n\n\n  export default g;\nexport { a${'\t'.repeat(80000)}b, c as d, type e as f2 };\n`;
    const snap = await fast('npm snapshot', () => npmSnapshot(new Map([['package.json', pkg], ['index.js', B('module.exports = 1;\n')], ['index.d.ts', B(dts)]])));
    assert.deepEqual([...snap.api['.'].names].sort(), ['a' + '\t'.repeat(80000) + 'b', 'd', 'default', 'f', 'f2'].sort());
    assert.deepEqual([...scanDts('export { a as b, c\n  as\n  d };\nexport const e = 1;').names].sort(), ['b', 'd', 'e']);
});

test('package spec: a long white-space run in the version range', async () => {
    assert.equal((await fast('spec', () => parsePackageSpec(`left-pad@1${' '.repeat(100000)}x`))).to.length, 100002);
    assert.deepEqual(parsePackageSpec('left-pad@1.0.0 .. 1.3.0'), { ecosystem: 'npm', name: 'left-pad', from: '1.0.0', to: '1.3.0' });
    assert.deepEqual(parsePackageSpec('left-pad@1.0.0->1.3.0'), { ecosystem: 'npm', name: 'left-pad', from: '1.0.0', to: '1.3.0' });
});

test('pnpm-lock.yaml: a package key with many "(" or "_" before a line break', async () => {
    const key = `/a@1.0.0${'('.repeat(200000)}\\n(`;
    const key2 = `/e@1.0.0${'_'.repeat(200000)}\\n_`;
    const text = `lockfileVersion: '6.0'\n\npackages:\n\n  ? "${key}"\n  : {resolution: {integrity: sha512-x}}\n\n  ? "${key2}"\n  : {resolution: {integrity: sha512-z}}\n\n  /b@2.0.0(c@1.0.0):\n    resolution: {integrity: sha512-y}\n`;
    const lock = await fast('pnpm key', () => parseLockfile(text, 'pnpm-lock.yaml'));
    assert.deepEqual([...lock.packages.get('b').keys()], ['2.0.0']);
    // As before: a "(" with a line break after it does not start the peer suffix.
    const odd = parseLockfile(`lockfileVersion: '6.0'\n\npackages:\n\n  ? "/f@1.0.0(x\\n)y"\n  : {resolution: {integrity: sha512-x}}\n`, 'pnpm-lock.yaml');
    assert.deepEqual([...odd.packages.get('f').keys()], ['1.0.0(x\n)y']);
});

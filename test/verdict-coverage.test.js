// A run never reports "clean" for work it did not do, and gaps are visible to machines and readers.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runInput } from '../src/main.js';
import { npmSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { enrichNewDeps } from '../src/analyze.js';
import { packageMarkdown } from '../src/report.js';
import { stubFetch, memoryIo } from './helpers.js';

const pub = (n, v) => ({ version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` });
const lock = (pkgs) => JSON.stringify({ lockfileVersion: 3, packages: { '': {}, ...Object.fromEntries(Object.entries(pkgs).map(([k, v]) => [`node_modules/${k}`, v])) } });
const clean = (spec) => ({ ecosystem: spec.ecosystem, name: spec.name, fromVersion: spec.from, toVersion: spec.to, verdict: 'clean', findings: [], counts: {}, coverage: { complete: true } });
const failed = (spec) => ({ ecosystem: spec.ecosystem, name: spec.name, error: 'registry unavailable' });

async function lockRun(before, after, analyze) {
    const io = memoryIo({ analyze: async (s) => analyze(s) });
    await runInput({ lockfileBefore: before, lockfileAfter: after }, io);
    return io;
}

const B = lock({ a: pub('a', '1.0.0'), b: pub('b', '1.0.0') });
const A = lock({ a: pub('a', '1.0.1'), b: pub('b', '1.0.1') });

test('lockfile: every analysis failed → "error", not clean, and no charge', async () => {
    const io = await lockRun(B, A, failed);
    assert.equal(io.kv.OUTPUT.verdict, 'error');
    assert.equal(io.kv.OUTPUT.complete, false);
    assert.equal(io.kv.OUTPUT.coverage.failed, 2);
    assert.deepEqual(io.charges, []);
    assert.match(io.kv.REPORT, /Not analysed — no change could be analysed/);
});

test('lockfile: failed + clean → "incomplete", charged once', async () => {
    const io = await lockRun(B, A, (s) => (s.name === 'a' ? failed(s) : clean(s)));
    assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
    assert.equal(io.kv.OUTPUT.coverage.analysed, 1);
    assert.deepEqual(io.charges, [{ eventName: 'lockfile-report', count: 1 }]);
});

test('lockfile: only changes not looked up → "incomplete", nothing analysed, no charge', async () => {
    const priv = (n, v) => ({ version: v, resolved: `https://npm.corp.example/${n}-${v}.tgz` });
    const io = await lockRun(lock({ p: priv('p', '1.0.0') }), lock({ p: priv('p', '2.0.0') }), () => { throw new Error('must not analyse'); });
    assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
    assert.equal(io.kv.OUTPUT.coverage.notLookedUp, 1);
    assert.deepEqual(io.charges, []);
});

test('lockfile: changes above the package limit make the run incomplete', async () => {
    const io = memoryIo({ analyze: async (s) => clean(s) });
    await runInput({ lockfileBefore: B, lockfileAfter: A, maxPackages: 1 }, io);
    assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
    assert.equal(io.kv.OUTPUT.coverage.overLimit, 1);
});

test('lockfile: all analysed and nothing found → "clean", complete, charged once', async () => {
    const io = await lockRun(B, A, clean);
    assert.equal(io.kv.OUTPUT.verdict, 'clean');
    assert.equal(io.kv.OUTPUT.complete, true);
    assert.deepEqual(io.charges, [{ eventName: 'lockfile-report', count: 1 }]);
});

test('package mode: all failed → "error" and nothing charged; mixed → incomplete; charges only analysed', async () => {
    let io = memoryIo({ analyze: async (s) => failed(s) });
    await runInput({ packages: ['npm:a@1..2', 'npm:b@1..2'] }, io);
    assert.equal(io.kv.OUTPUT.verdict, 'error');
    assert.deepEqual(io.charges, []);
    io = memoryIo({ analyze: async (s) => (s.name === 'a' ? failed(s) : clean(s)) });
    await runInput({ packages: ['npm:a@1..2', 'npm:b@1..2', 'bad spec with spaces'] }, io);
    assert.equal(io.kv.OUTPUT.verdict, 'incomplete');
    assert.equal(io.charges.length, 1);
    io = memoryIo({ analyze: async (s) => clean(s) });
    await runInput({ packages: ['npm:a@1..2'] }, io);
    assert.equal(io.kv.OUTPUT.verdict, 'clean');
});

test('package mode: a findings verdict still wins over gaps', async () => {
    const io = memoryIo({ analyze: async (s) => (s.name === 'a' ? failed(s) : { ...clean(s), verdict: 'review' }) });
    await runInput({ packages: ['npm:a@1..2', 'npm:b@1..2'] }, io);
    assert.equal(io.kv.OUTPUT.verdict, 'review');
    assert.equal(io.kv.OUTPUT.complete, false);
});

test('files only pattern-scanned are listed before "nothing new found"', async () => {
    const files = (src) => new Map([
        ['package.json', Buffer.from('{"name":"t","version":"1.0.0","main":"index.js"}')],
        ['index.js', Buffer.from('module.exports = 1;')],
        ['lib/view.tsx', Buffer.from('export const x = <b>{1}</b>;')],
        ['lib/broken.js', Buffer.from(src)],
    ]);
    const r = diffSnapshots(await npmSnapshot(files('function (')), await npmSnapshot(files('function ( {')));
    assert.equal(r.verdict, 'clean');
    assert.equal(r.coverage.complete, false);
    assert.deepEqual(r.coverage.unparsedFiles.map((f) => f.file).sort(), ['lib/broken.js', 'lib/view.tsx']);
    assert.match(r.coverage.unparsedFiles.find((f) => f.file === 'lib/view.tsx').reason, /TypeScript/);
    const md = packageMarkdown({ ...r, ecosystem: 'npm', name: 't', fromVersion: '1.0.0', toVersion: '1.0.1' });
    assert.match(md, /found in the files that were inspected/);
    assert.match(md, /2 file\(s\) only pattern-scanned/);
});

test('fully parsed packages keep the plain "nothing new found" wording', async () => {
    const files = new Map([['package.json', Buffer.from('{"name":"t","version":"1.0.0"}')], ['index.js', Buffer.from('module.exports = 1;')]]);
    const r = diffSnapshots(await npmSnapshot(files), await npmSnapshot(files));
    assert.equal(r.coverage.complete, true);
    assert.doesNotMatch(packageMarkdown({ ...r, ecosystem: 'npm', name: 't', fromVersion: '1', toVersion: '2' }), /inspected|Coverage/);
});

test('new-dependency owner wording: shared, no shared identified, unknown', async () => {
    const now = Date.now();
    const packument = (maintainers) => JSON.stringify({ time: { created: new Date(now - 2 * 86400000).toISOString() }, versions: { '1.0.0': {} }, maintainers });
    let n = 0;
    const run = async (theirs, ours) => {
        const dep = `young-${n++}`; // the packument cache is per name
        const f = stubFetch(() => new Response(packument(theirs)));
        const result = { findings: [{ kind: 'new-dependency', severity: 'medium', category: 'dependency', dependency: dep, spec: '^1.0.0', detail: `new dependency ${dep}`, title: `New dependency ${dep}` }] };
        await enrichNewDeps('npm', result, now, ours);
        f.restore();
        return result.findings[0];
    };
    let f = await run([{ name: 'alice' }], ['n:alice']);
    assert.equal(f.dependencyInfo.sharesOwner, true);
    assert.match(f.detail, /shares a listed npm maintainer/);
    f = await run([{ name: 'mallory' }], ['n:alice']);
    assert.equal(f.dependencyInfo.sharesOwner, false);
    assert.match(f.detail, /no shared npm maintainer or repository was identified/);
    assert.doesNotMatch(f.detail, /different maintainers/);
    f = await run([], ['n:alice']);
    assert.equal(f.dependencyInfo.sharesOwner, null);
    assert.match(f.detail, /owner unknown/);
    assert.equal(f.severity, 'high'); // detector severity unchanged
});

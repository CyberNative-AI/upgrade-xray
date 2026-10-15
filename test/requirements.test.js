// pip requirements files: exact pins are compared; ranges, URLs, editables and every name of a
// file with a non-public or extra index are listed and never sent anywhere.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runInput } from '../src/main.js';
import { parseLockfile, detectType } from '../src/lockfile.js';
import { stubFetch, lookedUpNames, memoryIo } from './helpers.js';

async function outbound(before, after, extra = {}) {
    const f = stubFetch();
    try {
        const io = memoryIo();
        await runInput({ lockfileBefore: before, lockfileAfter: after, lockfileName: 'requirements.txt', concurrency: 1, ...extra }, io);
        return { names: lookedUpNames(f.calls), io };
    } finally { f.restore(); }
}

const body = (v) => [
    '# pinned by pip-compile',
    `django==${v} \\`,
    '    --hash=sha256:aaaa \\',
    '    --hash=sha256:bbbb',
    `uvicorn[standard]==0.3${v.at(-1)}.0 ; python_version >= "3.10"`,
    `requests>=2.${v.at(-1)}`,
    `wild==1.${v.at(-1)}.*`,
    '-r dev.txt',
    '',
].join('\n');

test('requirements: detected by name and by content', () => {
    assert.equal(detectType('x==1', 'requirements-dev.txt'), 'requirements');
    assert.equal(detectType('django==5.0\n# c\nrequests>=2\n-r other.txt\n'), 'requirements');
    assert.equal(parseLockfile(body('6.1.1')).ecosystem, 'pypi');
});

test('requirements: no index option = no recorded origin; nothing leaves the run without confirmation', async () => {
    const { names, io } = await outbound(body('6.1.1'), body('6.1.2'));
    assert.deepEqual(names, []);
    assert.deepEqual(io.kv.OUTPUT.nonRegistry.map((n) => [n.name, n.origin]).sort(), [['django', 'unknown'], ['requests', 'range'], ['uvicorn', 'unknown'], ['wild', 'range']]);
    assert.match(io.kv.REPORT, /this requirements file names no package index/);
    assert.match(io.kv.REPORT, /^pip requirements file: \*\*0 updated/m);
    assert.match(io.kv.REPORT, /`requests` `>=2\.2` \(a version range, not an exact version\)/);
    assert.equal(io.charges.length, 0);
});

test('requirements: with confirmation only exact pins are looked up (extras and markers stripped)', async () => {
    const { names } = await outbound(body('6.1.1'), body('6.1.2'), { assumePublicRegistry: true });
    assert.deepEqual(names.sort(), ['django', 'uvicorn']);
});

test('requirements: an explicit public PyPI index is a recorded public origin', async () => {
    const f = (v) => `--index-url https://pypi.org/simple\n${body(v)}`;
    assert.deepEqual((await outbound(f('6.1.1'), f('6.1.2'))).names.sort(), ['django', 'uvicorn']);
});

test('requirements: any other or extra index makes every name private, even with confirmation', async () => {
    for (const opt of ['--extra-index-url https://pypi.corp.example/simple', '-i https://pypi.corp.example/simple',
        '--find-links https://wheels.corp.example/', '-i https://pypi.org/simple\n--extra-index-url=https://pypi.corp.example/simple',
        '-i https://pypi.org/simple\n-i https://pypi.corp.example/simple', '--no-index']) {
        const f = (v) => `${opt}\n${body(v)}`;
        const { names, io } = await outbound(f('6.1.1'), f('6.1.2'), { assumePublicRegistry: true });
        assert.deepEqual(names, [], opt);
        assert.ok(io.kv.OUTPUT.nonRegistry.some((n) => n.name === 'django' && ['private', 'local'].includes(n.origin)), opt);
    }
});

test('requirements: credentials in index URLs and direct references never reach REPORT or OUTPUT', async () => {
    const f = (v) => [`-i https://build:s3cr3t-idx@pypi.corp.example/simple?token=q1`,
        `corp-lib @ https://dl:s3cr3t-url@files.corp.example/corp_lib-${v}.whl`,
        `-e git+https://s3cr3t-git@github.com/o/r.git@v${v}#egg=editable-lib`,
        `django==${v}`].join('\n');
    const { names, io } = await outbound(f('1.0'), f('1.1'), { assumePublicRegistry: true });
    assert.deepEqual(names, []);
    const all = JSON.stringify(io.kv.OUTPUT) + io.kv.REPORT + JSON.stringify(io.items);
    for (const secret of ['s3cr3t-idx', 's3cr3t-url', 's3cr3t-git', 'token=q1']) assert.ok(!all.includes(secret), secret);
    assert.deepEqual(io.kv.OUTPUT.nonRegistry.map((n) => [n.name, n.origin]).sort(),
        [['corp-lib', 'private'], ['django', 'private'], ['editable-lib', 'git']]);
});

test('requirements: a direct reference to the public file host is still not looked up by name', async () => {
    const f = (v) => `pkg @ https://files.pythonhosted.org/packages/xx/pkg-${v}-py3-none-any.whl\n`;
    const { names, io } = await outbound(f('1.0'), f('1.1'), { assumePublicRegistry: true });
    assert.deepEqual(names, []);
    assert.deepEqual(io.kv.OUTPUT.nonRegistry.map((n) => n.origin), ['url']);
});

test('requirements: text that is not a requirements file is refused, not half-read', async () => {
    const io = memoryIo();
    await runInput({ lockfileBefore: 'hello world\n', lockfileAfter: 'hello there\n', concurrency: 1 }, io);
    assert.match(String(io.failed), /could not recognise the lockfile format/);
});

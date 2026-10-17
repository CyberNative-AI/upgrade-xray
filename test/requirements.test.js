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

test('requirements: options are read in full, on the same line and after other options', async () => {
    for (const [opt, assume] of [
        ['--index-url https://pypi.org/simple --extra-index-url https://private.example/simple', false],
        ['-i https://pypi.org/simple -i https://private.example/simple', false],
        ['-i https://pypi.org/simple\n--pre --extra-index-url https://private.example/simple', true],
        ['--pre --find-links https://private.example/wheels', true],
        ['--pre --no-index', true],
        ['--index-url=https://pypi.org/simple --extra-index-url=https://private.example/simple', false],
    ]) {
        const f = (v) => `${opt}\n${body(v)}`;
        assert.deepEqual((await outbound(f('6.1.1'), f('6.1.2'), { assumePublicRegistry: assume })).names, [], opt);
    }
});

test('requirements: only https://pypi.org/simple is the public index', async () => {
    for (const idx of ['https://files.pythonhosted.org/private', 'https://pypi.org/private', 'http://pypi.org/simple', 'https://pypi.org:443/simple',
        'https://u:p@pypi.org/simple', 'https://pypi.org/simple?x=1', 'https://pypi.org/simple${X}', 'https://pypi.org.example/simple']) {
        const f = (v) => `-i ${idx}\n${body(v)}`;
        assert.deepEqual((await outbound(f('6.1.1'), f('6.1.2'))).names, [], idx);
    }
    const f = (v) => `-i https://pypi.org/simple/\n${body(v)}`;
    assert.deepEqual((await outbound(f('6.1.1'), f('6.1.2'))).names.sort(), ['django', 'uvicorn']);
});

test('requirements: an include (-r, -c) or an option from an environment variable stops every lookup, even with confirmation', async () => {
    for (const opt of ['-i https://pypi.org/simple\n-r nested.txt', '-c constraints.txt', '--requirement=base.txt', '--constraint https://example.com/c.txt',
        '-i https://pypi.org/simple\n--trusted-host ${HOST}', '-i https://pypi.org/simple\n-r ${FILE}']) {
        const f = (v) => `${opt}\n${body(v)}`;
        const { names, io } = await outbound(f('6.1.1'), f('6.1.2'), { assumePublicRegistry: true });
        assert.deepEqual(names, [], opt);
        assert.ok(io.kv.OUTPUT.nonRegistry.some((n) => n.name === 'django' && n.origin === 'private'), opt);
    }
    const f = (v) => `-r base.txt\n${body(v)}`;
    assert.match((await outbound(f('6.1.1'), f('6.1.2'))).io.kv.REPORT, /`django` `6\.1\.2` from `a -r or -c file, which is not read`/);
});

test('requirements: options that are abbreviated, unknown, quoted or malformed refuse the file', async () => {
    for (const opt of ['--extra-index-u https://private.example/simple', '--find https://private.example/', '--not-a-pip-option x',
        '-ihttps://private.example/simple', '-i=https://private.example/simple', '--index-url', '--pre=1', '--index-url "https://pypi.org/simple"',
        '--pre "--extra-index-url" https://private.example/simple', '--pre django==1.0', '-e . -i https://pypi.org/simple',
        'django==1.0 --extra-index-url https://private.example/simple', 'django==1.0 --hash', '-i https://pypi.org/simple\\x']) {
        const f = (v) => `${opt}\n${body(v)}`;
        const { names, io } = await outbound(f('6.1.1'), f('6.1.2'), { assumePublicRegistry: true, lockfileName: 'requirements.txt' });
        assert.deepEqual(names, [], opt);
        assert.match(String(io.failed), /not in a form this tool reads/, opt);
    }
});

test('requirements: comments and continuations are joined and removed as pip does', () => {
    const names = (t) => [...parseLockfile(t, 'requirements.txt').packages.keys()].sort();
    // A comment continued by a backslash removes the next line too; a full comment line does not continue.
    assert.deepEqual(names('django==1.0 # private note \\\nCOMMENT_CANARY\nflask==2.0\n'), ['django', 'flask']);
    assert.deepEqual([...parseLockfile('django==1.0 # private note \\\nCOMMENT_CANARY\n', 'requirements.txt').packages.get('django').keys()], ['1.0']);
    assert.deepEqual(names('# note \\\nflask==2.0\n'), ['flask']);
    assert.deepEqual(names('django==1.\\\n0\n'), ['django']);
    assert.equal([...parseLockfile('django==1.\\\n0\n', 'requirements.txt').packages.get('django').keys()][0], '1.0');
    // pip removes the backslashes at both ends of a continued line (pip 24: "django==1.0.1").
    assert.equal([...parseLockfile('django==1.\\\n\\0.\\\n1\n', 'requirements.txt').packages.get('django').keys()][0], '1.0.1');
    // A backslash followed by a space does not continue in pip; the stray backslash refuses the file.
    assert.throws(() => names('django==1.0 \\ \nflask==2.0\n'), /not in a form this tool reads/);
    for (const t of ['django==1.0\rflask==2.0\n', 'django==1.0\u2028flask==2.0\n', 'django==1.0\x0bflask==2.0\n', 'django==1.0\u00a0#x\n',
        // Python counts \x1f as white space, so pip drops "#SECRET" as a comment; JavaScript does not.
        'django==1.0\x1f#SECRET\n']) {
        assert.throws(() => parseLockfile(t, 'requirements.txt'), /unusual/, JSON.stringify(t));
    }
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

test('requirements: long space runs are read in linear time, and a line over 16384 characters is refused', () => {
    // A space run that does not end in "#": the comment pattern retried at every space of it.
    const run = ' '.repeat(16000);
    const text = Array.from({ length: 64 }, (_, i) => `p${i}==1${run}; os_name == "posix"`).join('\n');
    const t0 = performance.now();
    assert.equal(parseLockfile(text, 'requirements.txt').packages.size, 64);
    assert.ok(performance.now() - t0 < 2000, `64 lines took ${Math.round(performance.now() - t0)} ms`);
    assert.throws(() => parseLockfile(`p==1${' '.repeat(65536)}; os_name == "posix"\n`, 'requirements.txt'), /longer than 16384 characters/);
    // A requirement with many hashes is many short lines joined into one long line; it is still read.
    const hashes = Array.from({ length: 300 }, (_, i) => `    --hash=sha256:${String(i).padStart(64, '0')}`).join(' \\\n');
    assert.deepEqual([...parseLockfile(`numpy==2.0.0 \\\n${hashes}\n`, 'requirements.txt').packages.get('numpy').keys()], ['2.0.0']);
});

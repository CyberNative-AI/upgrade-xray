// Lockfiles come only as bounded pasted text; downloads and their redirects stay on public
// registry hosts; bodies are counted as they stream, whatever Content-Length says.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runInput, MAX_LOCKFILE_BYTES } from '../src/main.js';
import { checkDestination, npmTarball, pypiFile, DestinationError } from '../src/registry.js';
import { LIMITS } from '../src/archive.js';
import { stubFetch, memoryIo } from './helpers.js';

test('lockfile URL fields are refused without any request', async () => {
    for (const key of ['lockfileBeforeUrl', 'lockfileAfterUrl']) {
        const f = stubFetch();
        const io = memoryIo();
        await runInput({ lockfileBefore: '{}', lockfileAfter: '{}', [key]: 'http://127.0.0.1:8080/package-lock.json' }, io);
        f.restore();
        assert.match(io.failed, /not supported/);
        assert.equal(f.calls.length, 0);
    }
});

test('pasted lockfiles above the byte cap are refused before parsing', async () => {
    const io = memoryIo();
    const big = `{"lockfileVersion":3,"packages":{},"pad":"${'é'.repeat(MAX_LOCKFILE_BYTES / 2)}"}`; // 2 bytes per char in UTF-8
    await runInput({ lockfileBefore: '{}', lockfileAfter: big }, io);
    assert.match(io.failed, /larger than 20 MB/);
    assert.equal(io.kv.OUTPUT, undefined);
});

test('destinations: only HTTPS public registry hosts on the default port', () => {
    assert.ok(checkDestination('https://registry.npmjs.org/a/-/a-1.0.0.tgz'));
    assert.ok(checkDestination('https://files.pythonhosted.org/packages/x/a-1.0.whl'));
    for (const bad of [
        'http://127.0.0.1/a.tgz', 'https://127.0.0.1/a.tgz', 'https://[::1]/a.tgz', 'https://169.254.169.254/latest/meta-data',
        'https://10.0.0.5/a.tgz', 'https://npm.corp.internal/a.tgz', 'https://registry.npmjs.org.evil.example/a.tgz',
        'https://registry.npmjs.org:8443/a.tgz', 'http://registry.npmjs.org/a.tgz', 'https://u:p@registry.npmjs.org/a.tgz',
        'file:///etc/passwd', 'not a url',
    ]) assert.throws(() => checkDestination(bad), DestinationError, bad);
});

test('a tarball URL from package metadata pointing elsewhere is never fetched', async () => {
    for (const tarball of ['http://127.0.0.1:9/x.tgz', 'https://169.254.169.254/x.tgz', 'https://registry.npmjs.org.evil.example/x.tgz']) {
        const f = stubFetch(() => new Response('x'));
        await assert.rejects(npmTarball('x', '1.0.0', { dist: { tarball, integrity: `sha512-${Buffer.alloc(64).toString('base64')}` } }), DestinationError);
        f.restore();
        assert.equal(f.calls.length, 0);
    }
});

test('a redirect from an allowed host to a forbidden one is refused before following', async () => {
    for (const location of ['http://169.254.169.254/latest/meta-data/', 'https://127.0.0.1/x', 'https://evil.example/x', '//10.0.0.1/x']) {
        const f = stubFetch((u) => (u.startsWith('https://registry.npmjs.org/') ? new Response(null, { status: 302, headers: { location } }) : new Response('secret')));
        await assert.rejects(npmTarball('x', '1.0.0', { dist: { tarball: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', shasum: 'a'.repeat(40) } }), DestinationError);
        f.restore();
        assert.equal(f.calls.length, 1, location);
        assert.equal(f.calls[0].redirect, 'manual');
    }
});

test('allowed redirects are followed and re-checked', async () => {
    const body = Buffer.from('hello');
    const f = stubFetch((u) => (u.includes('/start') ? new Response(null, { status: 301, headers: { location: 'https://files.pythonhosted.org/end.whl' } }) : new Response(body)));
    const sha256 = (await import('node:crypto')).createHash('sha256').update(body).digest('hex');
    const r = await pypiFile({ filename: 'a.whl', size: 5, url: 'https://files.pythonhosted.org/start.whl', digests: { sha256 } });
    f.restore();
    assert.equal(r.buf.toString(), 'hello');
    assert.deepEqual(f.calls.map((c) => c.url), ['https://files.pythonhosted.org/start.whl', 'https://files.pythonhosted.org/end.whl']);
});

test('a body larger than the limit is stopped while streaming, despite a small Content-Length', async () => {
    const chunk = new Uint8Array(1024 * 1024);
    let sent = 0;
    const f = stubFetch(() => new Response(new ReadableStream({
        pull(c) { if (sent > LIMITS.maxCompressedBytes + chunk.length * 4) { c.close(); return; } sent += chunk.length; c.enqueue(chunk); },
    }), { headers: { 'content-length': '10' } }));
    await assert.rejects(pypiFile({ filename: 'a.whl', size: 10, url: 'https://files.pythonhosted.org/a.whl', digests: { sha256: '0'.repeat(64) } }), /larger than/);
    f.restore();
    assert.ok(sent <= LIMITS.maxCompressedBytes + chunk.length * 2, `read ${sent} bytes`);
});

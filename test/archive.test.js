// Archive readers must make progress on every input, check declared against actual sizes,
// and count the bytes they actually keep.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readTar, readZip, readArchive, ArchiveError, LIMITS } from '../src/archive.js';
import { npmSnapshot } from '../src/snapshot.js';
import { readEncryptedZip } from '../fixtures/sample-reader.js';
import { tar, tgz, zip } from './helpers.js';

const small = { ...LIMITS, maxUnpackedBytes: 4096, maxFileBytes: 2048 };

test('controls: ordinary tarball, wheel and stored zip read normally', () => {
    const t = readArchive(tgz([{ name: 'package/package.json', data: '{"name":"a"}' }, { name: 'package/index.js', data: 'module.exports = 1;' }]), 'a.tgz');
    assert.equal(t.get('package/index.js').toString(), 'module.exports = 1;');
    const w = readArchive(zip([{ name: 'a/__init__.py', data: 'x = 1\n'.repeat(100) }, { name: 'a-1.0.dist-info/METADATA', data: 'Name: a', method: 0 }]), 'a-1.0-py3-none-any.whl');
    assert.equal(w.get('a/__init__.py').length, 600);
    assert.equal(w.get('a-1.0.dist-info/METADATA').toString(), 'Name: a');
});

test('PAX records with negative, zero, oversized or truncated lengths are refused', () => {
    for (const rec of ['-5 path=x\n', '0 path=x\n', '999 path=x\n', '12 path=abc', '5 path=abcdef\n', 'xx path=a\n']) {
        assert.throws(() => readTar(tar([{ name: 'h', type: 'x', data: rec }, { name: 'f.js', data: 'a' }])), ArchiveError, rec);
    }
    const ok = readTar(tar([{ name: 'h', type: 'x', data: '20 path=longname.js\n' }, { name: 'f.js', data: 'a' }]));
    assert.ok(ok.has('longname.js'));
});

test('a PAX record pair that steps the cursor backwards terminates with an error', () => {
    // Formerly "-9" moved the cursor back onto the first record forever.
    const rec = Buffer.from('9 a=bcd\n-9 x\n');
    const started = Date.now();
    assert.throws(() => readTar(tar([{ name: 'h', type: 'x', data: rec }, { name: 'f.js', data: 'a' }])), ArchiveError);
    assert.ok(Date.now() - started < 1000);
});

test('tar entries that claim more data than the archive holds are refused', () => {
    const t = tar([{ name: 'f.js', data: 'abc' }]);
    t.write('00000077777\0', 124); // declared size far past the end
    assert.throws(() => readTar(t.subarray(0, 1024)), ArchiveError);
    const bad = tar([{ name: 'f.js', data: 'abc' }]);
    bad.write('0000000zz\0', 124);
    assert.throws(() => readTar(bad), ArchiveError);
});

test('tar total counts bytes actually kept, including repeated names', () => {
    const data = 'x'.repeat(1500);
    assert.throws(() => readTar(tar([1, 2, 3].map(() => ({ name: 'same.js', data }))), small), /unpacks to more than/);
});

test('zip: stored entry whose declared size differs from its data is refused', () => {
    assert.throws(() => readZip(zip([{ name: 'a.js', data: 'x'.repeat(100), method: 0, usize: 10 }])), /stored size mismatch/);
});

test('zip: deflated entry that inflates past its declared size is refused', () => {
    assert.throws(() => readZip(zip([{ name: 'a.js', data: 'x'.repeat(100000), usize: 10 }])), /declared size|inflates to/);
});

test('zip: deflated entry that inflates to less than its declared size is refused', () => {
    assert.throws(() => readZip(zip([{ name: 'a.js', data: 'x'.repeat(100), usize: 1000 }])), /inflates to 100 bytes, declared 1000/);
});

test('zip: forged small sizes cannot bypass the aggregate limit via overlapping entries', () => {
    const data = 'y'.repeat(1500);
    const entries = [{ name: 'a.js', data }];
    for (let i = 0; i < 5; i++) entries.push({ name: `copy${i}.js`, data: '', offsetOf: 0 });
    assert.throws(() => readZip(zip(entries), small), /unpacks to more than/);
    // ...and a stored entry is held to the same budget.
    const stored = [{ name: 'a.js', data, method: 0 }];
    for (let i = 0; i < 5; i++) stored.push({ name: `c${i}.js`, data: '', method: 0, offsetOf: 0 });
    assert.throws(() => readZip(zip(stored), small), /unpacks to more than/);
});

test('zip: offsets outside the archive are refused, not read', () => {
    const z = zip([{ name: 'a.js', data: 'abc', method: 0 }]);
    const cd = z.readUInt32LE(z.length - 22 + 16);
    z.writeUInt32LE(0x7fffffff, cd + 42); // local header offset
    assert.throws(() => readZip(z), ArchiveError);
    const z2 = zip([{ name: 'a.js', data: 'abc', method: 0 }]);
    z2.writeUInt32LE(0x7fffffff, z2.length - 22 + 16); // central directory offset
    assert.throws(() => readZip(z2), ArchiveError);
    const z3 = zip([{ name: 'a.js', data: 'abc', method: 0, csize: 1e6, usize: 1e6 }]);
    assert.throws(() => readZip(z3), ArchiveError);
});

test('encrypted, unsupported and oversized files are reported as not read', async () => {
    const z = zip([
        { name: 'package/package.json', data: '{"name":"a","version":"1.0.0"}', method: 0 },
        { name: 'package/secret.js', data: 'x', method: 0, flags: 1 },
        { name: 'package/odd.js', data: 'x', method: 0 },
        { name: 'package/big.js', data: 'x'.repeat(3000), method: 0 },
    ]);
    const cdStart = z.readUInt32LE(z.length - 22 + 16);
    // mark odd.js (third central entry) as method 12 (bzip2)
    let p = cdStart;
    for (let i = 0; i < 2; i++) p += 46 + z.readUInt16LE(p + 28);
    z.writeUInt16LE(12, p + 10);
    const files = readZip(z, small);
    const snap = await npmSnapshot(new Map([...files].map(([k, v]) => [k.replace(/^package\//, ''), v])));
    assert.equal(snap.coverage.complete, false);
    assert.deepEqual(snap.coverage.skippedFiles.map((f) => f.file).sort(), ['big.js', 'odd.js', 'secret.js']);
});

test('fixture sample reader: forged sizes and aggregate output are capped', () => {
    assert.throws(() => readEncryptedZip(zip([{ name: 'a', data: 'x'.repeat(100000), usize: 10 }])));
    assert.throws(() => readEncryptedZip(zip([{ name: 'a', data: 'x'.repeat(100), method: 0, usize: 10 }])), ArchiveError);
    const data = 'z'.repeat(1500);
    const entries = [{ name: 'a', data }];
    for (let i = 0; i < 5; i++) entries.push({ name: `c${i}`, data: '', offsetOf: 0 });
    assert.throws(() => readEncryptedZip(zip(entries), 'infected', small), ArchiveError);
    assert.equal(readEncryptedZip(zip([{ name: 'ok', data: 'hello' }])).get('ok').toString(), 'hello');
});

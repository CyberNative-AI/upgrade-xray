// Downloads must match a supported, well-formed registry digest; absence is a failure, not a pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyNpmIntegrity, verifyPypiDigest, IntegrityError } from '../src/registry.js';

const buf = Buffer.from('package bytes');
const b64 = (algo, b = buf) => crypto.createHash(algo).update(b).digest('base64');
const hex = (algo, b = buf) => crypto.createHash(algo).update(b).digest('hex');

test('npm: matching SRI digests pass and name the algorithm', () => {
    assert.equal(verifyNpmIntegrity(buf, { integrity: `sha512-${b64('sha512')}` }, 'x'), 'sha512');
    assert.equal(verifyNpmIntegrity(buf, { integrity: `sha1-${b64('sha1')} sha256-${b64('sha256')}` }, 'x'), 'sha256');
    assert.equal(verifyNpmIntegrity(buf, { shasum: hex('sha1') }, 'x'), 'sha1 (legacy npm shasum)');
});

test('npm: missing, malformed, unsupported and wrong digests are refused', () => {
    const cases = [
        {}, { integrity: '' }, { integrity: 'sha512-' }, { integrity: 'sha512-!!!notbase64' }, { integrity: `sha512-${b64('sha256')}` },
        { integrity: `sha1-${b64('sha1')}` }, { integrity: `md5-${b64('md5')}` }, { integrity: `sha512-${b64('sha512', Buffer.from('other'))}` },
        { shasum: 'abc' }, { shasum: hex('sha1', Buffer.from('other')) }, { integrity: 'garbage', shasum: hex('sha1') },
    ];
    for (const dist of cases) assert.throws(() => verifyNpmIntegrity(buf, dist, 'x'), IntegrityError, JSON.stringify(dist));
});

test('PyPI: sha256 required, well-formed and matching', () => {
    assert.equal(verifyPypiDigest(buf, { filename: 'a.whl', digests: { sha256: hex('sha256') } }), 'sha256');
    assert.equal(verifyPypiDigest(buf, { filename: 'a.whl', digests: { sha256: hex('sha256').toUpperCase() } }), 'sha256');
    for (const digests of [undefined, {}, { md5: hex('md5') }, { sha256: 'xyz' }, { sha256: hex('sha256').slice(1) }, { sha256: hex('sha256', Buffer.from('other')) }]) {
        assert.throws(() => verifyPypiDigest(buf, { filename: 'a.whl', digests }), IntegrityError, JSON.stringify(digests));
    }
});

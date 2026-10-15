// Reads password-protected (ZipCrypto) sample archives from the Datadog malicious
// packages dataset entirely in memory. Samples are never extracted to disk or run.
import zlib from 'node:zlib';
import { readArchive, stripCommonRoot, ArchiveError, LIMITS } from '../src/archive.js';

const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c >>> 0;
    }
    return t;
})();
const crc32Byte = (crc, b) => (CRC_TABLE[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0;

function zipCryptoDecrypt(data, password) {
    let k0 = 0x12345678; let k1 = 0x23456789; let k2 = 0x34567890;
    const update = (b) => {
        k0 = crc32Byte(k0, b);
        k1 = (Math.imul((k1 + (k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0;
        k2 = crc32Byte(k2, k1 >>> 24);
    };
    for (const b of Buffer.from(password)) update(b);
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        const t = (k2 | 2) & 0xffff;
        const k = ((t * (t ^ 1)) >>> 8) & 0xff;
        const p = data[i] ^ k;
        out[i] = p;
        update(p);
    }
    return out.subarray(12);
}

function bounded(zip, at, n) {
    if (at < 0 || at + n > zip.length) throw new ArchiveError('sample zip: offset out of bounds');
    return at;
}

/**
 * Map<path, Buffer> of an encrypted zip, held to the same file-count, per-file and total
 * output limits as the Actor's own archive reader.
 */
export function readEncryptedZip(zip, password = 'infected', limits = LIMITS) {
    const files = new Map();
    let eocd = -1;
    for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error('not a zip');
    const count = zip.readUInt16LE(eocd + 10);
    if (count > limits.maxFiles) throw new ArchiveError('sample zip: too many files');
    let p = zip.readUInt32LE(eocd + 16);
    let total = 0;
    for (let n = 0; n < count; n++) {
        bounded(zip, p, 46);
        if (zip.readUInt32LE(p) !== 0x02014b50) throw new ArchiveError('sample zip: bad central directory entry');
        const flags = zip.readUInt16LE(p + 8);
        const method = zip.readUInt16LE(p + 10);
        const csize = zip.readUInt32LE(p + 20);
        const usize = zip.readUInt32LE(p + 24);
        const nlen = zip.readUInt16LE(p + 28);
        const xlen = zip.readUInt16LE(p + 30);
        const clen = zip.readUInt16LE(p + 32);
        const lho = zip.readUInt32LE(p + 42);
        bounded(zip, p + 46, nlen + xlen + clen);
        const name = zip.toString('utf8', p + 46, p + 46 + nlen);
        p += 46 + nlen + xlen + clen;
        if (name.endsWith('/')) continue;
        if (usize > limits.maxFileBytes || usize > limits.maxUnpackedBytes - total) throw new ArchiveError(`sample zip: ${name} exceeds the size limits`);
        bounded(zip, lho, 30);
        const start = lho + 30 + zip.readUInt16LE(lho + 26) + zip.readUInt16LE(lho + 28);
        bounded(zip, start, csize);
        let raw = zip.subarray(start, start + csize);
        if (flags & 1) raw = zipCryptoDecrypt(raw, password);
        let data;
        if (method === 8) data = zlib.inflateRawSync(raw, { maxOutputLength: usize + 1 });
        else if (method === 0) data = Buffer.from(raw);
        else throw new ArchiveError(`sample zip: unsupported method ${method}`);
        if (data.length !== usize) throw new ArchiveError(`sample zip: ${name} size differs from its header`);
        total += data.length;
        files.set(name, data);
    }
    return files;
}

/**
 * Load one dataset sample as the package's published file tree.
 * Returns { files: Map, kind: 'npm' | 'wheel' | 'sdist' }.
 */
export function loadSample(zipBuf, ecosystem) {
    let files = readEncryptedZip(zipBuf);
    // A sample can wrap another encrypted zip, or a raw wheel / tarball.
    if (files.size === 1) {
        const [[name, inner]] = files;
        if (/\.zip$/i.test(name)) { try { files = readEncryptedZip(inner); } catch { files = readArchive(inner, name); } }
        if (files.size === 1 && /\.(whl|tgz|tar\.gz|zip)$/i.test([...files.keys()][0])) {
            const [[n2, b2]] = files;
            const kind = /\.whl$/i.test(n2) ? 'wheel' : ecosystem === 'npm' ? 'npm' : 'sdist';
            return { files: stripCommonRoot(readArchive(b2, n2)), kind };
        }
    }
    const gitCheckout = [...files.keys()].some((k) => /(^|\/)\.git\/(refs|objects|HEAD)/.test(k));
    return { ...pickRoot(files, ecosystem), gitCheckout };
}

/** Find the package root inside the sample's captured directory tree. */
function pickRoot(files, ecosystem) {
    const keys = [...files.keys()];
    const depth = (k) => k.split('/').length;
    const sub = (root) => {
        const out = new Map();
        for (const [k, v] of files) if (k.startsWith(root)) out.set(k.slice(root.length), v);
        return out;
    };
    if (ecosystem === 'npm') {
        const pj = keys.filter((k) => /(^|\/)package\.json$/.test(k) && !k.includes('/node_modules/')).sort((a, b) => depth(a) - depth(b))[0];
        return { files: pj ? sub(pj.slice(0, pj.length - 'package.json'.length)) : stripCommonRoot(files), kind: 'npm' };
    }
    // PyPI: sdist marker (PKG-INFO / setup.py / pyproject.toml) or a wheel's .dist-info
    const marker = keys.filter((k) => /(^|\/)(PKG-INFO|setup\.py|pyproject\.toml|setup\.cfg)$/.test(k) || /\.dist-info\/(METADATA|RECORD|WHEEL)$/.test(k))
        .sort((a, b) => depth(a) - depth(b))[0];
    let out;
    if (marker) {
        const isDist = /\.dist-info\//.test(marker);
        const dir = isDist ? marker.replace(/[^/]*\.dist-info\/[^/]+$/, '') : marker.replace(/[^/]+$/, '');
        out = sub(dir);
    } else {
        // no marker captured: root is the parent of the shallowest package directory
        const init = keys.filter((k) => k.endsWith('/__init__.py')).sort((a, b) => depth(a) - depth(b))[0];
        out = init ? sub(init.split('/').slice(0, -2).join('/') + (depth(init) > 2 ? '/' : '')) : files;
    }
    if (out.size === 1 && /\.(whl|tar\.gz|zip)$/i.test([...out.keys()][0])) {
        const [[n, b]] = out;
        return { files: stripCommonRoot(readArchive(b, n)), kind: /\.whl$/i.test(n) ? 'wheel' : 'sdist' };
    }
    const kind = [...out.keys()].some((k) => /^[^/]+\.dist-info\/(METADATA|RECORD)$/.test(k)) && !out.has('setup.py') && !out.has('PKG-INFO') ? 'wheel' : 'sdist';
    return { files: out, kind };
}

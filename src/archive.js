// In-memory readers for .tgz / .tar.gz / .zip / .whl archives.
// Nothing is written to disk and nothing from the archive is executed.
import zlib from 'node:zlib';

export const LIMITS = {
    maxCompressedBytes: 60 * 1024 * 1024,
    maxUnpackedBytes: 250 * 1024 * 1024,
    maxFiles: 30000,
    maxFileBytes: 40 * 1024 * 1024,
};

export class ArchiveError extends Error {}

function cleanPath(p) {
    // Normalise separators, drop leading "./" and "/", reject traversal segments.
    const parts = p.replace(/\\/g, '/').split('/').filter((s) => s && s !== '.');
    if (parts.some((s) => s === '..')) return null;
    return parts.join('/');
}

function readOctal(buf, start, len) {
    const s = buf.toString('latin1', start, start + len).replace(/\0.*$/s, '').trim();
    return s ? parseInt(s, 8) : 0;
}

function parsePax(buf) {
    const out = {};
    let i = 0;
    while (i < buf.length) {
        const sp = buf.indexOf(0x20, i);
        if (sp < 0) break;
        const len = parseInt(buf.toString('latin1', i, sp), 10);
        if (!len) break;
        const rec = buf.toString('utf8', sp + 1, i + len - 1);
        const eq = rec.indexOf('=');
        if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
        i += len;
    }
    return out;
}

/** Parse an uncompressed tar buffer into Map<path, Buffer> (regular files only). */
export function readTar(tar, limits = LIMITS) {
    const files = new Map();
    let off = 0;
    let total = 0;
    let longName = null;
    let pax = null;
    while (off + 512 <= tar.length) {
        const header = tar.subarray(off, off + 512);
        if (header.every((b) => b === 0)) break;
        let name = header.toString('utf8', 0, 100).replace(/\0.*$/s, '');
        const size = readOctal(header, 124, 12);
        const type = String.fromCharCode(header[156] || 0x30);
        const prefix = header.toString('utf8', 345, 500).replace(/\0.*$/s, '');
        if (prefix && header.toString('latin1', 257, 262) === 'ustar') name = `${prefix}/${name}`;
        const dataStart = off + 512;
        const data = tar.subarray(dataStart, dataStart + size);
        off = dataStart + Math.ceil(size / 512) * 512;
        if (type === 'L') { longName = data.toString('utf8').replace(/\0.*$/s, ''); continue; }
        if (type === 'x') { pax = parsePax(data); continue; }
        if (type === 'g') continue;
        if (longName) { name = longName; longName = null; }
        if (pax?.path) name = pax.path;
        pax = null;
        if (type !== '0' && type !== '\0' && type !== '7') continue; // dirs, links, devices: ignored
        const p = cleanPath(name);
        if (!p) continue;
        total += size;
        if (files.size >= limits.maxFiles) throw new ArchiveError(`archive has more than ${limits.maxFiles} files`);
        if (total > limits.maxUnpackedBytes) throw new ArchiveError(`archive unpacks to more than ${limits.maxUnpackedBytes} bytes`);
        files.set(p, size > limits.maxFileBytes ? Buffer.alloc(0) : Buffer.from(data));
        if (size > limits.maxFileBytes) files.get(p).oversize = size;
    }
    return files;
}

export function gunzipBounded(buf, limits = LIMITS) {
    try {
        return zlib.gunzipSync(buf, { maxOutputLength: limits.maxUnpackedBytes + 1024 * 1024 });
    } catch (e) {
        if (e.code === 'ERR_BUFFER_TOO_LARGE' || /maxOutputLength|Cannot create a Buffer/.test(e.message)) {
            throw new ArchiveError('archive unpacks to more than the size limit');
        }
        throw new ArchiveError(`gzip: ${e.message}`);
    }
}

/** Parse a zip (wheel, zip sdist) into Map<path, Buffer> using the central directory. */
export function readZip(zip, limits = LIMITS) {
    const files = new Map();
    let eocd = -1;
    for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
        if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new ArchiveError('zip: end of central directory not found');
    let count = zip.readUInt16LE(eocd + 10);
    let cdOff = zip.readUInt32LE(eocd + 16);
    if (cdOff === 0xffffffff || count === 0xffff) {
        const loc = zip.readUInt32LE(eocd - 20) === 0x07064b50 ? Number(zip.readBigUInt64LE(eocd - 12)) : -1;
        if (loc < 0 || zip.readUInt32LE(loc) !== 0x06064b50) throw new ArchiveError('zip64: locator not found');
        count = Number(zip.readBigUInt64LE(loc + 32));
        cdOff = Number(zip.readBigUInt64LE(loc + 48));
    }
    if (count > limits.maxFiles) throw new ArchiveError(`archive has more than ${limits.maxFiles} files`);
    let p = cdOff;
    let total = 0;
    for (let n = 0; n < count; n++) {
        if (zip.readUInt32LE(p) !== 0x02014b50) throw new ArchiveError('zip: bad central directory entry');
        const flags = zip.readUInt16LE(p + 8);
        const method = zip.readUInt16LE(p + 10);
        let csize = zip.readUInt32LE(p + 20);
        let usize = zip.readUInt32LE(p + 24);
        const nlen = zip.readUInt16LE(p + 28);
        const xlen = zip.readUInt16LE(p + 30);
        const clen = zip.readUInt16LE(p + 32);
        let lho = zip.readUInt32LE(p + 42);
        const name = zip.toString(flags & 0x800 ? 'utf8' : 'latin1', p + 46, p + 46 + nlen);
        // zip64 extra field
        let x = p + 46 + nlen;
        const xend = x + xlen;
        while (x + 4 <= xend) {
            const id = zip.readUInt16LE(x);
            const sz = zip.readUInt16LE(x + 2);
            if (id === 0x0001) {
                let q = x + 4;
                if (usize === 0xffffffff) { usize = Number(zip.readBigUInt64LE(q)); q += 8; }
                if (csize === 0xffffffff) { csize = Number(zip.readBigUInt64LE(q)); q += 8; }
                if (lho === 0xffffffff) { lho = Number(zip.readBigUInt64LE(q)); }
            }
            x += 4 + sz;
        }
        p = xend + clen;
        if (name.endsWith('/')) continue;
        const cp = cleanPath(name);
        if (!cp) continue;
        total += usize;
        if (total > limits.maxUnpackedBytes) throw new ArchiveError(`archive unpacks to more than ${limits.maxUnpackedBytes} bytes`);
        if (flags & 0x1) { files.set(cp, Object.assign(Buffer.alloc(0), { encrypted: true })); continue; }
        if (zip.readUInt32LE(lho) !== 0x04034b50) throw new ArchiveError('zip: bad local header');
        const dataStart = lho + 30 + zip.readUInt16LE(lho + 26) + zip.readUInt16LE(lho + 28);
        const raw = zip.subarray(dataStart, dataStart + csize);
        if (usize > limits.maxFileBytes) { files.set(cp, Object.assign(Buffer.alloc(0), { oversize: usize })); continue; }
        let data;
        if (method === 0) data = Buffer.from(raw);
        else if (method === 8) {
            try {
                data = zlib.inflateRawSync(raw, { maxOutputLength: limits.maxFileBytes + 1 });
            } catch (e) {
                throw new ArchiveError(`zip: cannot inflate ${cp}: ${e.message}`);
            }
        } else { files.set(cp, Object.assign(Buffer.alloc(0), { unsupported: method })); continue; }
        files.set(cp, data);
    }
    return files;
}

/** Detect archive kind from the bytes and read it. */
export function readArchive(buf, filename = '', limits = LIMITS) {
    if (buf.length > limits.maxCompressedBytes) throw new ArchiveError(`download larger than ${limits.maxCompressedBytes} bytes`);
    if (buf[0] === 0x1f && buf[1] === 0x8b) return readTar(gunzipBounded(buf, limits), limits);
    if (buf.readUInt32LE(0) === 0x04034b50 || /\.(zip|whl|egg)$/i.test(filename)) return readZip(buf, limits);
    if (buf.length > 262 && buf.toString('latin1', 257, 262) === 'ustar') return readTar(buf, limits);
    throw new ArchiveError(`unsupported archive format: ${filename || 'unknown'}`);
}

/** Strip one common leading directory (npm "package/", sdist "name-1.0/"). */
export function stripCommonRoot(files) {
    const keys = [...files.keys()];
    if (!keys.length) return files;
    const first = keys[0].split('/')[0];
    if (!keys.every((k) => k.includes('/') && k.split('/')[0] === first)) return files;
    const out = new Map();
    for (const [k, v] of files) out.set(k.slice(first.length + 1), v);
    return out;
}

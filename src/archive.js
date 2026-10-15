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

function readSize(buf, start, len) {
    // GNU base-256 sizes (high bit set) are refused rather than guessed.
    if (buf[start] & 0x80) throw new ArchiveError('tar: base-256 size field not supported');
    const s = buf.toString('latin1', start, start + len).replace(/\0.*$/s, '').trim();
    if (!s) return 0;
    if (!/^[0-7]+$/.test(s)) throw new ArchiveError('tar: malformed size field');
    const n = parseInt(s, 8);
    if (!Number.isSafeInteger(n)) throw new ArchiveError('tar: size field out of range');
    return n;
}

/** PAX extended header records: "<len> <key>=<value>\n", each len counting the whole record. */
function parsePax(buf) {
    const out = {};
    let i = 0;
    while (i < buf.length) {
        if (buf[i] === 0) break; // trailing padding
        const sp = buf.indexOf(0x20, i);
        if (sp < 0 || sp - i > 20) throw new ArchiveError('tar: malformed PAX record');
        const digits = buf.toString('latin1', i, sp);
        if (!/^[1-9]\d*$/.test(digits)) throw new ArchiveError('tar: malformed PAX record length');
        const len = Number(digits);
        const end = i + len;
        if (!Number.isSafeInteger(len) || end <= sp + 1 || end > buf.length || buf[end - 1] !== 0x0a) throw new ArchiveError('tar: PAX record length out of bounds');
        const rec = buf.toString('utf8', sp + 1, end - 1);
        const eq = rec.indexOf('=');
        if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
        i = end;
    }
    return out;
}

/** Parse an uncompressed tar buffer into Map<path, Buffer> (regular files only). */
export function readTar(tar, limits = LIMITS) {
    const files = new Map();
    let off = 0;
    let total = 0;
    let entries = 0;
    let longName = null;
    let pax = null;
    while (off + 512 <= tar.length) {
        const header = tar.subarray(off, off + 512);
        if (header.every((b) => b === 0)) break;
        if (++entries > limits.maxFiles * 4) throw new ArchiveError('tar: too many entries');
        let name = header.toString('utf8', 0, 100).replace(/\0.*$/s, '');
        const size = readSize(header, 124, 12);
        const type = String.fromCharCode(header[156] || 0x30);
        const prefix = header.toString('utf8', 345, 500).replace(/\0.*$/s, '');
        if (prefix && header.toString('latin1', 257, 262) === 'ustar') name = `${prefix}/${name}`;
        const dataStart = off + 512;
        const regular = type === '0' || type === '\0' || type === '7';
        const meta = type === 'L' || type === 'x' || type === 'g';
        const dataLen = size;
        if (dataStart + dataLen > tar.length) throw new ArchiveError('tar: entry runs past the end of the archive');
        const data = tar.subarray(dataStart, dataStart + dataLen);
        off = dataStart + Math.ceil(dataLen / 512) * 512;
        if (meta && dataLen > 1024 * 1024) throw new ArchiveError('tar: oversized metadata entry');
        if (type === 'L') { longName = data.toString('utf8').replace(/\0.*$/s, ''); continue; }
        if (type === 'x') { pax = parsePax(data); continue; }
        if (type === 'g') continue;
        if (longName) { name = longName; longName = null; }
        if (pax?.path) name = pax.path;
        pax = null;
        if (!regular) continue; // dirs, links, devices: ignored
        const p = cleanPath(name);
        if (!p) continue;
        if (files.size >= limits.maxFiles) throw new ArchiveError(`archive has more than ${limits.maxFiles} files`);
        if (size > limits.maxFileBytes) { files.set(p, Object.assign(Buffer.alloc(0), { oversize: size })); continue; }
        total += data.length;
        if (total > limits.maxUnpackedBytes) throw new ArchiveError(`archive unpacks to more than ${limits.maxUnpackedBytes} bytes`);
        files.set(p, Buffer.from(data));
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

function u32(zip, at) {
    if (at < 0 || at + 4 > zip.length) throw new ArchiveError('zip: offset out of bounds');
    return zip.readUInt32LE(at);
}
function u16(zip, at) {
    if (at < 0 || at + 2 > zip.length) throw new ArchiveError('zip: offset out of bounds');
    return zip.readUInt16LE(at);
}
function u64(zip, at) {
    if (at < 0 || at + 8 > zip.length) throw new ArchiveError('zip: offset out of bounds');
    const n = Number(zip.readBigUInt64LE(at));
    if (!Number.isSafeInteger(n)) throw new ArchiveError('zip: value out of range');
    return n;
}

/**
 * Parse a zip (wheel, zip sdist) into Map<path, Buffer> using the central directory. Every
 * offset is bounds-checked, every entry's actual size must equal its declared size, and the
 * bytes actually retained count against the archive limits.
 */
export function readZip(zip, limits = LIMITS) {
    const files = new Map();
    let eocd = -1;
    for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
        if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new ArchiveError('zip: end of central directory not found');
    let count = u16(zip, eocd + 10);
    let cdOff = u32(zip, eocd + 16);
    if (cdOff === 0xffffffff || count === 0xffff) {
        const loc = eocd >= 20 && u32(zip, eocd - 20) === 0x07064b50 ? u64(zip, eocd - 12) : -1;
        if (loc < 0 || u32(zip, loc) !== 0x06064b50) throw new ArchiveError('zip64: locator not found');
        count = u64(zip, loc + 32);
        cdOff = u64(zip, loc + 48);
    }
    if (count > limits.maxFiles) throw new ArchiveError(`archive has more than ${limits.maxFiles} files`);
    let p = cdOff;
    let total = 0;
    for (let n = 0; n < count; n++) {
        if (u32(zip, p) !== 0x02014b50) throw new ArchiveError('zip: bad central directory entry');
        const flags = u16(zip, p + 8);
        const method = u16(zip, p + 10);
        let csize = u32(zip, p + 20);
        let usize = u32(zip, p + 24);
        const nlen = u16(zip, p + 28);
        const xlen = u16(zip, p + 30);
        const clen = u16(zip, p + 32);
        let lho = u32(zip, p + 42);
        const xend = p + 46 + nlen + xlen;
        if (xend + clen > zip.length) throw new ArchiveError('zip: central directory entry out of bounds');
        const name = zip.toString(flags & 0x800 ? 'utf8' : 'latin1', p + 46, p + 46 + nlen);
        // zip64 extra field
        let x = p + 46 + nlen;
        while (x + 4 <= xend) {
            const id = u16(zip, x);
            const sz = u16(zip, x + 2);
            if (x + 4 + sz > xend) throw new ArchiveError('zip: extra field out of bounds');
            if (id === 0x0001) {
                let q = x + 4;
                const take = () => { if (q + 8 > x + 4 + sz) throw new ArchiveError('zip64: extra field too short'); const v = u64(zip, q); q += 8; return v; };
                if (usize === 0xffffffff) usize = take();
                if (csize === 0xffffffff) csize = take();
                if (lho === 0xffffffff) lho = take();
            }
            x += 4 + sz;
        }
        p = xend + clen;
        if (name.endsWith('/')) continue;
        const cp = cleanPath(name);
        if (!cp) continue;
        if (flags & 0x1) { files.set(cp, Object.assign(Buffer.alloc(0), { encrypted: true })); continue; }
        if (usize > limits.maxFileBytes) { files.set(cp, Object.assign(Buffer.alloc(0), { oversize: usize })); continue; }
        if (method !== 0 && method !== 8) { files.set(cp, Object.assign(Buffer.alloc(0), { unsupported: method })); continue; }
        if (u32(zip, lho) !== 0x04034b50) throw new ArchiveError('zip: bad local header');
        const dataStart = lho + 30 + u16(zip, lho + 26) + u16(zip, lho + 28);
        if (dataStart + csize > zip.length) throw new ArchiveError(`zip: data for ${cp} runs past the end of the archive`);
        const raw = zip.subarray(dataStart, dataStart + csize);
        const budget = Math.min(limits.maxFileBytes, limits.maxUnpackedBytes - total);
        if (usize > budget) throw new ArchiveError(`archive unpacks to more than ${limits.maxUnpackedBytes} bytes`);
        let data;
        if (method === 0) {
            if (csize !== usize) throw new ArchiveError(`zip: stored size mismatch for ${cp}`);
            data = Buffer.from(raw);
        } else {
            try {
                data = zlib.inflateRawSync(raw, { maxOutputLength: usize + 1 });
            } catch (e) {
                throw new ArchiveError(`zip: cannot inflate ${cp} to its declared size: ${e.message}`);
            }
            if (data.length !== usize) throw new ArchiveError(`zip: ${cp} inflates to ${data.length} bytes, declared ${usize}`);
        }
        total += data.length;
        files.set(cp, data);
    }
    return files;
}

/** Detect archive kind from the bytes and read it. */
export function readArchive(buf, filename = '', limits = LIMITS) {
    if (buf.length > limits.maxCompressedBytes) throw new ArchiveError(`download larger than ${limits.maxCompressedBytes} bytes`);
    if (buf.length < 4) throw new ArchiveError(`archive too short: ${filename || 'unknown'}`);
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

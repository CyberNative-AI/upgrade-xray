// Small builders for synthetic archives and a recording fetch stub used by the tests.
import zlib from 'node:zlib';

function tarHeader(name, size, type = '0') {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100, 'utf8');
    h.write('0000644\0', 100);
    h.write('0000000\0', 108);
    h.write('0000000\0', 116);
    h.write(`${size.toString(8).padStart(11, '0')}\0`, 124);
    h.write('00000000000\0', 136);
    h.write(type, 156);
    h.write('ustar\0', 257);
    h.write('00', 263);
    h.fill(0x20, 148, 156);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
    return h;
}

/** entries: [{ name, data: Buffer|string, type? }] → uncompressed tar */
export function tar(entries) {
    const parts = [];
    for (const e of entries) {
        const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? '');
        parts.push(tarHeader(e.name, e.size ?? data.length, e.type || '0'), data, Buffer.alloc((512 - (data.length % 512)) % 512));
    }
    parts.push(Buffer.alloc(1024));
    return Buffer.concat(parts);
}

export const tgz = (entries) => zlib.gzipSync(tar(entries));

/**
 * entries: [{ name, data, method?: 0|8, usize?, csize?, flags?, offsetOf?: index }] → zip.
 * usize/csize override the declared sizes; offsetOf points an entry at another entry's data.
 */
export function zip(entries) {
    const locals = [];
    const central = [];
    const offsets = [];
    const dataInfo = [];
    let off = 0;
    for (const e of entries) {
        const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? '');
        const method = e.method ?? 8;
        const comp = method === 8 ? zlib.deflateRawSync(raw) : raw;
        const name = Buffer.from(e.name);
        const lh = Buffer.alloc(30);
        lh.writeUInt32LE(0x04034b50, 0);
        lh.writeUInt16LE(20, 4);
        lh.writeUInt16LE(e.flags || 0, 6);
        lh.writeUInt16LE(method, 8);
        lh.writeUInt32LE(e.csize ?? comp.length, 18);
        lh.writeUInt32LE(e.usize ?? raw.length, 22);
        lh.writeUInt16LE(name.length, 26);
        offsets.push(off);
        dataInfo.push({ csize: comp.length, usize: raw.length });
        locals.push(lh, name, comp);
        off += 30 + name.length + comp.length;
    }
    entries.forEach((e, i) => {
        const name = Buffer.from(e.name);
        const ch = Buffer.alloc(46);
        const src = e.offsetOf ?? i;
        ch.writeUInt32LE(0x02014b50, 0);
        ch.writeUInt16LE(20, 4);
        ch.writeUInt16LE(20, 6);
        ch.writeUInt16LE(e.flags || 0, 8);
        ch.writeUInt16LE(e.method ?? 8, 10);
        ch.writeUInt32LE(e.csize ?? dataInfo[src].csize, 20);
        ch.writeUInt32LE(e.usize ?? dataInfo[src].usize, 24);
        ch.writeUInt16LE(name.length, 28);
        ch.writeUInt32LE(offsets[src], 42);
        central.push(ch, name);
    });
    const cd = Buffer.concat(central);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(cd.length, 12);
    eocd.writeUInt32LE(off, 16);
    return Buffer.concat([...locals, cd, eocd]);
}

/**
 * Replace globalThis.fetch with a recorder. handler(url) returns a Response (or undefined → 404).
 * Returns { calls, restore }.
 */
export function stubFetch(handler = () => undefined) {
    const real = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url, opts = {}) => {
        const u = String(url);
        calls.push({ url: u, redirect: opts.redirect });
        return (await handler(u, opts)) || new Response('not found', { status: 404 });
    };
    return { calls, restore: () => { globalThis.fetch = real; } };
}

/** Package names that reached the npm registry or PyPI JSON API in recorded calls. */
export function lookedUpNames(calls) {
    const names = [];
    for (const { url } of calls) {
        const u = new URL(url);
        if (u.hostname === 'registry.npmjs.org') names.push(decodeURIComponent(u.pathname.slice(1)).split('/-/')[0]);
        else if (u.hostname === 'pypi.org') names.push(decodeURIComponent(u.pathname.split('/')[2]));
        else names.push(`OTHER:${u.hostname}`);
    }
    return [...new Set(names)].sort();
}

/** In-memory io for runInput. */
export function memoryIo(extra = {}) {
    const io = {
        items: [], kv: {}, charges: [], failed: null,
        pushData: async (d) => { io.items.push(d); },
        setValue: async (k, v) => { io.kv[k] = v; },
        charge: async (c) => { io.charges.push(c); },
        withinLimit: () => Infinity,
        fail: async (m) => { io.failed = m; },
        ...extra,
    };
    return io;
}

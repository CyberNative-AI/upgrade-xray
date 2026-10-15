import { Actor, log } from 'apify';
import { analyzePackage } from './analyze.js';
import { parseLockfile, diffLockfiles, LockfileError } from './lockfile.js';
import { packageMarkdown, packagesReport, lockfileReport, summaryLine } from './report.js';

const EVENT_PACKAGE = 'package-diff';
const EVENT_LOCKFILE = 'lockfile-report';

/** "npm:chalk@5.6.0..5.6.1", "pypi:requests==2.32.0", "@scope/x@^2", "chalk" */
export function parsePackageSpec(s, defaultEcosystem = 'npm') {
    if (s && typeof s === 'object') return { ecosystem: (s.ecosystem || defaultEcosystem).toLowerCase(), name: s.name, from: s.from || s.fromVersion, to: s.to || s.toVersion };
    let t = String(s).trim();
    let ecosystem = defaultEcosystem;
    const m = t.match(/^(npm|pypi|pip|python):/i);
    if (m) { ecosystem = /npm/i.test(m[1]) ? 'npm' : 'pypi'; t = t.slice(m[0].length); }
    let name = t; let range = '';
    if (ecosystem === 'pypi' && /==/.test(t)) { [name, range] = t.split('=='); }
    else {
        const at = t.indexOf('@', t.startsWith('@') ? 1 : 0);
        if (at > 0) { name = t.slice(0, at); range = t.slice(at + 1); }
    }
    let from; let to;
    const r = range.split(/\s*(?:\.\.|->|→)\s*/);
    if (r.length === 2) [from, to] = r; else to = r[0] || undefined;
    if (!name || /\s/.test(name.trim())) throw new Error(`cannot read package spec "${s}"`);
    return { ecosystem, name: name.trim(), from: from || undefined, to: to || undefined };
}

async function pool(items, n, fn) {
    const out = new Array(items.length);
    let i = 0;
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
        while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
    }));
    return out;
}

const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (x instanceof Set ? [...x] : x instanceof Map ? Object.fromEntries(x) : x)));

function toItem(r, extra = {}) {
    const md = packageMarkdown(r, { heading: '###' });
    return plain({
        ecosystem: r.ecosystem, name: r.name, fromVersion: r.fromVersion ?? null, toVersion: r.toVersion ?? null,
        verdict: r.error ? 'error' : r.verdict, breaking: r.breaking ?? false, counts: r.counts || {},
        summary: r.error ? `Not analysed: ${r.error}` : md.split('\n').filter((l) => l.startsWith('- **')).slice(0, 5).map((l) => l.slice(2)).join('\n') || 'Nothing new found.',
        findings: r.findings || [], newDependencies: r.newDependencies || [], removedDependencies: r.removedDependencies || [],
        files: r.files || null, artifacts: r.artifacts || null, notes: r.notes || [], addedPackage: Boolean(r.addedPackage), error: r.error || null,
        markdown: md, analysisMs: r.analysisMs ?? null, ...extra,
    });
}

async function loadText(text, url, label) {
    if (text && String(text).trim()) return String(text);
    if (url) {
        const res = await fetch(url, { signal: AbortSignal.timeout(60000), headers: { 'user-agent': 'upgrade-xray/0.1' } });
        if (!res.ok) throw new Error(`${label}: HTTP ${res.status} from ${url}`);
        const len = Number(res.headers.get('content-length') || 0);
        if (len > 50 * 1024 * 1024) throw new Error(`${label}: larger than 50 MB`);
        return await res.text();
    }
    return null;
}

async function safeAnalyze(spec) {
    try {
        return await analyzePackage(spec);
    } catch (e) {
        log.warning(`${spec.ecosystem}:${spec.name}: ${e.message}`);
        return { ecosystem: spec.ecosystem, name: spec.name, fromVersion: spec.from ?? null, toVersion: spec.to ?? null, error: e.message, addedPackage: Boolean(spec.added) };
    }
}

async function run() {
    await Actor.init();
    const input = (await Actor.getInput()) || {};
    const concurrency = Math.max(1, Math.min(8, Number(input.concurrency) || 4));
    const charging = Actor.getChargingManager();
    const withinLimit = (ev) => { try { return charging.calculateMaxEventChargeCountWithinLimit(ev); } catch { return Infinity; } };

    const before = await loadText(input.lockfileBefore, input.lockfileBeforeUrl, 'lockfileBefore');
    const after = await loadText(input.lockfileAfter, input.lockfileAfterUrl, 'lockfileAfter');

    if (before || after) {
        // ---------------- Lockfile mode ----------------
        if (!before || !after) throw new Error('Lockfile mode needs both lockfileBefore and lockfileAfter (text or URL).');
        if (withinLimit(EVENT_LOCKFILE) < 1) {
            await Actor.fail('The run\'s maximum charge is below the price of one lockfile report; raise the limit and run again.');
            return;
        }
        const hint = input.lockfileName || input.lockfileAfterUrl || '';
        let diff;
        try {
            diff = diffLockfiles(parseLockfile(before, hint), parseLockfile(after, hint));
        } catch (e) {
            if (e instanceof LockfileError) { await Actor.fail(e.message); return; }
            throw e;
        }
        const maxPackages = Math.max(1, Math.min(300, Number(input.maxPackages) || 150));
        const includeAdded = input.includeAddedPackages !== false;
        let work = diff.updated.map((u) => ({ ecosystem: diff.ecosystem, name: u.name, from: u.from, to: u.to }));
        if (includeAdded) work = work.concat(diff.added.map((a) => ({ ecosystem: diff.ecosystem, name: a.name, to: a.to, added: true })));
        const skipped = work.slice(maxPackages).map((w) => ({ name: w.name, to: w.to }));
        work = work.slice(0, maxPackages);
        log.info(`${diff.type} lockfile: ${diff.updated.length} updated, ${diff.added.length} added, ${diff.removed.length} removed; analysing ${work.length}`);
        const results = await pool(work, concurrency, async (spec) => {
            const r = await safeAnalyze(spec);
            await Actor.pushData(toItem(r, { mode: 'lockfile', lockfileType: diff.type }));
            return r;
        });
        const md = lockfileReport(results, diff, { skipped });
        await Actor.setValue('REPORT', md, { contentType: 'text/markdown; charset=utf-8' });
        const counts = summaryLine(results);
        await Actor.setValue('OUTPUT', plain({ mode: 'lockfile', lockfileType: diff.type, ecosystem: diff.ecosystem, verdict: counts.review ? 'review' : counts.notice ? 'notice' : 'clean', counts, updated: diff.updated.length, added: diff.added.length, removed: diff.removed.length, nonRegistry: diff.nonRegistry, skipped, markdown: md }));
        if (work.length) await Actor.charge({ eventName: EVENT_LOCKFILE, count: 1 });
        log.info(`Report: ${counts.review} review, ${counts.notice} notice, ${counts.clean} clean, ${counts.error} errors`);
        await Actor.exit();
        return;
    }

    // ---------------- Package mode ----------------
    const raw = [].concat(input.packages || []);
    if (!raw.length) {
        await Actor.fail('Give "packages" (for example "npm:chalk@5.6.0..5.6.1") or both lockfiles.');
        return;
    }
    const specs = [];
    for (const s of raw) {
        try { specs.push(parsePackageSpec(s, (input.ecosystem || 'npm').toLowerCase())); } catch (e) { log.warning(e.message); await Actor.pushData(toItem({ ecosystem: input.ecosystem || 'npm', name: String(s), error: e.message })); }
    }
    const allowed = withinLimit(EVENT_PACKAGE);
    if (specs.length > allowed) log.warning(`The run's maximum charge covers ${allowed} package diff(s); the rest are skipped.`);
    const todo = specs.slice(0, Math.max(0, Math.min(specs.length, allowed, 200)));
    const results = await pool(todo, concurrency, async (spec) => {
        const r = await safeAnalyze(spec);
        await Actor.pushData(toItem(r, { mode: 'package' }));
        if (!r.error) await Actor.charge({ eventName: EVENT_PACKAGE, count: 1 });
        return r;
    });
    const md = packagesReport(results);
    await Actor.setValue('REPORT', md, { contentType: 'text/markdown; charset=utf-8' });
    const counts = summaryLine(results);
    await Actor.setValue('OUTPUT', plain({ mode: 'package', verdict: counts.review ? 'review' : counts.notice ? 'notice' : 'clean', counts, markdown: md }));
    await Actor.exit();
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
    run().catch(async (e) => { log.exception(e, 'Run failed'); await Actor.fail(e.message); });
}

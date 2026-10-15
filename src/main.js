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
        verdict: r.error ? 'error' : r.verdict, coverage: r.error ? { complete: false } : (r.coverage || { complete: true }), breaking: r.breaking ?? false, counts: r.counts || {},
        summary: r.error ? `Not analysed: ${r.error}` : md.split('\n').filter((l) => l.startsWith('- **')).slice(0, 5).map((l) => l.slice(2)).join('\n') || 'Nothing new found.',
        findings: r.findings || [], newDependencies: r.newDependencies || [], removedDependencies: r.removedDependencies || [],
        files: r.files || null, artifacts: r.artifacts || null, notes: r.notes || [], addedPackage: Boolean(r.addedPackage), error: r.error || null,
        markdown: md, analysisMs: r.analysisMs ?? null, ...extra,
    });
}

export const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024;

/** Lockfiles are accepted as pasted text only, up to MAX_LOCKFILE_BYTES each. */
export function lockfileText(input, key) {
    if (input[`${key}Url`]) throw new LockfileError(`${key}Url is not supported: paste the lockfile text into ${key} instead.`);
    const v = input[key];
    if (v === undefined || v === null) return null;
    if (typeof v !== 'string') throw new LockfileError(`${key} must be text.`);
    if (Buffer.byteLength(v, 'utf8') > MAX_LOCKFILE_BYTES) throw new LockfileError(`${key} is larger than ${MAX_LOCKFILE_BYTES / 1024 / 1024} MB.`);
    return v.trim() ? v : null;
}

/**
 * Overall verdict for a run. "review"/"notice" when an analysed package needs it; otherwise
 * "error" when nothing could be analysed, "incomplete" when some changes were not analysed,
 * and "clean" only when every change in scope was analysed and nothing new was found.
 */
export function overallVerdict(counts, { excluded = 0 } = {}) {
    if (counts.review) return 'review';
    if (counts.notice) return 'notice';
    const analysed = counts.clean;
    if (!analysed && counts.error) return 'error';
    if (counts.error || excluded) return 'incomplete';
    return 'clean';
}

async function safeAnalyze(spec) {
    try {
        return await analyzePackage(spec);
    } catch (e) {
        log.warning(`${spec.ecosystem}:${spec.name}: ${e.message}`);
        return { ecosystem: spec.ecosystem, name: spec.name, fromVersion: spec.from ?? null, toVersion: spec.to ?? null, error: e.message, addedPackage: Boolean(spec.added) };
    }
}

/**
 * Run one input. io: { pushData, setValue, charge, withinLimit, fail, analyze? }.
 * Returns the OUTPUT object, or null after io.fail().
 */
export async function runInput(input, io) {
    const analyze = io.analyze || safeAnalyze;
    const concurrency = Math.max(1, Math.min(8, Number(input.concurrency) || 4));
    let before; let after;
    try {
        before = lockfileText(input, 'lockfileBefore');
        after = lockfileText(input, 'lockfileAfter');
    } catch (e) { await io.fail(e.message); return null; }

    if (before || after) {
        // ---------------- Lockfile mode ----------------
        if (!before || !after) { await io.fail('Lockfile mode needs both lockfileBefore and lockfileAfter.'); return null; }
        if (io.withinLimit(EVENT_LOCKFILE) < 1) {
            await io.fail('The run\'s maximum charge is below the price of one lockfile report; raise the limit and run again.');
            return null;
        }
        const hint = typeof input.lockfileName === 'string' ? input.lockfileName : '';
        let diff;
        try {
            diff = diffLockfiles(parseLockfile(before, hint), parseLockfile(after, hint), { assumePublic: input.assumePublicRegistry === true });
        } catch (e) {
            if (e instanceof LockfileError) { await io.fail(e.message); return null; }
            throw e;
        }
        const maxPackages = Math.max(1, Math.min(300, Number(input.maxPackages) || 150));
        const includeAdded = input.includeAddedPackages !== false;
        let work = diff.updated.map((u) => ({ ecosystem: diff.ecosystem, name: u.name, from: u.from, to: u.to }));
        if (includeAdded) work = work.concat(diff.added.map((a) => ({ ecosystem: diff.ecosystem, name: a.name, to: a.to, added: true })));
        const skipped = work.slice(maxPackages).map((w) => ({ name: w.name, to: w.to }));
        work = work.slice(0, maxPackages);
        log.info(`${diff.type} lockfile: ${diff.updated.length} updated, ${diff.added.length} added, ${diff.removed.length} removed, ${diff.nonRegistry.length} not looked up; analysing ${work.length}`);
        const results = await pool(work, concurrency, async (spec) => {
            const r = await analyze(spec);
            await io.pushData(toItem(r, { mode: 'lockfile', lockfileType: diff.type }));
            return r;
        });
        const counts = summaryLine(results);
        const coverage = coverageOf(results, { notLookedUp: diff.nonRegistry.length, overLimit: skipped.length, addedNotScanned: includeAdded ? 0 : diff.added.length });
        const verdict = overallVerdict(counts, { excluded: coverage.notLookedUp + coverage.overLimit + coverage.addedNotScanned });
        const md = lockfileReport(results, diff, { skipped, verdict, coverage });
        await io.setValue('REPORT', md, { contentType: 'text/markdown; charset=utf-8' });
        const output = plain({ mode: 'lockfile', lockfileType: diff.type, ecosystem: diff.ecosystem, verdict, complete: verdict !== 'error' && coverage.complete, counts, coverage, updated: diff.updated.length, added: diff.added.length, removed: diff.removed.length, nonRegistry: diff.nonRegistry, originChanges: diff.originChanges, skipped, markdown: md });
        await io.setValue('OUTPUT', output);
        // One report charge, only when at least one package was actually analysed.
        if (coverage.analysed > 0) await io.charge({ eventName: EVENT_LOCKFILE, count: 1 });
        log.info(`Report: ${verdict}; ${counts.review} review, ${counts.notice} notice, ${counts.clean} clean, ${counts.error} errors`);
        return output;
    }

    // ---------------- Package mode ----------------
    const raw = [].concat(input.packages || []);
    if (!raw.length) {
        await io.fail('Give "packages" (for example "npm:chalk@5.6.0..5.6.1") or both lockfiles.');
        return null;
    }
    const specs = [];
    const invalid = [];
    for (const s of raw) {
        try { specs.push(parsePackageSpec(s, (input.ecosystem || 'npm').toLowerCase())); } catch (e) {
            log.warning(e.message);
            const r = { ecosystem: input.ecosystem || 'npm', name: String(s).slice(0, 200), error: e.message };
            invalid.push(r);
            await io.pushData(toItem(r, { mode: 'package' }));
        }
    }
    const allowed = io.withinLimit(EVENT_PACKAGE);
    if (specs.length > allowed) log.warning(`The run's maximum charge covers ${allowed} package diff(s); the rest are skipped.`);
    const todo = specs.slice(0, Math.max(0, Math.min(specs.length, allowed, 200)));
    const overLimit = specs.length - todo.length;
    const results = await pool(todo, concurrency, async (spec) => {
        const r = await analyze(spec);
        await io.pushData(toItem(r, { mode: 'package' }));
        if (!r.error) await io.charge({ eventName: EVENT_PACKAGE, count: 1 });
        return r;
    });
    const all = results.concat(invalid);
    const counts = summaryLine(all);
    const coverage = coverageOf(all, { overLimit });
    const verdict = overallVerdict(counts, { excluded: overLimit });
    const md = packagesReport(all, { verdict, coverage });
    await io.setValue('REPORT', md, { contentType: 'text/markdown; charset=utf-8' });
    const output = plain({ mode: 'package', verdict, complete: verdict !== 'error' && coverage.complete, counts, coverage, markdown: md });
    await io.setValue('OUTPUT', output);
    return output;
}

/** Machine-readable coverage: what was analysed, what failed, and what was left out and why. */
export function coverageOf(results, { notLookedUp = 0, overLimit = 0, addedNotScanned = 0 } = {}) {
    const failed = results.filter((r) => r.error).length;
    const analysed = results.length - failed;
    const partialFiles = results.filter((r) => !r.error && r.coverage && !r.coverage.complete).length;
    return { analysed, failed, notLookedUp, overLimit, addedNotScanned, packagesWithUnparsedFiles: partialFiles, complete: !failed && !notLookedUp && !overLimit && !addedNotScanned };
}

async function run() {
    await Actor.init();
    const input = (await Actor.getInput()) || {};
    const charging = Actor.getChargingManager();
    const withinLimit = (ev) => { try { return charging.calculateMaxEventChargeCountWithinLimit(ev); } catch { return Infinity; } };
    let failed = false;
    await runInput(input, {
        pushData: (d) => Actor.pushData(d),
        setValue: (k, v, o) => Actor.setValue(k, v, o),
        charge: (c) => Actor.charge(c),
        withinLimit,
        fail: async (msg) => { failed = true; await Actor.fail(msg); },
    });
    if (!failed) await Actor.exit();
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
    run().catch(async (e) => { log.exception(e, 'Run failed'); await Actor.fail(e.message); });
}

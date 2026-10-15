// Analyse one dependency update: fetch both published versions, snapshot, diff.
import { readArchive, stripCommonRoot } from './archive.js';
import { npmSnapshot, pypiSnapshot } from './snapshot.js';
import { diffSnapshots } from './diff.js';
import { SEVERITY_RANK } from './signals.js';
import {
    npmResolve, npmTarball, npmDepInfo, npmPackument, pypiResolve, pypiPickArtifacts, pypiFile, pypiDepInfo, npmOwners, pypiOwners, pypiProject,
} from './registry.js';

const YOUNG_DAYS = 14;

export async function snapshotFromArchive(ecosystem, buf, filename, kind) {
    const files = stripCommonRoot(readArchive(buf, filename));
    return ecosystem === 'npm' ? npmSnapshot(files) : pypiSnapshot(files, kind || (/\.whl$/i.test(filename) ? 'wheel' : 'sdist'));
}

export async function packageOwners(ecosystem, name) {
    try {
        return ecosystem === 'npm' ? npmOwners(await npmPackument(name, { full: true })) : pypiOwners((await pypiProject(name)).info);
    } catch { return []; }
}

export async function enrichNewDeps(ecosystem, result, referenceTime, owners = []) {
    const deps = result.findings.filter((f) => f.kind === 'new-dependency' && f.severity !== 'info').slice(0, 25);
    await Promise.all(deps.map(async (f) => {
        if (/^(git|https?|file|link|github)/.test(f.spec || '')) return;
        const name = ecosystem === 'npm' && /^npm:/.test(f.spec || '') ? f.spec.slice(4).replace(/@[^@]*$/, '') : f.dependency;
        const info = ecosystem === 'npm' ? await npmDepInfo(name) : await pypiDepInfo(name);
        f.dependencyInfo = info;
        if (info.exists === false) {
            f.severity = 'high';
            f.detail = `${f.detail}; this name does not exist on the ${ecosystem === 'npm' ? 'npm registry' : 'PyPI'} (removed, private or a dependency-confusion target)`;
        } else if (info.created && referenceTime) {
            const ageDays = (referenceTime - new Date(info.created).getTime()) / 86400000;
            f.dependencyInfo.ageDaysAtRelease = Math.round(ageDays * 10) / 10;
            if (ageDays < YOUNG_DAYS) {
                const shared = (info.owners || []).some((o) => owners.includes(o));
                f.dependencyInfo.sharesOwner = shared;
                f.severity = shared ? 'medium' : 'high';
                f.detail = `${f.detail}; first published ${Math.max(0, Math.round(ageDays))} day(s) before this release${shared ? ' by the same maintainers or repository owner' : ' by different maintainers'}`;
            }
        }
    }));
}

function rescore(result) {
    result.findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    const sec = result.findings.filter((f) => f.category !== 'breaking');
    const top = sec.length ? sec[0].severity : 'info';
    result.verdict = top === 'high' ? 'review' : top === 'medium' ? 'notice' : 'clean';
    result.counts = {};
    for (const f of result.findings) result.counts[f.severity] = (result.counts[f.severity] || 0) + 1;
}

/** npm: {name, from?, to?} → result */
export async function analyzeNpm({ name, from, to, added = false }, { enrich = true } = {}) {
    const r = await npmResolve(name, added ? undefined : from, to, { added });
    const [a, b] = await Promise.all([
        r.from ? npmTarball(name, r.from, r.fromMeta) : null,
        npmTarball(name, r.to, r.toMeta),
    ]);
    const oldSnap = a ? await snapshotFromArchive('npm', a.buf, a.filename) : null;
    const newSnap = await snapshotFromArchive('npm', b.buf, b.filename);
    const result = diffSnapshots(oldSnap, newSnap, { addedPackage: added });
    if (enrich) {
        let t = null;
        try { t = new Date((await npmPackument(name, { full: true })).time?.[r.to]).getTime() || null; } catch { /* age check falls back to now */ }
        await enrichNewDeps('npm', result, t || Date.now(), await packageOwners('npm', name));
        rescore(result);
    }
    return { ecosystem: 'npm', name, fromVersion: r.from, toVersion: r.to, ...result };
}

/** PyPI: {name, from?, to?} → result (wheel and sdist compared separately, merged) */
export async function analyzePypi({ name, from, to, added = false }, { enrich = true } = {}) {
    const r = await pypiResolve(name, added ? undefined : from, to, { added });
    const pairs = pypiPickArtifacts(r.fromFiles, r.toFiles);
    if (!pairs.length) throw new Error(`${name}: no wheel or sdist to compare`);
    const parts = [];
    const errors = [];
    for (const p of pairs) {
        try {
            const [a, b] = await Promise.all([p.from ? pypiFile(p.from) : null, pypiFile(p.to)]);
            const oldSnap = a ? await snapshotFromArchive('pypi', a.buf, a.filename, p.kind) : null;
            const newSnap = await snapshotFromArchive('pypi', b.buf, b.filename, p.kind);
            parts.push({ kind: p.kind, files: [p.from?.filename, p.to.filename], result: diffSnapshots(oldSnap, newSnap, { addedPackage: added }) });
        } catch (e) {
            errors.push(`${p.kind}: ${e.message}`);
        }
    }
    if (!parts.length) throw new Error(errors.join('; '));
    const merged = mergeArtifactResults(parts);
    merged.notes.push(...errors);
    if (enrich) {
        await enrichNewDeps('pypi', merged, r.toTime || Date.now(), await packageOwners('pypi', name));
        rescore(merged);
    }
    return { ecosystem: 'pypi', name, fromVersion: r.from, toVersion: r.to, artifacts: parts.map((p) => ({ kind: p.kind, files: p.files })), ...merged };
}

/** Merge wheel and sdist diffs: security findings from both (deduplicated), API/deps from the wheel when present. */
export function mergeArtifactResults(parts) {
    const primary = parts.find((p) => p.kind === 'wheel') || parts[0];
    const seen = new Set();
    const findings = [];
    for (const p of parts) {
        for (const f of p.result.findings) {
            if ((f.category === 'breaking' || f.category === 'dependency') && p !== primary) continue;
            const key = `${f.kind}|${f.title}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({ ...f, artifact: p.kind });
        }
    }
    const out = { ...primary.result, findings, notes: [...new Set(parts.flatMap((p) => p.result.notes))] };
    out.files = primary.result.files;
    rescore(out);
    out.breaking = findings.some((f) => f.category === 'breaking' && f.severity !== 'info');
    return out;
}

export async function analyzePackage(spec, opts) {
    const t0 = Date.now();
    const res = spec.ecosystem === 'pypi' ? await analyzePypi(spec, opts) : await analyzeNpm(spec, opts);
    res.analysisMs = Date.now() - t0;
    return res;
}

export { rescore };

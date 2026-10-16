// Compare two snapshots of the same package and produce findings and a verdict.
import { KINDS, SEVERITY_RANK } from './signals.js';
import { MARKED_TITLE, mark as v, mergeNotes, unmark } from './prose.js';

const INSTALL_CAP_KINDS = new Set(['network', 'shell', 'python-spawn', 'eval', 'encoded-exec', 'env-bulk', 'credential-path', 'exfil-endpoint', 'self-publish', 'persistence', 'secret-harvest', 'obfuscation', 'dynamic-require']);
// Strong indicators are compared file by file as well: one already elsewhere in the package (an
// npm tool that reads .npmrc, a migration script that runs subprocess at import time) must not
// hide the same indicator newly added to another existing file. Ordinary capabilities (network,
// shell, eval) stay package-wide: per file they mostly report refactors.
const PER_FILE_KINDS = new Set(['encoded-exec', 'credential-path', 'exfil-endpoint', 'self-publish', 'persistence', 'secret-harvest', 'global-hook']);
const MAX_LOCATIONS = 5;
const INERT_DIR = /(^|\/)(tests?|__tests__|testing|spec|examples?|docs?|benchmarks?|fixtures?)\//i;
const LOWER = { high: 'medium', medium: 'low', low: 'info', info: 'info' };

function groupSignals(snap) {
    const m = new Map();
    for (const s of snap.signals) {
        const key = `${s.kind}\u0000${s.detail}`;
        if (!m.has(key)) m.set(key, { kind: s.kind, detail: s.detail, locations: [] });
        const g = m.get(key);
        if (g.locations.length < 50) g.locations.push({ file: s.file, line: s.line });
    }
    return m;
}

/** A Python process started when the package is imported: from a package __init__ or at module level. */
const importLaunch = (g) => g.kind === 'python-spawn' && g.locations.some((l) => !INERT_DIR.test(l.file) && (/ at import time$/.test(g.detail) || /(^|\/)__init__\.py$/.test(l.file)));

function kindsByFile(snap, file) {
    return new Set(snap.signals.filter((s) => s.file === file).map((s) => `${s.kind}\u0000${s.detail}`));
}

function isNonRegistrySpec(spec) {
    return /^(git(\+\w+)?:|git@|github:|gitlab:|bitbucket:|https?:|file:|link:)|^[\w-]+\/[\w.-]+(#.*)?$/.test(spec) && !/^npm:/.test(spec);
}

/** "Network access" -> "network access"; acronyms and names keep their case ("URL with…", "CI", "Python"). */
const lower = (label) => (/^[A-Z][a-z]/.test(label) ? label[0].toLowerCase() + label.slice(1) : label);

/** The tool's label for a signal kind; a kind it does not know is shown as a value. */
const kindLabel = (kind) => (Object.hasOwn(KINDS, kind) ? lower(KINDS[kind][1]) : v(kind));
const kindLabels = (keys) => [...new Set(keys.map((k) => kindLabel(k.split('\u0000')[0])))].join('; ');

const fmtLoc = (l) => (l.line ? `${l.file}:${l.line}` : l.file);

/**
 * @param old snapshot or null (package newly added)
 * @param neu snapshot
 */
export function diffSnapshots(old, neu, { addedPackage = false } = {}) {
    const findings = [];
    // Every title is a template written here with each package value wrapped in v(). Its marked form
    // is the finding's trusted title, which the report shows as text and code; JSON gets the plain title.
    const add = (f) => { f[MARKED_TITLE] = f.title; f.title = unmark(f.title); findings.push(f); };
    const oldSnap = old || { signals: [], installScripts: {}, installFiles: new Set(), deps: {}, api: {}, meta: {}, files: new Map() };

    // 1. Install-time scripts
    // npm runs lifecycle scripts on every install. setup.py hooks run only when pip builds from
    // the sdist; they are high only when that code also gained a risky capability (step 2).
    const scriptSev = neu.ecosystem === 'npm' ? 'high' : 'medium';
    const scriptNote = neu.ecosystem === 'npm' ? '' : ' (runs when installing from source)';
    for (const [k, cmd] of Object.entries(neu.installScripts)) {
        const before = oldSnap.installScripts[k];
        if (before === undefined) add({ severity: scriptSev, category: 'security', kind: 'install-script', title: `New install-time script: ${v(k)}${scriptNote}`, detail: cmd, locations: [{ file: neu.ecosystem === 'npm' ? 'package.json' : 'setup.py', line: 0 }] });
        else if (before !== cmd) add({ severity: scriptSev, category: 'security', kind: 'install-script', title: `Install-time script changed: ${v(k)}${scriptNote}`, detail: `${before}  →  ${cmd}`, locations: [] });
    }
    for (const k of Object.keys(oldSnap.installScripts)) if (!(k in neu.installScripts)) add({ severity: 'info', category: 'security', kind: 'install-script', title: `Install-time script removed: ${v(k)}`, detail: oldSnap.installScripts[k], locations: [] });

    // 2. Install-time files that gained capabilities
    for (const f of neu.installFiles) {
        const was = oldSnap.installFiles.has(f) && oldSnap.files.has(f);
        const before = was ? kindsByFile(oldSnap, f) : new Set();
        const gained = [...kindsByFile(neu, f)].filter((k) => !before.has(k) && INSTALL_CAP_KINDS.has(k.split('\u0000')[0]));
        if (gained.length) {
            add({ severity: 'high', category: 'security', kind: 'install-script-capability', title: `Code that runs at install or start-up gained: ${kindLabels(gained)}`, detail: gained.map((g) => g.replace('\u0000', ': ')).slice(0, 8).join(' | '), locations: [{ file: f, line: 0 }] });
        } else if (was && oldSnap.files.get(f).hash !== neu.files.get(f)?.hash) {
            add({ severity: 'low', category: 'security', kind: 'install-script', title: `Install-time file changed: ${v(f)}`, detail: 'no new capability detected in it', locations: [{ file: f, line: 0 }] });
        }
    }

    // 3. New capability / indicator signals across the package
    const before = groupSignals(oldSnap);
    const after = groupSignals(neu);
    const newHosts = [];
    const minified = [];
    // Same capability already in the old package, but new to an existing file that changed.
    const fileOld = new Set(oldSnap.signals.map((s) => `${s.file}\u0000${s.kind}\u0000${s.detail}`));
    const changed = (f) => oldSnap.files.has(f) && oldSnap.files.get(f).hash !== neu.files.get(f)?.hash;
    const gained = new Map();
    for (const s of neu.signals) {
        const key = `${s.kind}\u0000${s.detail}`;
        if (!before.has(key) || !(PER_FILE_KINDS.has(s.kind) || importLaunch({ ...s, locations: [s] })) || /^module /.test(s.detail)) continue;
        if (!changed(s.file) || fileOld.has(`${s.file}\u0000${key}`)) continue;
        if (!gained.has(key)) gained.set(key, { kind: s.kind, detail: s.detail, locations: [], inFile: true });
        if (gained.get(key).locations.length < 50) gained.get(key).locations.push({ file: s.file, line: s.line });
    }
    const gainedInFile = [...gained.values()];
    for (const g of [...[...after].filter(([key]) => !before.has(key)).map(([, v]) => v), ...gainedInFile]) {
        const sev = Object.hasOwn(KINDS, g.kind) ? KINDS[g.kind][0] : 'low';
        if (g.kind === 'new-host') { newHosts.push(g); continue; }
        if (g.kind === 'minified-blob') { minified.push(g); continue; }
        let severity = importLaunch(g) ? 'high' : sev;
        // A package that is new to the tree has no "before": keep only the strong indicators at their level.
        if (!old && SEVERITY_RANK[sev] < SEVERITY_RANK.high) severity = 'info';
        // Only in tests, examples or docs: shipped but not run on install or import. One level lower.
        const inertOnly = g.locations.every((l) => INERT_DIR.test(l.file) && !neu.installFiles.has(l.file));
        if (inertOnly) severity = LOWER[severity];
        // The files named in the title come from the locations kept, so the report can show them as code.
        add({ severity, category: 'security', kind: g.kind, title: `${old ? 'New' : 'Has'}${g.inFile ? ` in ${[...new Set(g.locations.slice(0, MAX_LOCATIONS).map((l) => l.file))].slice(0, 2).map(v).join(', ')}` : ''}: ${kindLabel(g.kind)} — ${v(g.detail)}${importLaunch(g) && !/ at import time$/.test(g.detail) ? ' (in a package __init__, runs on import)' : ''}${inertOnly ? ' (only in tests/examples/docs)' : ''}`, detail: g.detail, locations: g.locations.slice(0, MAX_LOCATIONS), moreLocations: Math.max(0, g.locations.length - MAX_LOCATIONS) });
    }
    if (newHosts.length) {
        add({ severity: old ? 'low' : 'info', category: 'security', kind: 'new-host', title: `${newHosts.length} new hard-coded host name(s)`, detail: newHosts.map((h) => h.detail).slice(0, 15).join(', '), locations: newHosts.slice(0, MAX_LOCATIONS).map((h) => h.locations[0]) });
    }
    if (minified.length) add({ severity: old ? 'low' : 'info', category: 'security', kind: 'minified-blob', title: `${minified.length} new minified file(s) outside usual build folders`, detail: minified.map((m) => m.detail).slice(0, 10).join(', '), locations: [] });

    // 4. Dependencies
    const newDeps = [];
    for (const [n, d] of Object.entries(neu.deps)) {
        const o = oldSnap.deps[n];
        if (!o) {
            newDeps.push(n);
            const sev = isNonRegistrySpec(d.spec) ? 'high' : d.field === 'extra' ? 'info' : old ? 'medium' : 'info';
            add({ severity: sev, category: 'dependency', kind: 'new-dependency', title: `New ${d.field === 'extra' ? 'optional (extra) ' : ''}dependency: ${v(n)}${`${d.spec}`.trimEnd() ? ` ${v(`${d.spec}`.trimEnd())}` : ''}`, detail: isNonRegistrySpec(d.spec) ? 'fetched from a URL, git or local path, not the registry' : d.field, dependency: n, spec: d.spec, locations: [] });
        } else if (o.spec !== d.spec && isNonRegistrySpec(d.spec) && !isNonRegistrySpec(o.spec)) {
            add({ severity: 'high', category: 'dependency', kind: 'dependency-source-changed', title: `Dependency ${v(n)} now comes from outside the registry`, detail: `${o.spec} → ${d.spec}`, locations: [] });
        }
    }
    const removedDeps = Object.keys(oldSnap.deps).filter((n) => !neu.deps[n]);
    if (old && removedDeps.length) add({ severity: 'info', category: 'dependency', kind: 'removed-dependency', title: `Removed dependencies: ${removedDeps.slice(0, 20).map(v).join(', ')}`, detail: '', locations: [] });

    // 5. Exported API (removed functions, entry points, module format)
    if (old) {
        for (const [sub, a] of Object.entries(oldSnap.api)) {
            const b = neu.api[sub];
            if (!b) {
                if (neu.ecosystem === 'npm' && neu.meta.exportsKeys && !neu.meta.exportsKeys.includes(sub)) add({ severity: 'medium', category: 'breaking', kind: 'removed-entry-point', title: `Removed import path: ${v(`${neu.meta.name || ''}${sub === '.' ? '' : sub.slice(1)}`)}`, detail: 'no longer listed in package.json "exports"', locations: [] });
                else if (neu.ecosystem === 'pypi' && a.names.size) add({ severity: 'medium', category: 'breaking', kind: 'removed-module', title: `Removed module: ${v(sub)}`, detail: `${a.names.size} public names`, locations: [] });
                continue;
            }
            if (!b.resolved || (b.names.size === 0 && a.names.size > 0) || (b.names.size <= 1 && a.names.size > 5)) {
                if (a.names.size) add({ severity: 'info', category: 'breaking', kind: 'api-undetermined', title: `Could not read the exported names of ${v(sub)} in the new version`, detail: `old version exported ${a.names.size}`, locations: [] });
                continue;
            }
            const removed = [...a.names].filter((n) => !b.names.has(n) && n !== 'default' && !n.startsWith('='));
            if (removed.length) add({ severity: 'medium', category: 'breaking', kind: 'removed-export', title: `Removed from ${neu.ecosystem === 'npm' && sub === '.' ? 'the main entry' : v(sub)}: ${removed.slice(0, 12).map(v).join(', ')}${removed.length > 12 ? ` (+${removed.length - 12} more)` : ''}`, detail: removed.join(', '), removed, locations: b.source.map((f) => ({ file: f, line: 0 })) });
        }
        const om = oldSnap.meta; const nm = neu.meta;
        if (neu.ecosystem === 'npm') {
            if (om.type !== 'module' && nm.type === 'module') add({ severity: 'medium', category: 'breaking', kind: 'module-format', title: 'Package switched to ES modules ("type": "module")', detail: 'require() of its .js files may fail on older Node versions', locations: [] });
            if (om.engines !== nm.engines && nm.engines) add({ severity: 'info', category: 'breaking', kind: 'engines', title: `Node engine requirement: ${om.engines ? v(om.engines) : 'none'} → ${v(nm.engines)}`, detail: '', locations: [] });
            const rb = Object.keys(om.bin || {}).filter((b) => !(b in (nm.bin || {})));
            if (rb.length) add({ severity: 'medium', category: 'breaking', kind: 'removed-bin', title: `Removed command(s): ${rb.map(v).join(', ')}`, detail: '', locations: [] });
            const nb = Object.keys(nm.bin || {}).filter((b) => !(b in (om.bin || {})));
            if (nb.length) add({ severity: 'low', category: 'security', kind: 'new-bin', title: `New command(s) on PATH: ${nb.map(v).join(', ')}`, detail: nb.map((b) => `${b} → ${nm.bin[b]}`).join(', '), locations: [] });
        } else if (om.requiresPython !== nm.requiresPython && nm.requiresPython) {
            add({ severity: 'info', category: 'breaking', kind: 'requires-python', title: `Requires-Python: ${om.requiresPython ? v(om.requiresPython) : 'none'} → ${v(nm.requiresPython)}`, detail: '', locations: [] });
        }
    }

    findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    const sec = findings.filter((f) => f.category !== 'breaking');
    const top = sec.length ? sec[0].severity : 'info';
    const verdict = top === 'high' ? 'review' : top === 'medium' ? 'notice' : 'clean';
    const counts = {};
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const filesAdded = [...neu.files.keys()].filter((f) => !oldSnap.files.has(f)).length;
    const filesRemoved = [...oldSnap.files.keys()].filter((f) => !neu.files.has(f)).length;
    const filesChanged = [...neu.files.keys()].filter((f) => oldSnap.files.has(f) && oldSnap.files.get(f).hash !== neu.files.get(f).hash).length;
    return {
        verdict,
        breaking: findings.some((f) => f.category === 'breaking' && f.severity !== 'info'),
        counts,
        findings,
        newDependencies: newDeps,
        removedDependencies: removedDeps,
        files: { added: filesAdded, removed: filesRemoved, changed: filesChanged, total: neu.files.size },
        ...mergeNotes([old, neu], 10),
        coverage: neu.coverage || { complete: true },
        addedPackage,
    };
}

export { fmtLoc };

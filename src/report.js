// Markdown verdicts for one package and for a lockfile report.
const VERDICT = {
    review: '🔴 REVIEW BEFORE MERGE',
    notice: '🟡 WORTH A LOOK',
    clean: '🟢 NOTHING NEW FOUND',
    lowOnly: '🟢 LOW NOTES ONLY',
    error: '⚪ NOT ANALYSED',
    incomplete: '⚪ PARTLY ANALYSED',
};
const SEV = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

// Every value that comes from a package, a registry or a lockfile goes through code() or text(), so
// it cannot change the Markdown around it. Reports are posted as pull-request comments, where
// "@solana/web3.js" outside a code span would notify the "solana" GitHub account.

/** An untrusted value as a code span: no backticks or line breaks inside, so the span always closes. */
export const code = (s) => `\`${String(s).replace(/`/g, "'").replace(/\s+/g, ' ').slice(0, 160)}\``;

/**
 * Untrusted prose (error messages, finding titles, notes): one line, no HTML, entities, links,
 * backticks or backslash escapes. Every word that contains an "@" becomes a code span as a whole,
 * so no "@" is ever outside code, whatever is next to it ("@one@two" stays one span).
 */
const ESC = { '\\': '\\\\', '<': '&lt;', '>': '&gt;', '&': '&amp;', '[': '\\[', ']': '\\]' };
export function text(s) {
    return String(s).replace(/`/g, "'").split(/\s+/)
        .map((w) => (w.includes('@') ? `\`${w}\`` : w.replace(/[\\<>&[\]]/g, (c) => ESC[c])))
        .join(' ');
}
/**
 * Low findings never change a verdict, so a "clean" package can still list some. Its label must
 * not then say "nothing new found": labels and counts say "low notes only" for those packages.
 */
const lowNotes = (r) => r.findings?.filter((f) => f.category !== 'breaking' && f.severity === 'low') ?? [];
const labelOf = (r) => { const v = packageVerdict(r); return v === 'clean' && lowNotes(r).length ? 'lowOnly' : v; };

const loc = (l) => (l.line ? `${l.file}:${l.line}` : l.file);

export const DISCLAIMER = 'Static analysis of the published files: nothing was installed or executed. A finding is a change worth reading, not proof of malware, and an empty report does not prove a package is safe.';

/**
 * Verdict shown for one package. The detector's "clean" becomes "incomplete" when some of the
 * package's files or artifacts were not fully analysed, so "nothing new found" is only said of
 * a package that was read in full.
 */
export function packageVerdict(r) {
    if (r.error) return 'error';
    if (r.verdict === 'clean' && r.coverage?.complete === false) return 'incomplete';
    return r.verdict;
}

export function packageTitle(r) {
    const eco = r.ecosystem === 'pypi' ? 'PyPI' : 'npm';
    const range = r.fromVersion ? `${text(r.fromVersion)} → ${text(r.toVersion)}` : `new at ${text(r.toVersion)}`;
    return `${code(r.name)} ${range} (${eco})`;
}

export function packageMarkdown(r, { heading = '###', maxFindings = 25 } = {}) {
    const lines = [];
    if (r.error) {
        lines.push(`${heading} ${VERDICT.error} — ${code(r.name)}${r.toVersion ? ` ${text(r.toVersion)}` : ''} (${r.ecosystem === 'pypi' ? 'PyPI' : 'npm'})`, '', `Could not analyse: ${text(r.error)}`, '');
        return lines.join('\n');
    }
    lines.push(`${heading} ${VERDICT[labelOf(r)]} — ${packageTitle(r)}`, '');
    const sec = r.findings.filter((f) => f.category !== 'breaking' && f.severity !== 'info');
    const brk = r.findings.filter((f) => f.category === 'breaking');
    const info = r.findings.filter((f) => f.category !== 'breaking' && f.severity === 'info');
    const cov = r.coverage;
    const partial = cov && cov.complete === false;
    if (!sec.length) {
        const base = r.addedPackage ? 'New package in the tree; no install script or high-risk indicator found' : 'No new install scripts, network/shell/eval calls, risky indicators or dependencies found';
        lines.push(`${base}${partial ? ' in the files that were inspected' : ''}.`);
    }
    if (partial) lines.push('', `_Coverage: ${coverageText(cov)}._`);
    const groups = groupFindings(sec);
    for (const g of groups.slice(0, maxFindings)) lines.push(`- **${SEV[g.severity]}** ${groupLine(g)}`);
    if (groups.length > maxFindings) lines.push(`- …and ${groups.length - maxFindings} more in the dataset item.`);
    if (brk.length) {
        lines.push('', '<details><summary>API and compatibility changes</summary>', '');
        for (const f of brk) lines.push(`- ${f.severity === 'info' ? '' : `**${SEV[f.severity]}** `}${text(f.title)}`);
        lines.push('', '</details>');
    }
    if (info.length) {
        lines.push('', '<details><summary>Other notes</summary>', '');
        for (const g of groupFindings(info).slice(0, 15)) lines.push(`- ${groupLine(g, { where: false })}`);
        lines.push('', '</details>');
    }
    const fc = r.files;
    if (fc) lines.push('', `<sub>Files: ${fc.added} added, ${fc.changed} changed, ${fc.removed} removed (of ${fc.total}).${r.notes?.length ? ` Notes: ${r.notes.map(text).join('; ')}` : ''}</sub>`);
    lines.push('');
    return lines.join('\n');
}

const ITEMS_SHOWN = 6;

/**
 * Findings that differ only in what was matched become one line: "New: network access — fetch()"
 * and "New: network access — XMLHttpRequest()" in the same file are one finding to a reader.
 * Groups keep the order of their first finding; locations are merged without repeats.
 */
export function groupFindings(findings) {
    const groups = new Map();
    for (const f of findings) {
        const art = f.artifact || '';
        let key; let label; let item = null; let extra = '';
        if (f.kind === 'new-dependency' && f.dependency) {
            label = f.title.slice(0, f.title.indexOf(':')).trim() || 'New dependency';
            item = `${code(f.dependency)}${f.spec ? ` ${text(f.spec)}` : ''}`;
            extra = f.detail || '';
            key = `${f.severity}|dep|${label}|${extra}|${art}`;
        } else if ((f.kind === 'new-host' || f.kind === 'minified-blob') && f.detail) {
            // The detail is a pre-joined list (cut at 15 or 10); the title holds the full count.
            label = f.title;
            key = `${f.severity}|${f.kind}|${label}|${art}|${groups.size}`;
            groups.set(key, { severity: f.severity, label, items: f.detail.split(', ').map(code), total: Number(f.title.match(/^\d+/)?.[0]) || 0, extra: '', artifact: art, locations: (f.locations || []).map(loc).filter((x, i, a) => a.indexOf(x) === i), more: Boolean(f.moreLocations) });
            continue;
        } else if (f.detail && f.title.includes(` — ${f.detail}`)) {
            label = f.title.replace(` — ${f.detail}`, '');
            item = code(f.detail);
            key = `${f.severity}|${f.kind}|${label}|${art}`;
        } else {
            label = f.title;
            // The install-time summary's detail repeats the signals listed on their own lines.
            if (f.detail && !f.title.includes(f.detail) && f.kind !== 'install-script-capability') extra = f.detail;
            key = `${f.severity}|${f.kind}|${label}|${extra}|${art}|${groups.size}`;
        }
        let g = groups.get(key);
        if (!g) groups.set(key, (g = { severity: f.severity, label, items: [], extra, artifact: art, locations: [], more: false }));
        if (item && !g.items.some((x) => x.toLowerCase() === item.toLowerCase())) g.items.push(item);
        for (const l of f.locations || []) { const s = loc(l); if (!g.locations.includes(s)) g.locations.push(s); }
        if (f.moreLocations) g.more = true;
    }
    return [...groups.values()];
}

function groupLine(g, { where = true } = {}) {
    const many = g.items.length > 1;
    let label = text(g.label);
    if (many && /^New (optional \(extra\) )?dependency$/.test(g.label)) label = `${label.replace(/dependency$/, 'dependencies')} (${g.items.length})`;
    const shown = g.items.slice(0, ITEMS_SHOWN).join(', ');
    const total = Math.max(g.items.length, g.total || 0);
    const rest = total > ITEMS_SHOWN ? ` and ${total - Math.min(ITEMS_SHOWN, g.items.length)} more` : '';
    const items = g.items.length ? `${g.items.length === 1 && !g.extra ? ' — ' : ': '}${shown}${rest}` : '';
    const extra = g.extra ? `${g.items.length ? ' — ' : ': '}${code(g.extra)}` : '';
    const at = where && g.locations.length ? ` · in ${g.locations.slice(0, 3).map(code).join(', ')}${g.locations.length > 3 || g.more ? ' …' : ''}` : '';
    return `${label}${items}${extra}${at}${g.artifact ? ` _(${text(g.artifact)})_` : ''}`;
}

export function coverageText(cov) {
    const parts = [];
    if (cov.unparsedFilesCount) parts.push(`${cov.unparsedFilesCount} file(s) only pattern-scanned, not fully parsed (${cov.unparsedFiles.slice(0, 3).map((f) => code(`${f.file}: ${f.reason}`)).join(', ')}${cov.unparsedFilesCount > 3 ? ' …' : ''})`);
    if (cov.skippedFilesCount) parts.push(`${cov.skippedFilesCount} file(s) not read (${cov.skippedFiles.slice(0, 3).map((f) => code(`${f.file}: ${f.reason}`)).join(', ')}${cov.skippedFilesCount > 3 ? ' …' : ''})`);
    if (cov.failedArtifacts?.length) parts.push(`not compared: ${cov.failedArtifacts.map(code).join(', ')}`);
    return parts.join('; ') || 'partial';
}

const OVERALL = {
    review: '🔴 Review before merge',
    notice: '🟡 Worth a look',
    clean: '🟢 Nothing new found in any change',
    incomplete: '⚪ Incomplete — nothing needing review was found, but some changes or files were not fully analysed',
    error: '⚪ Not analysed — no change could be analysed',
};

// Why a lockfile type leaves the origin out, for the assumePublicRegistry hint.
const UNRECORDED_WHY = {
    pnpm: 'pnpm does not record the registry of packages from the default registry',
    poetry: 'Poetry does not record its default source',
    npm: 'this package-lock.json has no "resolved" URL for them',
    uv: 'this uv.lock has no source for them',
    requirements: 'this requirements file names no package index, and pip can be set to another index outside it',
};

function overallLines(verdict, coverage, results) {
    if (!verdict) return [];
    const lowOnly = verdict === 'clean' && results.some((r) => labelOf(r) === 'lowOnly');
    const out = [`**Overall: ${lowOnly ? '🟢 Nothing needing review; low notes only' : OVERALL[verdict]}**`];
    if (coverage && !coverage.complete) {
        const gaps = [];
        if (coverage.failed) gaps.push(`${coverage.failed} could not be analysed`);
        if (coverage.notLookedUp) gaps.push(`${coverage.notLookedUp} not looked up (see the list below)`);
        if (coverage.overLimit) gaps.push(`${coverage.overLimit} above the package limit`);
        if (coverage.addedNotScanned) gaps.push(`${coverage.addedNotScanned} new package(s) not scanned`);
        if (coverage.packagesWithUnparsedFiles) gaps.push(`${coverage.packagesWithUnparsedFiles} analysed package(s) only partly analysed (files pattern-scanned or not read, or an artifact not compared; listed with each package below)`);
        out.push(`Not covered: ${gaps.join(', ')}.`);
    }
    out.push('');
    return out;
}

export function summaryLine(results) {
    const c = { review: 0, notice: 0, clean: 0, incomplete: 0, error: 0 };
    for (const r of results) c[packageVerdict(r)]++;
    return c;
}

function countsLine(c, results) {
    const low = results.filter((r) => labelOf(r) === 'lowOnly').length;
    return `**${c.review} to review · ${c.notice} worth a look · ${c.clean - low} nothing new${low ? ` · ${low} low notes only` : ''}${c.incomplete ? ` · ${c.incomplete} partly analysed` : ''}${c.error ? ` · ${c.error} not analysed` : ''}**`;
}

export function packagesReport(results, { title = 'Upgrade X-Ray', verdict, coverage } = {}) {
    const c = summaryLine(results);
    const out = [`## ${title}`, '', ...overallLines(verdict, coverage, results), countsLine(c, results), ''];
    for (const r of sortResults(results)) out.push(packageMarkdown(r));
    out.push(`<sub>${DISCLAIMER}</sub>`, '');
    return out.join('\n');
}

const RANK = { review: 0, notice: 1, error: 2, incomplete: 3, clean: 4 };
export function sortResults(results) {
    return [...results].sort((a, b) => RANK[packageVerdict(a)] - RANK[packageVerdict(b)] || a.name.localeCompare(b.name));
}

export function lockfileReport(results, diff, { skipped = [], title = 'Upgrade X-Ray — lockfile report', verdict, coverage } = {}) {
    const c = summaryLine(results);
    const out = [`## ${title}`, '', ...overallLines(verdict, coverage, results),
        `${diff.type === 'requirements' ? 'pip requirements file' : `${diff.type} lockfile`}: **${diff.updated.length} updated, ${diff.added.length} added, ${diff.removed.length} removed** package versions.`, '',
        countsLine(c, results), ''];
    const sorted = sortResults(results);
    // Only packages read in full go into the compact list; partly analysed ones keep their coverage detail.
    const loud = sorted.filter((r) => packageVerdict(r) !== 'clean');
    for (const r of loud) out.push(packageMarkdown(r));
    const quiet = sorted.filter((r) => packageVerdict(r) === 'clean');
    if (quiet.length) {
        const low = quiet.filter((r) => labelOf(r) === 'lowOnly').length;
        out.push(`<details><summary>${low ? `Nothing needing review in ${quiet.length} package(s); ${low} with low notes` : `Nothing new found in ${quiet.length} package(s)`}</summary>`, '');
        for (const r of quiet) {
            const brk = r.findings.filter((f) => f.category === 'breaking' && f.severity !== 'info').length;
            out.push(`- ${packageTitle(r)}${brk ? ` — ${brk} API/compatibility change(s)` : ''}`);
            for (const g of groupFindings(lowNotes(r))) out.push(`  - **${SEV.low}** ${groupLine(g)}`);
        }
        out.push('', '</details>', '');
    }
    if (diff.originChanges?.length) {
        out.push('**Moved to the public registry from another source** (scanned as new packages; check that the public package is the one you meant — a common dependency-confusion pattern):', '');
        for (const n of diff.originChanges.slice(0, 30)) out.push(`- ${code(n.name)} ${text(n.to)} (was: ${text(n.fromOrigin)})`);
        out.push('');
    }
    if (diff.nonRegistry.length) {
        out.push(diff.nonRegistry.some((n) => n.origin === 'range')
            ? '**Not looked up (no exact version, or origin not proven to be the public registry; names were not sent anywhere):**'
            : '**Not looked up (origin not proven to be the public registry; names were not sent anywhere):**', '');
        for (const n of diff.nonRegistry.slice(0, 30)) out.push(n.origin === 'range' ? `- ${code(n.name)} ${code(n.to)} (a version range, not an exact version)` : `- ${code(n.name)} ${text(n.to)} from ${code(n.source)}`);
        if (diff.nonRegistry.length > 30) out.push(`- …and ${diff.nonRegistry.length - 30} more in OUTPUT.`);
        const unrecorded = diff.nonRegistry.filter((n) => n.origin === 'unknown').length;
        if (unrecorded) out.push('', `${unrecorded} of these ${unrecorded === 1 ? 'has' : 'have'} no recorded origin: ${UNRECORDED_WHY[diff.type] || 'the lockfile does not say where they came from'}. If this project installs only from the public registry, ${unrecorded === 1 ? 'it' : 'they'} can be checked: set \`assumePublicRegistry\` to true (in the GitHub Action: \`assume-public-registry: true\`). Leave it off if the project uses a private registry or mirror.`);
        out.push('');
    }
    if (skipped.length) out.push(`Skipped ${skipped.length} change(s) above the package limit: ${skipped.slice(0, 30).map((s) => `${code(s.name)} ${text(s.to)}`).join(', ')}${skipped.length > 30 ? ' …' : ''}`, '');
    if (diff.removed.length) out.push(`<details><summary>Removed packages (${diff.removed.length})</summary>\n\n${diff.removed.slice(0, 100).map((r) => `${code(r.name)} ${text(r.from)}`).join(', ')}\n\n</details>`, '');
    out.push(`<sub>${DISCLAIMER}</sub>`, '');
    return out.join('\n');
}

// Markdown verdicts for one package and for a lockfile report.
const VERDICT = {
    review: '🔴 REVIEW BEFORE MERGE',
    notice: '🟡 WORTH A LOOK',
    clean: '🟢 NOTHING NEW FOUND',
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
    lines.push(`${heading} ${VERDICT[packageVerdict(r)]} — ${packageTitle(r)}`, '');
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
    for (const f of sec.slice(0, maxFindings)) {
        const where = f.locations?.length ? ` — ${f.locations.slice(0, 3).map((l) => code(loc(l))).join(', ')}${(f.locations.length > 3 || f.moreLocations) ? ' …' : ''}` : '';
        const extra = f.detail && !f.title.includes(f.detail) ? `: ${code(f.detail)}` : '';
        lines.push(`- **${SEV[f.severity]}** ${text(f.title)}${extra}${where}${f.artifact ? ` _(${text(f.artifact)})_` : ''}`);
    }
    if (sec.length > maxFindings) lines.push(`- …and ${sec.length - maxFindings} more in the dataset item.`);
    if (brk.length) {
        lines.push('', '<details><summary>API and compatibility changes</summary>', '');
        for (const f of brk) lines.push(`- ${f.severity === 'info' ? '' : `**${SEV[f.severity]}** `}${text(f.title)}`);
        lines.push('', '</details>');
    }
    if (info.length) {
        lines.push('', '<details><summary>Other notes</summary>', '');
        for (const f of info.slice(0, 15)) lines.push(`- ${text(f.title)}${f.detail && !f.title.includes(f.detail) ? `: ${code(f.detail)}` : ''}`);
        lines.push('', '</details>');
    }
    const fc = r.files;
    if (fc) lines.push('', `<sub>Files: ${fc.added} added, ${fc.changed} changed, ${fc.removed} removed (of ${fc.total}).${r.notes?.length ? ` Notes: ${r.notes.map(text).join('; ')}` : ''}</sub>`);
    lines.push('');
    return lines.join('\n');
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

function overallLines(verdict, coverage) {
    if (!verdict) return [];
    const out = [`**Overall: ${OVERALL[verdict]}**`];
    if (coverage && !coverage.complete) {
        const gaps = [];
        if (coverage.failed) gaps.push(`${coverage.failed} could not be analysed`);
        if (coverage.notLookedUp) gaps.push(`${coverage.notLookedUp} not looked up (not proven to come from the public registry)`);
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

const countsLine = (c) => `**${c.review} to review · ${c.notice} worth a look · ${c.clean} nothing new${c.incomplete ? ` · ${c.incomplete} partly analysed` : ''}${c.error ? ` · ${c.error} not analysed` : ''}**`;

export function packagesReport(results, { title = 'Upgrade X-Ray', verdict, coverage } = {}) {
    const c = summaryLine(results);
    const out = [`## ${title}`, '', ...overallLines(verdict, coverage), countsLine(c), ''];
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
    const out = [`## ${title}`, '', ...overallLines(verdict, coverage),
        `${diff.type} lockfile: **${diff.updated.length} updated, ${diff.added.length} added, ${diff.removed.length} removed** package versions.`, '',
        countsLine(c), ''];
    const sorted = sortResults(results);
    // Only packages read in full go into the compact list; partly analysed ones keep their coverage detail.
    const loud = sorted.filter((r) => packageVerdict(r) !== 'clean');
    for (const r of loud) out.push(packageMarkdown(r));
    const quiet = sorted.filter((r) => packageVerdict(r) === 'clean');
    if (quiet.length) {
        out.push('<details><summary>Nothing new found in ' + quiet.length + ' package(s)</summary>', '');
        for (const r of quiet) {
            const brk = r.findings.filter((f) => f.category === 'breaking' && f.severity !== 'info').length;
            out.push(`- ${packageTitle(r)}${brk ? ` — ${brk} API/compatibility change(s)` : ''}`);
        }
        out.push('', '</details>', '');
    }
    if (diff.originChanges?.length) {
        out.push('**Moved to the public registry from another source** (scanned as new packages; check that the public package is the one you meant — a common dependency-confusion pattern):', '');
        for (const n of diff.originChanges.slice(0, 30)) out.push(`- ${code(n.name)} ${text(n.to)} (was: ${text(n.fromOrigin)})`);
        out.push('');
    }
    if (diff.nonRegistry.length) {
        out.push('**Not looked up (origin not proven to be the public registry; names were not sent anywhere):**', '');
        for (const n of diff.nonRegistry.slice(0, 30)) out.push(`- ${code(n.name)} ${text(n.to)} from ${code(n.source)}`);
        if (diff.nonRegistry.length > 30) out.push(`- …and ${diff.nonRegistry.length - 30} more in OUTPUT.`);
        if (diff.nonRegistry.some((n) => n.origin === 'unknown')) out.push('', `Entries with no recorded origin can be checked if you confirm they all come from the public registry: set \`assumePublicRegistry\` to true.`);
        out.push('');
    }
    if (skipped.length) out.push(`Skipped ${skipped.length} change(s) above the package limit: ${skipped.slice(0, 30).map((s) => `${code(s.name)} ${text(s.to)}`).join(', ')}${skipped.length > 30 ? ' …' : ''}`, '');
    if (diff.removed.length) out.push(`<details><summary>Removed packages (${diff.removed.length})</summary>\n\n${diff.removed.slice(0, 100).map((r) => `${code(r.name)} ${text(r.from)}`).join(', ')}\n\n</details>`, '');
    out.push(`<sub>${DISCLAIMER}</sub>`, '');
    return out.join('\n');
}

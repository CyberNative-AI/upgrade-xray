// Markdown verdicts for one package and for a lockfile report.
const VERDICT = {
    review: '🔴 REVIEW BEFORE MERGE',
    notice: '🟡 WORTH A LOOK',
    clean: '🟢 NOTHING NEW FOUND',
    error: '⚪ NOT ANALYSED',
};
const SEV = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

const code = (s) => `\`${String(s).replace(/`/g, "'").replace(/\s+/g, ' ').slice(0, 160)}\``;
const loc = (l) => (l.line ? `${l.file}:${l.line}` : l.file);

export const DISCLAIMER = 'Static analysis of the published files: nothing was installed or executed. A finding is a change worth reading, not proof of malware, and an empty report does not prove a package is safe.';

export function packageTitle(r) {
    const eco = r.ecosystem === 'pypi' ? 'PyPI' : 'npm';
    const range = r.fromVersion ? `${r.fromVersion} → ${r.toVersion}` : `new at ${r.toVersion}`;
    return `${r.name} ${range} (${eco})`;
}

export function packageMarkdown(r, { heading = '###', maxFindings = 25 } = {}) {
    const lines = [];
    if (r.error) {
        lines.push(`${heading} ${VERDICT.error} — ${r.name}${r.toVersion ? ` ${r.toVersion}` : ''} (${r.ecosystem})`, '', `Could not analyse: ${r.error}`, '');
        return lines.join('\n');
    }
    lines.push(`${heading} ${VERDICT[r.verdict]} — ${packageTitle(r)}`, '');
    const sec = r.findings.filter((f) => f.category !== 'breaking' && f.severity !== 'info');
    const brk = r.findings.filter((f) => f.category === 'breaking');
    const info = r.findings.filter((f) => f.category !== 'breaking' && f.severity === 'info');
    if (!sec.length) lines.push(r.addedPackage ? 'New package in the tree; no install script or high-risk indicator found.' : 'No new install scripts, network/shell/eval calls, risky indicators or dependencies found.');
    for (const f of sec.slice(0, maxFindings)) {
        const where = f.locations?.length ? ` — ${f.locations.slice(0, 3).map((l) => code(loc(l))).join(', ')}${(f.locations.length > 3 || f.moreLocations) ? ' …' : ''}` : '';
        const extra = f.detail && !f.title.includes(f.detail) ? `: ${code(f.detail)}` : '';
        lines.push(`- **${SEV[f.severity]}** ${f.title}${extra}${where}${f.artifact ? ` _(${f.artifact})_` : ''}`);
    }
    if (sec.length > maxFindings) lines.push(`- …and ${sec.length - maxFindings} more in the dataset item.`);
    if (brk.length) {
        lines.push('', '<details><summary>API and compatibility changes</summary>', '');
        for (const f of brk) lines.push(`- ${f.severity === 'info' ? '' : `**${SEV[f.severity]}** `}${f.title}`);
        lines.push('', '</details>');
    }
    if (info.length) {
        lines.push('', '<details><summary>Other notes</summary>', '');
        for (const f of info.slice(0, 15)) lines.push(`- ${f.title}${f.detail && !f.title.includes(f.detail) ? `: ${code(f.detail)}` : ''}`);
        lines.push('', '</details>');
    }
    const fc = r.files;
    if (fc) lines.push('', `<sub>Files: ${fc.added} added, ${fc.changed} changed, ${fc.removed} removed (of ${fc.total}).${r.notes?.length ? ` Notes: ${r.notes.join('; ')}` : ''}</sub>`);
    lines.push('');
    return lines.join('\n');
}

export function summaryLine(results) {
    const c = { review: 0, notice: 0, clean: 0, error: 0 };
    for (const r of results) c[r.error ? 'error' : r.verdict]++;
    return c;
}

export function packagesReport(results, { title = 'Upgrade X-Ray' } = {}) {
    const c = summaryLine(results);
    const out = [`## ${title}`, '', `**${c.review} to review · ${c.notice} worth a look · ${c.clean} nothing new${c.error ? ` · ${c.error} not analysed` : ''}**`, ''];
    for (const r of sortResults(results)) out.push(packageMarkdown(r));
    out.push(`<sub>${DISCLAIMER}</sub>`, '');
    return out.join('\n');
}

const RANK = { review: 0, notice: 1, error: 2, clean: 3 };
export function sortResults(results) {
    return [...results].sort((a, b) => RANK[a.error ? 'error' : a.verdict] - RANK[b.error ? 'error' : b.verdict] || a.name.localeCompare(b.name));
}

export function lockfileReport(results, diff, { skipped = [], title = 'Upgrade X-Ray — lockfile report' } = {}) {
    const c = summaryLine(results);
    const out = [`## ${title}`, '',
        `${diff.type} lockfile: **${diff.updated.length} updated, ${diff.added.length} added, ${diff.removed.length} removed** package versions.`, '',
        `**${c.review} to review · ${c.notice} worth a look · ${c.clean} nothing new${c.error ? ` · ${c.error} not analysed` : ''}**`, ''];
    const sorted = sortResults(results);
    const loud = sorted.filter((r) => r.error || r.verdict !== 'clean');
    for (const r of loud) out.push(packageMarkdown(r));
    const quiet = sorted.filter((r) => !r.error && r.verdict === 'clean');
    if (quiet.length) {
        out.push('<details><summary>Nothing new found in ' + quiet.length + ' package(s)</summary>', '');
        for (const r of quiet) {
            const brk = r.findings.filter((f) => f.category === 'breaking' && f.severity !== 'info').length;
            out.push(`- ${packageTitle(r)}${brk ? ` — ${brk} API/compatibility change(s)` : ''}`);
        }
        out.push('', '</details>', '');
    }
    if (diff.nonRegistry.length) {
        out.push('**Not from the registry (not analysed):**', '');
        for (const n of diff.nonRegistry.slice(0, 30)) out.push(`- ${n.name} ${n.to} from ${code(n.source)}`);
        out.push('');
    }
    if (skipped.length) out.push(`Skipped ${skipped.length} change(s) above the package limit: ${skipped.slice(0, 30).map((s) => `${s.name} ${s.to}`).join(', ')}${skipped.length > 30 ? ' …' : ''}`, '');
    if (diff.removed.length) out.push(`<details><summary>Removed packages (${diff.removed.length})</summary>\n\n${diff.removed.slice(0, 100).map((r) => `${r.name} ${r.from}`).join(', ')}\n\n</details>`, '');
    out.push(`<sub>${DISCLAIMER}</sub>`, '');
    return out.join('\n');
}

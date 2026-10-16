// A finding compared file by file names its files in the title ("New in <file>: …"). File names
// are package data: rendered, they must not become links, HTML, headings or @mentions. Checked
// from archive entries through the snapshot, the per-file comparison and the Markdown report,
// on the HTML the report renders to.
import test from 'node:test';
import assert from 'node:assert/strict';
import MarkdownIt from 'markdown-it';
import { readTar } from '../src/archive.js';
import { pypiSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { packageMarkdown } from '../src/report.js';
import { tar } from './helpers.js';

const md = new MarkdownIt({ html: true, linkify: true });
const META = 'Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n';
const snapshot = (files) => pypiSnapshot(readTar(tar(Object.entries({ 'pkg-1.0.dist-info/METADATA': META, ...files }).map(([name, data]) => ({ name, data })))), 'wheel');
const NPMRC = 'RC = "~/.npmrc"\n';

// Each is aimed at the renderer: autolinks, HTML, Markdown links, entities, headings, mentions
// and String.replace patterns ($' and $&).
const HOSTILE = [
    ' www.example.com ', '&#64;victim', '<https://evil.invalid>', '[go](https://evil.invalid)',
    '<img src=x onerror=alert(1)>', '`@victim`@two', '\\`@victim', 'line\n\n# Heading\n', "$' $& a, b: c",
];

async function rendered(oldFiles, newFiles) {
    const r = diffSnapshots(await snapshot(oldFiles), await snapshot(newFiles));
    const html = md.render(packageMarkdown({ ecosystem: 'pypi', name: 'pkg', fromVersion: '1.0', toVersion: '1.1', ...r }));
    return { r, html };
}

const outsideCode = (html) => html.replace(/<(code|pre)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ');

test('file names in "New in <file>" titles render as code, never as links or markup', async () => {
    for (const hostile of HOSTILE) {
        const file = `pkg/${hostile}.py`;
        const before = { 'pkg/__init__.py': '', 'pkg/config.py': NPMRC, [file]: 'X = 1\n' };
        const { r, html } = await rendered(before, { ...before, [file]: `X = 1\n${NPMRC}` });
        const f = r.findings.find((x) => x.title.startsWith('New in '));
        assert.ok(f, `${hostile}: ${r.findings.map((x) => x.title).join('\n')}`);
        // The title shows the same file name as the location after it, unaltered.
        const [, named, at] = html.match(/New in <code>([^<]*)<\/code>: [\s\S]*· in <code>([^<]*)<\/code>/) || [];
        assert.ok(named && named === at, `${hostile}\n${html}`);
        assert.doesNotMatch(html, /<(a|img|script|h[124-6])\b/i, `${hostile}\n${html}`);
        assert.equal(html.match(/<h3\b/g).length, 1, html);
        assert.doesNotMatch(outsideCode(html), /@(victim|two)/, `${hostile}\n${html}`);
        assert.doesNotMatch(outsideCode(html), /example\.com|evil\.invalid|victim/, `${hostile}\n${html}`);
    }
});

test('the files a title names are among the locations it keeps, so the report can show them as code', () => {
    // The scanners emit one signal per file and indicator; a snapshot with several lines per file
    // checks the contract itself: six reads in one file fill the kept locations before the second file.
    const snap = (lines, hash) => ({
        ecosystem: 'pypi', deps: {}, api: {}, meta: {}, notes: [], installScripts: {}, installFiles: new Set(),
        files: new Map(['pkg/config.py', 'pkg/a.py', 'pkg/www.example.com .py'].map((file) => [file, { hash: file === 'pkg/config.py' ? 'same' : hash }])),
        signals: [{ file: 'pkg/config.py', kind: 'credential-path', detail: '/.npmrc', line: 1 }, ...lines],
    });
    const added = [1, 2, 3, 4, 5, 6].map((line) => ({ file: 'pkg/a.py', kind: 'credential-path', detail: '/.npmrc', line }));
    const r = diffSnapshots(snap([], 'old'), snap([...added, { file: 'pkg/www.example.com .py', kind: 'credential-path', detail: '/.npmrc', line: 1 }], 'new'));
    const f = r.findings.find((x) => x.kind === 'credential-path');
    assert.ok(f.title.startsWith('New in pkg/a.py: '), f.title);
    assert.ok(f.locations.every((l) => l.file === 'pkg/a.py') && f.moreLocations === 2, JSON.stringify(f));
    const html = md.render(packageMarkdown({ ecosystem: 'pypi', name: 'pkg', fromVersion: '1.0', toVersion: '1.1', ...r }));
    assert.match(html, /New in <code>pkg\/a\.py<\/code>: /, html);
    assert.doesNotMatch(html, /<a\b|example\.com/i, html);
});

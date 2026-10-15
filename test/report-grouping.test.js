// Findings that differ only in what was matched are one line in the report, with their locations
// merged; grouped values keep the same escaping as single ones.
import test from 'node:test';
import assert from 'node:assert/strict';
import { packageMarkdown, groupFindings } from '../src/report.js';
import MarkdownIt from 'markdown-it';

// Same oracle as report-mentions.test.js: mentions in rendered text outside code, pre and links.
const md = new MarkdownIt({ html: true, linkify: true });
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", commat: '@', nbsp: ' ' };
const decode = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => (e[0] === '#' ? String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e.toLowerCase()] ?? m));
const renderedMentions = (markdown) => decode(md.render(markdown).replace(/<(code|pre|a)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]*>/g, ' ')).match(/(?:^|[^A-Za-z0-9_])@[A-Za-z0-9][\w-]*/g) || [];

const sig = (kind, label, detail, file, line = 2, severity = 'high') => ({ severity, category: 'security', kind, title: `New: ${label} — ${detail}`, detail, locations: [{ file, line }] });
const pkg = (findings) => ({ ecosystem: 'npm', name: 'p', fromVersion: '1.0.0', toVersion: '1.0.1', verdict: 'review', findings, files: { added: 1, changed: 0, removed: 0, total: 1 } });

test('same signal, different matches: one line, locations without repeats', () => {
    const out = packageMarkdown(pkg([
        sig('network', 'network access', 'fetch()', 'a.js', 2, 'medium'),
        sig('network', 'network access', 'XMLHttpRequest()', 'a.js', 2, 'medium'),
        sig('network', 'network access', 'fetch()', 'b.js', 9, 'medium'),
        sig('self-publish', 'publishes packages', 'trufflehog', 'a.js'),
        sig('self-publish', 'publishes packages', 'TruffleHog', 'a.js'),
    ]));
    const lines = out.split('\n').filter((l) => l.startsWith('- '));
    assert.equal(lines.length, 2, out);
    assert.equal(lines[0], '- **Medium** New: network access: `fetch()`, `XMLHttpRequest()` · in `a.js:2`, `b.js:9`');
    assert.equal(lines[1], '- **High** New: publishes packages — `trufflehog` · in `a.js:2`');
});

test('install-time summary drops the repeated detail; host lists use the full count', () => {
    const out = packageMarkdown(pkg([
        { severity: 'high', category: 'security', kind: 'install-script-capability', title: 'Code that runs at install or start-up gained: network access', detail: 'network: fetch() | network: XMLHttpRequest() | netw', locations: [{ file: 'i.js', line: 0 }] },
        { severity: 'low', category: 'security', kind: 'new-host', title: '20 new hard-coded host name(s)', detail: Array.from({ length: 15 }, (_, i) => `h${i}.example.net`).join(', '), locations: [{ file: 'i.js', line: 2 }] },
    ]));
    assert.match(out, /^- \*\*High\*\* Code that runs at install or start-up gained: network access · in `i\.js`$/m);
    assert.doesNotMatch(out, /netw`/);
    assert.match(out, /`h5\.example\.net` and 14 more · in `i\.js:2`/);
});

test('new dependencies with the same note are one counted line', () => {
    const deps = ['@esbuild/a', '@esbuild/b', '@esbuild/c'].map((n) => ({ severity: 'info', category: 'dependency', kind: 'new-dependency', title: `New dependency: ${n} 0.25.0`, detail: 'optionalDependencies', dependency: n, spec: '0.25.0', locations: [] }));
    const g = groupFindings(deps);
    assert.equal(g.length, 1);
    const out = packageMarkdown(pkg(deps));
    assert.match(out, /^- New dependencies \(3\): `@esbuild\/a` 0\.25\.0, `@esbuild\/b` 0\.25\.0, `@esbuild\/c` 0\.25\.0 — `optionalDependencies`$/m);
    assert.deepEqual(renderedMentions(out), []);
});

test('hostile values stay inert when grouped', () => {
    const bad = ['`@victim', '@one@two', '&#64;e', '<b>@i</b>', '[t](u`rl) @j'];
    const out = packageMarkdown(pkg([
        ...bad.map((d) => sig('exfil-endpoint', 'hard-coded exfiltration-style endpoint', d, `@x/${d}`)),
        ...bad.map((d) => ({ severity: 'medium', category: 'dependency', kind: 'new-dependency', title: `New dependency: ${d} ${d}`, detail: d, dependency: d, spec: d, locations: [] })),
        ...bad.map((d) => ({ severity: 'high', category: 'dependency', kind: 'dependency-source-changed', title: `Dependency ${d} now comes from outside the registry`, detail: `${d} → ${d}`, locations: [] })),
        { severity: 'low', category: 'security', kind: 'new-host', title: '5 new hard-coded host name(s)', detail: bad.join(', '), locations: [] },
    ]));
    assert.deepEqual(renderedMentions(out), [], out);
});

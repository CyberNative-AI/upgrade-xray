// Reports are posted as pull-request comments: npm scopes and hostile package data must not become
// @mentions there. Checked on the rendered HTML, the way GitHub finds mentions: in text outside
// code, pre and links, after entities are decoded.
import test from 'node:test';
import assert from 'node:assert/strict';
import MarkdownIt from 'markdown-it';
import { runInput } from '../src/main.js';
import { packageMarkdown, packagesReport } from '../src/report.js';
import { memoryIo } from './helpers.js';

const md = new MarkdownIt({ html: true, linkify: true });
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", commat: '@', nbsp: ' ' };
const decode = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => (e[0] === '#' ? String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e.toLowerCase()] ?? m));
export function renderedMentions(markdown) {
    const html = md.render(markdown)
        .replace(/<(code|pre|a)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
        .replace(/<[^>]*>/g, ' ');
    return decode(html).match(/(?:^|[^A-Za-z0-9_])@[A-Za-z0-9][\w-]*/g) || [];
}
const codes = (markdown) => [...md.render(markdown).matchAll(/<code>([^<]*)<\/code>/g)].map((m) => decode(m[1]));

const pub = (n, v) => ({ version: v, resolved: `https://registry.npmjs.org/${n}/-/${n.split('/').pop()}-${v}.tgz` });
const lock = (pkgs) => JSON.stringify({ lockfileVersion: 3, packages: { '': {}, ...Object.fromEntries(Object.entries(pkgs).map(([k, v]) => [`node_modules/${k}`, v])) } });

// Text an attacker can put in a package, its files or a lockfile, each aimed at breaking a code span.
const HOSTILE = [
    'malformed archive `@victim',
    '``@a`` ` @b `@c` \\`@d` \\',
    '&#64;e &#x40;f &commat;g &#064h',
    '<b title="`">@i</b> <x a="',
    '[t](u`rl) @j `x',
    'line\n\n```\n@k\n```\n\n    @l',
    'path/@m and (@n) and "@o"',
    // Adjacent mentions: quoting the first must not leave the next one outside code.
    'malformed archive @one@victim',
    'a@b@c @p/@q @r.@s (@t)@u @v-@w x@@y @z,@aa',
    '`@ab`@ac @ad`@ae`',
];

test('the oracle finds the mentions it should', () => {
    assert.deepEqual(renderedMentions('hi @x and `@y`').map((s) => s.trim()), ['@x']);
    assert.equal(renderedMentions('failed at `@victim').length, 1, 'an unmatched backtick does not protect');
    assert.equal(renderedMentions('a &#64;b').length, 1, 'entities are decoded');
});

test('an error message is one code span when rendered, adjacent at-signs included', () => {
    const out = packageMarkdown({ name: 'pkg', ecosystem: 'npm', error: 'malformed archive @one@victim' });
    assert.ok(md.render(out).includes('<code>malformed archive @one@victim</code>'), md.render(out));
    assert.deepEqual(renderedMentions(out), []);
});

test('every untrusted field of a package result renders without a mention', () => {
    for (const h of HOSTILE) {
        const r = {
            ecosystem: 'npm', name: `@evil/x${h}`, fromVersion: `1.0.0${h}`, toVersion: `1.0.1 ${h}`, verdict: 'review', coverage: { complete: false, unparsedFilesCount: 1, unparsedFiles: [{ file: `${h}.js`, reason: h }], skippedFilesCount: 0, skippedFiles: [], failedArtifacts: [h] },
            findings: [
                { category: 'security', severity: 'high', title: `New dependency ${h}`, detail: h, artifact: h, locations: [{ file: h, line: 3 }] },
                { category: 'breaking', severity: 'medium', title: `Removed ${h}` },
                { category: 'other', severity: 'info', title: `Note ${h}`, detail: `${h}!` },
            ],
            files: { added: 1, changed: 0, removed: 0, total: 1 }, notes: [h],
        };
        for (const out of [packageMarkdown(r), packageMarkdown({ ecosystem: 'npm', name: h, toVersion: h, error: h }), packagesReport([r], { verdict: 'review', coverage: { complete: true } })]) {
            assert.deepEqual(renderedMentions(out), [], `${JSON.stringify(h)}\n${out}`);
        }
    }
});

test('lockfile REPORT and dataset markdown carry no mentions, and scoped names stay readable', async () => {
    const before = lock({ '@solana/web3.js': pub('@solana/web3.js', '1.95.6'), '@types/old': pub('@types/old', '1.0.0'), '@babel/core': pub('@babel/core', '7.0.0'), '@corp/priv': { version: '1.0.0', resolved: 'https://npm.corp.example/@corp/priv/-/priv-1.0.0.tgz' } });
    const after = lock({ '@solana/web3.js': pub('@solana/web3.js', '1.95.7'), '@octo/new': pub('@octo/new', '2.0.0'), '@babel/core': pub('@babel/core', '7.0.1'), '@corp/priv': { version: '1.0.1', resolved: 'https://npm.corp.example/@corp/priv/-/priv-1.0.1.tgz' } });
    const io = memoryIo({
        analyze: async (s) => (s.name === '@babel/core'
            ? { ecosystem: s.ecosystem, name: s.name, error: HOSTILE[0] }
            : { ecosystem: s.ecosystem, name: s.name, fromVersion: s.from, toVersion: s.to, verdict: s.name.startsWith('@solana') ? 'review' : 'clean', findings: s.name.startsWith('@solana') ? [{ category: 'security', severity: 'high', title: `New dependency @evil/drain first published 2 days ago ${HOSTILE[3]}` }] : [], counts: {}, coverage: { complete: true } }),
    });
    await runInput({ lockfileBefore: before, lockfileAfter: after }, io);
    assert.deepEqual(renderedMentions(io.kv.REPORT), [], io.kv.REPORT);
    for (const name of ['@solana/web3.js', '@types/old', '@octo/new', '@corp/priv']) assert.ok(codes(io.kv.REPORT).includes(name), `${name} is shown as code`);
    // A title diffSnapshots did not build is shown whole as code.
    assert.ok(codes(io.kv.REPORT).some((c) => c.startsWith('New dependency @evil/drain first published')), io.kv.REPORT);
    assert.ok(io.items.length > 0);
    for (const item of io.items) assert.deepEqual(renderedMentions(item.markdown || ''), [], item.name);
    assert.deepEqual(renderedMentions(io.kv.OUTPUT.markdown), []);
});

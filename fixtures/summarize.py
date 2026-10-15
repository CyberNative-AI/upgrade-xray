"""Summarise fixture runs into fixtures/results.json and print a markdown table."""
import collections, json, math, re, sys

from packaging.version import InvalidVersion, Version


def semver_key(v):
    """npm semver precedence: release > its prereleases; numeric prerelease ids < alphanumeric."""
    m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$', v)
    if not m:
        return (1, (), v)
    pre = m.group(4)
    ids = tuple((0, int(x), '') if x.isdigit() else (1, 0, x) for x in pre.split('.')) if pre else ()
    return (0, (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, ids), '')


def version_key(r):
    if r['ecosystem'] == 'npm':
        return semver_key(r['version'])
    try:
        return (0, Version(r['version']), '')
    except InvalidVersion:
        return (1, (), r['version'])

def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k / n; d = 1 + z*z/n; c = p + z*z/(2*n); a = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))
    return ((c - a) / d, (c + a) / d)

def load(p): return [json.loads(l) for l in open(p)]

out = {}
for split in ('dev', 'holdout'):
    m = load(f'fixtures/results/mal-{split}.jsonl'); b = load(f'fixtures/results/ben-{split}.jsonl')
    comp = [r for r in m if r.get('comparable') == 'yes']
    upd = [r for r in comp if r.get('mode') == 'update']
    new = [r for r in comp if r.get('mode') != 'update']
    hit = lambda rs: sum(r['verdict'] == 'review' for r in rs)
    pkgs = {}
    for r in sorted(upd, key=lambda r: (r['ecosystem'], r['name'], version_key(r))):
        pkgs.setdefault((r['ecosystem'], r['name']), r)
    byeco = {e: [r for r in upd if r['ecosystem'] == e] for e in ('npm', 'pypi')}
    bok = [r for r in b if 'verdict' in r]
    out[split] = {
        'malicious_samples': len(m),
        'not_comparable': dict(collections.Counter(r.get('comparable') for r in m if r.get('comparable') not in ('yes', None))),
        'excluded_errors': {
            'registry_not_found': sum('error' in r and r['error'].startswith('not found') for r in m),
            'download_too_large': sum('error' in r and 'larger than' in r['error'] for r in m),
            'other': sum('error' in r and not r['error'].startswith('not found') and 'larger than' not in r['error'] for r in m),
        },
        'updates': {'n': len(upd), 'review': hit(upd), 'notice': sum(r['verdict'] == 'notice' for r in upd), 'ci95': wilson(hit(upd), len(upd))},
        'updates_by_ecosystem': {e: {'n': len(v), 'review': hit(v)} for e, v in byeco.items()},
        'updates_first_version_per_package': {'n': len(pkgs), 'review': hit(pkgs.values()), 'ordering': 'semver (npm) / PEP 440 (PyPI)'},
        'new_packages': {'n': len(new), 'review': hit(new)},
        'by_discovery_month': {k: {'n': len(v), 'review': hit(v)} for k, v in sorted(collections.defaultdict(list, {}).items())},
        'high_kinds_in_hits': dict(collections.Counter(k for r in upd if r['verdict'] == 'review' for k in r['highKinds']).most_common()),
        'misses': [f"{r['ecosystem']}:{r['name']} {r['before']}->{r['version']} ({r['verdict']})" for r in upd if r['verdict'] != 'review'],
        'benign': {'n': len(bok), 'errors': [f"{r['ecosystem']}:{r['name']}: {r['error'][:120]}" for r in b if 'error' in r],
                   'review': sum(r['verdict'] == 'review' for r in bok), 'notice': sum(r['verdict'] == 'notice' for r in bok),
                   'clean': sum(r['verdict'] == 'clean' for r in bok), 'ci95_review': wilson(sum(r['verdict'] == 'review' for r in bok), len(bok)),
                   'by_ecosystem': {e: {'n': sum(r['ecosystem'] == e for r in bok), 'review': sum(r['ecosystem'] == e and r['verdict'] == 'review' for r in bok)} for e in ('npm', 'pypi')},
                   'false_alarms': [f"{r['ecosystem']}:{r['name']} {r['from']}->{r['to']}: {r['top'][:2]}" for r in bok if r['verdict'] == 'review']},
    }
    months = collections.defaultdict(list)
    for r in upd: months[(r.get('date') or '?')[:7]].append(r)
    out[split]['by_discovery_month'] = {k: {'n': len(v), 'review': hit(v)} for k, v in sorted(months.items())}
json.dump(out, open('fixtures/results/summary.json', 'w'), indent=1)
print(json.dumps(out['holdout'], indent=1)[:6000])

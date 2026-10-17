# Upgrade X-Ray

**See what a dependency update really changes before you merge it — computed from the published npm and PyPI files, not from the changelog.**

For each update, Upgrade X-Ray downloads the old and new published artifacts (npm tarball, PyPI wheel and sdist) from the public registry hosts only, refuses any download that does not match a registry checksum, and compares them statically. Nothing is installed or executed. It reports:

- **New install-time code** — new or changed `preinstall` / `install` / `postinstall` scripts, implicit `node-gyp` builds, `setup.py` command hooks, in-tree build backends, and `.pth` / `sitecustomize` files that run at every Python start-up.
- **New network, shell or eval calls** — new uses of `child_process`, `subprocess`, `fetch`, `http(s)`, `socket`, `requests`, `eval`, `exec`, `new Function`, `vm`, code launched with inline or base64-encoded payloads, and a new Python process started when the package is imported.
- **High-risk indicators** — obfuscation (including code hidden after long runs of spaces and payloads hidden in invisible Unicode characters), reads of credential files (`.npmrc`, `.ssh`, cloud and wallet keys), requests that send a seed phrase or a secret or private key to a hard-coded address, exfiltration-style endpoints, token theft and self-publishing, persistence, overrides of global `fetch` / `XMLHttpRequest` / wallet functions, and new executables.
- **Removed functions** — exports removed from each entry point or module (JS, TypeScript declarations, Python public names), removed import paths and commands, a switch to ES modules, and raised engine / Python requirements.
- **New dependencies** — with their age and listed owners: a dependency first published days before the release that shares no listed maintainer or repository with the package (or lists none) is flagged high; one that does not exist on the registry, or comes from git or a URL, is flagged high. Owners are compared as the registry lists them (npm maintainers and repository URLs, PyPI's self-declared author emails and project URLs); they are not verified identities.

Each package gets a verdict: **🔴 review before merge**, **🟡 worth a look**, **🟢 nothing new found** (**🟢 low notes only** when its only findings are Low ones, which never raise a verdict), or **⚪ partly analysed** when nothing was found but some of its files could only be pattern-scanned or not read, or one of its artifacts could not be compared. The package lists those files and the reason.

## Example: two compromised npm releases from 2025

These are the reports Upgrade X-Ray writes for two well-known bad releases, each compared with the clean version before it (the registry no longer serves the bad versions, so they were read from the labelled dataset described under *Measured accuracy*):

- [`@ctrl/tinycolor` 4.1.0 → 4.1.1](https://github.com/CyberNative-AI/upgrade-xray/blob/main/examples/ctrl-tinycolor-4.1.1.md) — a self-spreading worm: a new `postinstall` script that runs a bundled file which steals npm and GitHub tokens and republishes packages.
- [`debug` 4.4.1 → 4.4.2](https://github.com/CyberNative-AI/upgrade-xray/blob/main/examples/debug-4.4.2.md) — a crypto-wallet drainer hidden as obfuscated code inside the package's normal entry point, with no install script.

`fixtures/example-report.js` regenerates them.

## Two ways to run it

**Package mode** — one or more updates, charged per package:

```json
{ "packages": ["npm:axios@1.7.9..1.8.0", "pypi:requests@2.31.0..2.32.0", "pypi:urllib3==2.5.0", "esbuild"] }
```

`name@from..to` compares two versions; `name@to` or `pypi:name==to` compares a version with the release before it; a bare name compares the previous release with the latest.

**Lockfile mode** — the old and new lockfile of a pull request, one report for every changed package:

```json
{ "lockfileBefore": "<old package-lock.json>", "lockfileAfter": "<new package-lock.json>" }
```

Supported: `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (v5–v9, including the two-document files of pnpm 11 and later), `yarn.lock` (Yarn 1 and Yarn 2 and later), `bun.lock` (the text lockfile of bun 1.2 and later; the binary `bun.lockb` is not read), `uv.lock`, `poetry.lock` and pip requirements files (`requirements.txt`; exact `==` pins are compared, version ranges are listed), pasted as text (up to 20 MB each; a line longer than 16,384 characters in a Yarn 1 `yarn.lock` or a requirements file is refused, since Yarn 1 and pip-compile write lines of a few hundred). Packages new to the tree are checked for install scripts and high-risk indicators.

Only entries whose recorded source is the public registry (`https://registry.npmjs.org`, `https://registry.yarnpkg.com`, `https://pypi.org`, `https://files.pythonhosted.org`) are looked up. Entries from private registries, mirrors, git, URLs or local paths are listed but **not looked up** — their names are not sent anywhere. pnpm, Yarn 2 and later, bun and Poetry do not record the source of packages from the default registry, a requirements file names its index only if it has an `--index-url` line, and some npm lockfiles omit it; those entries are also listed and skipped unless you set `assumePublicRegistry` to confirm that they all come from the public registry. Leave it off if the project uses a private registry or mirror. A requirements file is public only when its one index is `https://pypi.org/simple`. One with any other index, an `--extra-index-url`, `--find-links`, an included file (`-r`, `-c`, which is not read) or an option set from an environment variable is never looked up, even with `assumePublicRegistry`, because pip may take any of its packages from those sources. A requirements file is read as pip reads it; one with an option this tool does not read in full (an abbreviation, an unknown option, quoting) is refused, not partly read. A package that moves from another source to the public registry is scanned as new and called out, since that is a common dependency-confusion pattern.

## Output

- **Dataset** — one item per package: verdict, findings with file and line, new and removed dependencies, API changes, and a ready-to-post markdown section.
- **Key-value store** — `REPORT` (the full markdown verdict, e.g. for a pull-request comment) and `OUTPUT` (summary JSON).

`OUTPUT.verdict` is `review` or `notice` when an analysed package needs it. Otherwise it is `clean` only when every change in scope was analysed in full; `incomplete` when nothing needing review was found but some changes were not analysed (failed, not looked up, or above the package limit) or some packages were only partly analysed; and `error` when no change could be analysed. Each dataset item's `verdict` follows the same rule (`incomplete` for a partly analysed package). `OUTPUT.complete` and `OUTPUT.coverage` give the counts; check them before treating a run as clean.

AI agents can call it through the Apify MCP server; the markdown is designed to be pasted into a pull-request review as is.

## Pricing

Pay per event, no subscription:

| Event | Price |
|---|---|
| Package diff (package mode) | $0.02 per package analysed |
| Lockfile report (lockfile mode) | $0.25 per report, up to 150 changed packages (configurable to 300) |

In package mode, a package that cannot be analysed (not found, too large, failed checksum) is not charged. In lockfile mode, the report is charged once if at least one package was analysed, even if others failed or were skipped; a report where no package could be analysed is not charged. A run never goes over the maximum charge you set.

## Measured accuracy

Measured on 2026-10-15 with the detectors frozen in advance. Detectors were tuned on a *dev* split only; the numbers below are from the *holdout* split, which was run once. The split is a fixed hash of the package name, so every version of a package falls on the same side.

**Compromised versions.** Labelled compromised versions of legitimate packages from the [Datadog malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset) (`compromised_lib`, Apache-2.0), each compared with the closest earlier clean version from the registry:

| Holdout set | Flagged "review before merge" |
|---|---|
| All comparable updates | **988 / 998 (99.0%, 95% CI 98.2–99.5%)** |
| npm | 982 / 988 |
| PyPI | 6 / 10 |
| First compromised version of each package only | 698 / 703 |
| Compromised first releases (no earlier version, scanned as new packages) | 43 / 47 |

Excluded and listed separately: 12 samples that are a git checkout rather than the published file, 2 samples with no code, 27 where the registry no longer serves the package or the earlier version needed for the comparison, and 1 whose download was above the size limit. "First compromised version" uses semantic-version order for npm and PEP 440 order for PyPI.

**Read these numbers with care.** Most samples come from a few large worm campaigns (September and November 2025, May–June 2026) that add install scripts and obvious credential theft — the easy case for this kind of tool. The misses are the targeted attacks that hid key theft inside normal code paths of the package: `xrpl` 4.2.1–4.2.4 and 2.14.2, `@solana/web3.js` 1.95.7, `litellm` 1.82.7, `lightning` 2.6.2–2.6.3 and `guardrails-ai` 0.10.1 (`xrpl` 2.14.2, `lightning` and `guardrails-ai` got "worth a look", the rest "nothing new"). PyPI coverage is small. Treat the tool as a reader's guide to what changed, not a malware scanner.

**Change after this measurement (2026-10-16).** We read the misses and changed the detector. A new Python process started on import (at module level or from a package `__init__`), or started next to a long encoded string or a download, is now flagged. Strong indicators such as credential paths are now also compared file by file, so an old file can no longer hide the same indicator added to another file. All four PyPI misses (`litellm` 1.82.7, `lightning` 2.6.2–2.6.3, `guardrails-ai` 0.10.1) now get "review before merge": all comparable updates 992 / 998, PyPI 10 / 10. This re-run is not an independent test, because these samples shaped the change. No other verdict changed on the 1,477 labelled samples, on the 150 benign major bumps, or on 160 newly picked ordinary releases (the latest update of the next most-downloaded PyPI and npm packages). One of those 160 got "review before merge" both before and after the change: `nodeenv` 1.11.0, which newly writes an `.npmrc` file. The re-run is in [`fixtures/results/rerun-2026-10-16/`](https://github.com/CyberNative-AI/upgrade-xray/tree/main/fixtures/results/rerun-2026-10-16).

**Change after this measurement (2026-10-17).** We gave a general-purpose coding agent the same updates and fixed three gaps the comparison showed. A request to an address written in the code (not a well-known site) that sends a seed phrase or a secret or private key, directly or through the function the request is in, is now flagged. With it, the remaining npm misses (`xrpl` 4.2.1–4.2.4 and 2.14.2, `@solana/web3.js` 1.95.7) get "review before merge": all comparable updates 998 / 998, npm 988 / 988, first compromised version of each package 703 / 703; compromised first releases stay at 43 / 47. This re-run is not an independent test either: these samples shaped the change, and a targeted attack that hides keys in a way the rule does not follow is still missed (see Limits). An `.npmrc` path that a script sets as npm's config location under an environment variable (`npm_config_userconfig="$NODE_VIRTUAL_ENV/.npmrc"`) no longer counts as a credential read, so `nodeenv` 1.11.0 now gets "worth a look" instead of "review before merge". PyPI wheels are now compared on a tag both versions publish. No verdict changed on the 150 benign major bumps, and none of the 160 ordinary releases gets "review before merge" (11 get "worth a look"). The re-run is in [`fixtures/results/rerun-2026-10-17/`](https://github.com/CyberNative-AI/upgrade-xray/tree/main/fixtures/results/rerun-2026-10-17).

**Benign major bumps.** The latest major-version bump of the most-downloaded packages on npm and PyPI (ranking from ecosyste.ms, picked in rank order, not by hand), released between 2021-10-01 and 2026-10-01. For 0.x packages a minor bump (0.4 → 0.5) counts as a major one:

| Holdout set | "Review before merge" (false alarm) | "Worth a look" |
|---|---|---|
| 50 npm + 50 PyPI major bumps | **0 / 100 (95% CI 0–3.7%)** | 12 / 100 |

The full per-sample results, the selection script and the harness are in [`fixtures/`](https://github.com/CyberNative-AI/upgrade-xray/tree/main/fixtures). Rates will be re-measured on compromised versions published after this date.

## Limits

- Static analysis of JavaScript, TypeScript and Python with real parsers (acorn, Python's `ast`). TypeScript is converted to JavaScript with Node's own type stripper first; when that needs Node's transform mode (enums, namespaces), findings in that file carry no line number. JSX/TSX files, files above the 6 MB parser limit and files that do not parse get a pattern scan only; each package lists them. Files above the size limits, encrypted entries and unsupported compression are not read and are listed. Native binaries are reported as new files, not analysed.
- A tunnel or paste-site host name that appears only as an entry in a long list of bare host names (for example a bundled public suffix list), nowhere else in the package and not in install-time code, is reported as low, not high. The tool does not follow how the list is used. A full URL in such a list stays high.
- A version that was removed from the registry cannot be compared, because its files are gone. This includes many well-known compromised releases. On npm, the row says the version was removed and gives its publish date. The row is not charged. PyPI keeps no record of a deleted release, so it is reported as not found.
- A dependency's age and owner are read from the registry at run time.
- A request counts as sending key material when its own arguments, or the arguments of a call to the function it is in, use a name such as `seed`, `mnemonic`, `secretKey` or `privateKey`, and its address is a URL written in the call (not a well-known site). Keys under other names, keys passed on through further functions, and addresses kept in a variable are not followed. This check covers JavaScript and TypeScript, not Python.
- An `.npmrc` path that a script sets as npm's own config location (`npm_config_userconfig="$NODE_VIRTUAL_ENV/.npmrc"`, `--userconfig $PREFIX/.npmrc`) is not reported as a credential read when its directory is a variable whose name does not suggest the home directory. The variable's value is not known, so this is a heuristic: a script that sets such a variable to the home directory first is not caught by this check. Every other `.npmrc` path, including `$HOME/.npmrc`, `~/.npmrc` and a bare `.npmrc`, still counts, as do `.pypirc` and `.netrc` anywhere.
- npm packages are compared as published (one tarball). For PyPI, a wheel and the sdist are compared separately and merged. The wheel is the best one whose tag (Python version, ABI, platform) both versions publish; only when they share none is each version's best wheel used. Very large distributions (over 60 MB) are not analysed.
- A finding is a change worth reading, not proof of malice; an empty report does not prove a package is safe.

## Privacy and what to send

The Actor runs in your Apify account and keeps its input, logs and results in that run's storage, under your retention settings; you can delete them at any time. It sends nothing to the publisher and has no publisher credentials or telemetry. It contacts only the public npm registry and PyPI.

- **What leaves the run:** package names and versions that are proven to come from the public registry (or that you confirm with `assumePublicRegistry`), sent to that registry. Nothing else is looked up.
- **What to paste:** only lockfiles you are allowed to process, with credentials, tokens and signed URLs removed. Upgrade X-Ray strips user names, passwords and query strings from the sources it reports, but the pasted input itself is stored as you gave it.
- **What the report contains:** package names, versions and the sources of entries that were not looked up. Treat `REPORT`, `OUTPUT` and the dataset as being as sensitive as the lockfile.
- **Sharing:** Apify lets you share a run with an Actor's developer, and putting a run link in an Actor issue grants that access. A shared run exposes its input, logs and storages to us. For sensitive lockfiles, keep your account's resource access restricted, leave automatic sharing with developers off, and do not post run links. We never ask for private lockfiles, tokens or run links; for support, send a small synthetic lockfile that reproduces the problem.

## About

Built and maintained by **CyberNative AI LLC**, an AI-run company: the tool, the detectors and this README were written by AI agents. Report false alarms, misses or errors in the Actor's [Issues tab](https://apify.com/cybernative-ai/upgrade-xray/issues) on Apify, using public packages or synthetic examples only. Licensed under the Apache License 2.0 (see `LICENSE`); dependencies keep their own licenses.

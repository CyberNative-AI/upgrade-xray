## Upgrade X-Ray

**Overall: 🔴 Review before merge**

**1 to review · 0 worth a look · 0 nothing new**

### 🔴 REVIEW BEFORE MERGE — `@ctrl/tinycolor` 4.1.0 → 4.1.1 (npm)

- **High** New install-time script: postinstall: `node bundle.js` · in `package.json`
- **High** Code that runs at install or start-up gained: hard-coded exfiltration-style endpoint; publishes packages, reads tokens or edits ci workflows; dynamic code evaluation; network access; reads credential or wallet locations; reads the whole environment; collects the whole environment and has network access in the same file · in `bundle.js`
- **High** New: hard-coded exfiltration-style endpoint: `webhook.site`, `169.254.169.254`, `metadata.google.internal` · in `bundle.js:2`
- **High** New: publishes packages, reads tokens or edits ci workflows: `GITHUB_TOKEN`, `NPM token`, `NPM whoami`, `npm publish`, `gh auth token`, `trufflehog` · in `bundle.js:2` …
- **High** New: reads credential or wallet locations — `.npmrc` · in `bundle.js:2`
- **High** New: collects the whole environment and has network access in the same file — `whole environment + network in one file` · in `bundle.js`
- **Medium** New: dynamic code evaluation: `Function()`, `eval()` · in `bundle.js:2`
- **Medium** New: network access: `fetch()`, `XMLHttpRequest()` · in `bundle.js:2` …
- **Medium** New: reads the whole environment: `t(process.env)`, `Object.keys(process.env)` · in `bundle.js:2`
- **Low** 20 new hard-coded host name(s): `webhook.site`, `sts.amazonaws.com`, `aws.amazon.com`, `docs.aws.amazon.com`, `oauth2.googleapis.com`, `www.googleapis.com` and 14 more · in `bundle.js:2` …
- **Low** 1 new minified file(s) outside usual build folders — `bundle.js`

<sub>Files: 1 added, 1 changed, 0 removed (of 42).</sub>

<sub>Static analysis of the published files: nothing was installed or executed. A finding is a change worth reading, not proof of malware, and an empty report does not prove a package is safe.</sub>

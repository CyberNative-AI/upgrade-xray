// Finding titles and notes are fixed prose with package data inside: "Removed module: <name>". The
// tool builds them with each package value marked, so the Markdown report shows the fixed words as
// text and each value as code, while titles and notes in the JSON output stay plain text.
//
// Trust comes from where a string was built, never from what it contains. The marked form is kept
// under a Symbol key on the finding or result that the tool built (Symbol keys stay out of JSON), so
// no string a package, a registry or an error message supplies can become fixed prose, whatever
// characters it contains. Anything without a marked form is shown as one code span.
const OPEN = String.fromCharCode(0xe000);
const CLOSE = String.fromCharCode(0xe001);
const MARKS = new RegExp(`[${OPEN}${CLOSE}]`, 'g');
const REPLACEMENT = String.fromCharCode(0xfffd);

/** The marked title of a finding built by diffSnapshots. */
export const MARKED_TITLE = Symbol('markedTitle');

/** The marked notes of a snapshot or result, index for index with its plain `notes`. */
export const MARKED_NOTES = Symbol('markedNotes');

/** A package value inside fixed prose. Marker characters in the value itself become U+FFFD. */
export const mark = (v) => `${OPEN}${String(v).replace(MARKS, REPLACEMENT)}${CLOSE}`;

export const unmark = (s) => String(s).replace(MARKS, '');

/** Alternating fixed text and marked values: [fixed, value, fixed, …]. Stray markers are dropped. */
export function segments(s) {
    const out = [''];
    for (const c of String(s)) {
        if (c === OPEN) { if (out.length % 2) out.push(''); } else if (c === CLOSE) { if (!(out.length % 2)) out.push(''); } else out[out.length - 1] += c;
    }
    return out;
}

/** Add a note the tool built (a template with its package values marked) to a snapshot. */
export function addNote(snap, marked) {
    snap.notes.push(unmark(marked));
    (snap[MARKED_NOTES] ??= [])[snap.notes.length - 1] = marked;
}

/** The marked form of note i, when the tool built that note. */
export function markedNote(r, i) {
    const m = r[MARKED_NOTES]?.[i];
    return m !== undefined && unmark(m) === r.notes[i] ? m : undefined;
}

/** The notes of several snapshots or results, deduplicated in order and cut at limit, with their marked forms. */
export function mergeNotes(sources, limit = Infinity) {
    const out = { notes: [], [MARKED_NOTES]: [] };
    const seen = new Set();
    for (const s of sources) {
        (s?.notes || []).forEach((n, i) => {
            if (seen.has(n) || out.notes.length >= limit) return;
            seen.add(n);
            out[MARKED_NOTES][out.notes.length] = markedNote(s, i);
            out.notes.push(n);
        });
    }
    return out;
}

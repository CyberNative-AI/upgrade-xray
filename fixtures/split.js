// Fixed dev/holdout split by package name: detectors are tuned on "dev" only;
// published rates come from "holdout".
import crypto from 'node:crypto';

export const splitOf = (name) => (parseInt(crypto.createHash('sha1').update(name).digest('hex').slice(0, 2), 16) < 64 ? 'dev' : 'holdout');

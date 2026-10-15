// Local command line: node src/cli.js npm chalk 4.1.2 5.0.0   (from/to optional)
import { analyzePackage } from './analyze.js';

const [ecosystem, name, from, to] = process.argv.slice(2);
const r = await analyzePackage({ ecosystem, name, from: from || undefined, to: to || undefined });
console.log(JSON.stringify(r, (k, v) => (v instanceof Set ? [...v] : v), 2));

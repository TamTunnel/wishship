// Fails if any compiled artifact sits next to a .ts source. Test imports
// resolve stale .js first, so a green suite against stale files means
// nothing — build output lives in dist/ only.
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const roots = ["src", "client/src"];
let bad = [];
function walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules") continue;
      walk(p);
    } else if (e.isFile() && /\.(js|d\.ts)$/.test(e.name) && !e.name.endsWith(".config.js")) {
      const base = e.name.replace(/\.d\.ts$/, "").replace(/\.js$/, "");
      const ts = join(dir, `${base}.ts`);
      const tsx = join(dir, `${base}.tsx`);
      try {
        statSync(ts);
        bad.push(p);
      } catch {
        try {
          statSync(tsx);
          bad.push(p);
        } catch {
          // No matching source; not a stale artifact.
        }
      }
    }
  }
}
for (const r of roots) walk(r);
if (bad.length > 0) {
  console.error("Stale build artifacts next to sources:\n" + bad.join("\n"));
  process.exit(1);
}
console.log("No stale in-source artifacts.");

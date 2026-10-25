import { defineConfig, type Plugin } from "vitest/config";

// node:sqlite (stable in Node 22.5+) is not in esbuild/Vite 5.x's built-in list,
// so Vite tries to load it as a file. This plugin redirects the import to a virtual
// module that loads node:sqlite via createRequire at runtime — synchronous, no
// top-level await, invisible to Vite's static import analysis.
const nodeSqlitePlugin: Plugin = {
  name: "node-sqlite-virtual",
  enforce: "pre",
  resolveId(id) {
    if (id === "node:sqlite" || id === "sqlite") {
      return "\0virt:node-sqlite";
    }
  },
  load(id) {
    if (id === "\0virt:node-sqlite") {
      return `
import { createRequire } from "module";
const _cwd = process.cwd().split("\\\\").join("/");
const _url = "file://" + (_cwd[0] === "/" ? "" : "/") + _cwd + "/x.js";
const _r = createRequire(_url);
const { DatabaseSync, StatementSync } = _r("node:sqlite");
export { DatabaseSync, StatementSync };
`;
    }
  },
};

export default defineConfig({
  plugins: [nodeSqlitePlugin],
  test: {
    environment: "node",
  },
});

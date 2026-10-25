import { defineConfig, type Plugin } from "vitest/config";

// node:sqlite is not in esbuild/Vite 5.x's built-in list. This virtual module
// plugin intercepts the stripped "sqlite" import and loads it synchronously via
// createRequire — avoiding top-level await timing issues in virtual ESM modules.
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
    include: ["src/**/*.test.ts"],
  },
});

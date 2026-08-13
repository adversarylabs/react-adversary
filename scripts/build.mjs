import { build } from "esbuild";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });

await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  minifyWhitespace: true,
  legalComments: "external",
  outfile: "dist/index.js",
  banner: {
    js: [
      "import { createRequire as __reactCreateRequire } from 'node:module';",
      "import { fileURLToPath as __reactFileURLToPath } from 'node:url';",
      "import { dirname as __reactDirname } from 'node:path';",
      "const require = __reactCreateRequire(import.meta.url);",
      "const __filename = __reactFileURLToPath(import.meta.url);",
      "const __dirname = __reactDirname(__filename);",
    ].join(" "),
  },
});

const legalNotice = await readFile("dist/index.js.LEGAL.txt", "utf8");
await writeFile(
  "dist/index.js.LEGAL.txt",
  `${legalNotice.split("\n").map((line) => line.trimEnd()).join("\n").trimEnd()}\n`,
);

await mkdir("schemas", { recursive: true });
await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.review.v1.schema.json",
  "schemas/adversary.review.v1.schema.json",
);

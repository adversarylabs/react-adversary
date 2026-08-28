#!/usr/bin/env node

import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Adversary } from "@adversarylabs/sdk";
import { analyzeRepository } from "./analyze.js";
import { registerRules } from "./rules.js";

export function createApp(): Adversary {
  const app = new Adversary({ name: "web/react", version: "0.0.14", review: { maximumFindings: 12 } });
  registerRules(app);
  app.rule("react.review", async (ctx) => analyzeRepository(ctx));
  return app;
}

if (
  process.argv[1] !== undefined &&
  (await realpath(process.argv[1])) === (await realpath(fileURLToPath(import.meta.url)))
) {
  await createApp().runFromEnvironment();
}

import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import ts from "typescript";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  status: "added" | "modified" | "repository";
  changedLines: Set<number>;
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const sources: SourceFile[] = [];
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  for (const file of scoped) {
    if (wholeTarget || file.status === "repository") {
      sources.push({
        path: file.path,
        source: file.content,
        status: "repository",
        changedLines: new Set<number>(),
      });
      continue;
    }

    const change = await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      status: change.status,
      changedLines: change.changedLines,
    });
  }
  ctx.summary.files_scanned = sources.length;

  const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "raw-href-handler-guard") return matchingSources.flatMap((file) => findRawHrefHandlerGuards(rule, file));

  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locateEligible(file, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locateEligible(file, match.pattern);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

function findRawHrefHandlerGuards(rule: RuleSpec, source: SourceFile): Detection[] {
  const kind = source.path.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.JSX;
  const file = ts.createSourceFile(source.path, source.source, ts.ScriptTarget.Latest, true, kind);
  const sanitizers = collectSanitizerNames(file);
  const safeValues = collectSanitizedValues(file, sanitizers);
  const handlers = collectHandlers(file);
  const detections: Detection[] = [];

  function visit(node: ts.Node): void {
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      if (node.tagName.getText(file) !== "a") { ts.forEachChild(node, visit); return; }
      const href = jsxAttribute(node, "href");
      const onClick = jsxAttribute(node, "onClick");
      const hrefExpression = jsxExpression(href);
      const handlerExpression = jsxExpression(onClick);
      if (!hrefExpression || !handlerExpression || isStaticString(hrefExpression) || isSanitizedExpression(hrefExpression, sanitizers, safeValues, file)) {
        ts.forEachChild(node, visit);
        return;
      }
      const handler = resolveHandler(handlerExpression, handlers);
      const guard = handler && handlerGuardForExpression(handler, hrefExpression, sanitizers, file);
      if (handler && guard) {
        const anchor = eligibleNodeAnchor(source, file, hrefExpression, guard);
        if (anchor === undefined) {
          ts.forEachChild(node, visit);
          return;
        }
        detections.push({
          rule,
          file: source.path,
          ...locationAtLine(source.source, anchor),
          label: `href uses raw ${hrefExpression.getText(file)} while onClick performs URL validation`,
          data: { href: hrefExpression.getText(file), handler: handlerExpression.getText(file) },
        });
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
  return detections;
}

function collectSanitizerNames(file: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  function visit(node: ts.Node): void {
    if (ts.isImportSpecifier(node)) {
      const imported = node.propertyName?.text ?? node.name.text;
      if (looksLikeUrlGuard(imported)) names.add(node.name.text);
    }
    if (ts.isFunctionDeclaration(node) && node.name && looksLikeUrlGuard(node.name.text)) names.add(node.name.text);
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && looksLikeUrlGuard(node.name.text) && node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) names.add(node.name.text);
    ts.forEachChild(node, visit);
  }
  visit(file);
  return names;
}

function looksLikeUrlGuard(name: string): boolean {
  return /(?:saniti[sz]e|neutralize|safe|validate|allow)(?:d|r)?(?:.*url)|(?:url).*(?:safe|valid|allow)/i.test(name);
}

function collectSanitizedValues(file: ts.SourceFile, sanitizers: Set<string>): Set<string> {
  const safe = new Set<string>();
  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && isGuardCall(node.initializer, sanitizers)) safe.add(node.name.text);
    ts.forEachChild(node, visit);
  }
  visit(file);
  return safe;
}

function collectHandlers(file: ts.SourceFile): Map<string, ts.FunctionLikeDeclaration> {
  const handlers = new Map<string, ts.FunctionLikeDeclaration>();
  function visit(node: ts.Node): void {
    if (ts.isFunctionDeclaration(node) && node.name) handlers.set(node.name.text, node);
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) handlers.set(node.name.text, node.initializer);
    ts.forEachChild(node, visit);
  }
  visit(file);
  return handlers;
}

function jsxAttribute(node: ts.JsxOpeningLikeElement, name: string): ts.JsxAttribute | undefined {
  return node.attributes.properties.find((attribute): attribute is ts.JsxAttribute => ts.isJsxAttribute(attribute) && attribute.name.getText() === name);
}

function jsxExpression(attribute: ts.JsxAttribute | undefined): ts.Expression | undefined {
  return attribute?.initializer && ts.isJsxExpression(attribute.initializer) ? attribute.initializer.expression : undefined;
}

function isStaticString(expression: ts.Expression): boolean {
  return ts.isStringLiteralLike(expression) || (ts.isTemplateExpression(expression) && expression.templateSpans.length === 0);
}

function isSanitizedExpression(expression: ts.Expression, sanitizers: Set<string>, safeValues: Set<string>, file: ts.SourceFile): boolean {
  return isStaticString(expression) || isGuardCall(expression, sanitizers) || (ts.isIdentifier(expression) && safeValues.has(expression.text)) ||
    (ts.isConditionalExpression(expression) &&
      isSanitizedExpression(expression.whenTrue, sanitizers, safeValues, file) &&
      isSanitizedExpression(expression.whenFalse, sanitizers, safeValues, file));
}

function resolveHandler(expression: ts.Expression, handlers: Map<string, ts.FunctionLikeDeclaration>): ts.FunctionLikeDeclaration | undefined {
  if (ts.isArrowFunction(expression) || ts.isFunctionExpression(expression)) return expression;
  return ts.isIdentifier(expression) ? handlers.get(expression.text) : undefined;
}

function handlerGuardForExpression(
  handler: ts.FunctionLikeDeclaration,
  href: ts.Expression,
  sanitizers: Set<string>,
  file: ts.SourceFile,
): ts.CallExpression | undefined {
  const target = compactExpression(href.getText(file));
  let guard: ts.CallExpression | undefined;
  function visit(node: ts.Node): void {
    if (guard !== undefined || (node !== handler && ts.isFunctionLike(node))) return;
    if (ts.isCallExpression(node) && isGuardCall(node, sanitizers) && node.arguments.some((argument) => compactExpression(argument.getText(file)) === target)) guard = node;
    ts.forEachChild(node, visit);
  }
  visit(handler);
  return guard;
}

function isGuardCall(expression: ts.Expression, sanitizers: Set<string>): expression is ts.CallExpression {
  if (!ts.isCallExpression(expression)) return false;
  if (ts.isIdentifier(expression.expression)) return sanitizers.has(expression.expression.text) || looksLikeUrlGuard(expression.expression.text);
  return ts.isPropertyAccessExpression(expression.expression) && looksLikeUrlGuard(expression.expression.name.text);
}

function compactExpression(value: string): string {
  return value.replace(/\s+/g, "");
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locateEligible(file: SourceFile, expression: MatchExpression): { line: number; snippet: string } | undefined {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  for (const match of file.source.matchAll(new RegExp(expression.pattern, flags))) {
    if (match.index === undefined) continue;
    const start = match.index;
    const end = start + match[0].length;
    const anchor = eligibleAnchor(
      file,
      lineAt(file.source, start),
      lineAt(file.source, Math.max(start, end - 1)),
    );
    if (anchor === undefined) continue;
    return locationAtLine(file.source, anchor);
  }
  return undefined;
}

function eligibleNodeAnchor(
  source: SourceFile,
  file: ts.SourceFile,
  ...nodes: ts.Node[]
): number | undefined {
  if (source.status !== "modified") return lineAt(source.source, nodes[0]?.getStart(file) ?? 0);
  for (const node of nodes) {
    const anchor = eligibleAnchor(
      source,
      lineAt(source.source, node.getStart(file)),
      lineAt(source.source, Math.max(node.getStart(file), node.getEnd() - 1)),
    );
    if (anchor !== undefined) return anchor;
  }
  return undefined;
}

function eligibleAnchor(file: SourceFile, startLine: number, endLine: number): number | undefined {
  if (file.status !== "modified") return startLine;
  for (let line = startLine; line <= endLine; line += 1) {
    if (file.changedLines.has(line)) return line;
  }
  return undefined;
}

function lineAt(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function locationAtLine(source: string, line: number): { line: number; snippet: string } {
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  return { changedLines: changedLineNumbers(patch), status: "modified" };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}

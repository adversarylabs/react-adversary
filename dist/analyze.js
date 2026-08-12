import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import ts from "typescript";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            spec.files.some((glob) => matchesGlob(path, glob)),
        limit: MAX_FILES,
    });
    const sources = scoped.map((file) => ({ path: file.path, source: file.content }));
    ctx.summary.files_scanned = sources.length;
    const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (sources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
function evaluate(rule, sources, allPaths) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
    if (match.kind === "raw-href-handler-guard")
        return matchingSources.flatMap((file) => findRawHrefHandlerGuards(rule, file));
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locate(file.source, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)))
            return [];
        const location = locate(file.source, match.pattern);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
function findRawHrefHandlerGuards(rule, source) {
    const kind = source.path.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.JSX;
    const file = ts.createSourceFile(source.path, source.source, ts.ScriptTarget.Latest, true, kind);
    const sanitizers = collectSanitizerNames(file);
    const safeValues = collectSanitizedValues(file, sanitizers);
    const handlers = collectHandlers(file);
    const detections = [];
    function visit(node) {
        if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
            if (node.tagName.getText(file) !== "a") {
                ts.forEachChild(node, visit);
                return;
            }
            const href = jsxAttribute(node, "href");
            const onClick = jsxAttribute(node, "onClick");
            const hrefExpression = jsxExpression(href);
            const handlerExpression = jsxExpression(onClick);
            if (!hrefExpression || !handlerExpression || isStaticString(hrefExpression) || isSanitizedExpression(hrefExpression, sanitizers, safeValues, file)) {
                ts.forEachChild(node, visit);
                return;
            }
            const handler = resolveHandler(handlerExpression, handlers);
            if (handler && handlerGuardsExpression(handler, hrefExpression, sanitizers, file)) {
                const start = hrefExpression.getStart(file);
                detections.push({
                    rule,
                    file: source.path,
                    ...locateFromIndex(source.source, start),
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
function collectSanitizerNames(file) {
    const names = new Set();
    function visit(node) {
        if (ts.isImportSpecifier(node)) {
            const imported = node.propertyName?.text ?? node.name.text;
            if (looksLikeUrlGuard(imported))
                names.add(node.name.text);
        }
        if (ts.isFunctionDeclaration(node) && node.name && looksLikeUrlGuard(node.name.text))
            names.add(node.name.text);
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && looksLikeUrlGuard(node.name.text) && node.initializer &&
            (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)))
            names.add(node.name.text);
        ts.forEachChild(node, visit);
    }
    visit(file);
    return names;
}
function looksLikeUrlGuard(name) {
    return /(?:saniti[sz]e|neutralize|safe|validate|allow)(?:d|r)?(?:.*url)|(?:url).*(?:safe|valid|allow)/i.test(name);
}
function collectSanitizedValues(file, sanitizers) {
    const safe = new Set();
    function visit(node) {
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && isGuardCall(node.initializer, sanitizers))
            safe.add(node.name.text);
        ts.forEachChild(node, visit);
    }
    visit(file);
    return safe;
}
function collectHandlers(file) {
    const handlers = new Map();
    function visit(node) {
        if (ts.isFunctionDeclaration(node) && node.name)
            handlers.set(node.name.text, node);
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer &&
            (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)))
            handlers.set(node.name.text, node.initializer);
        ts.forEachChild(node, visit);
    }
    visit(file);
    return handlers;
}
function jsxAttribute(node, name) {
    return node.attributes.properties.find((attribute) => ts.isJsxAttribute(attribute) && attribute.name.getText() === name);
}
function jsxExpression(attribute) {
    return attribute?.initializer && ts.isJsxExpression(attribute.initializer) ? attribute.initializer.expression : undefined;
}
function isStaticString(expression) {
    return ts.isStringLiteralLike(expression) || (ts.isTemplateExpression(expression) && expression.templateSpans.length === 0);
}
function isSanitizedExpression(expression, sanitizers, safeValues, file) {
    return isStaticString(expression) || isGuardCall(expression, sanitizers) || (ts.isIdentifier(expression) && safeValues.has(expression.text)) ||
        (ts.isConditionalExpression(expression) &&
            isSanitizedExpression(expression.whenTrue, sanitizers, safeValues, file) &&
            isSanitizedExpression(expression.whenFalse, sanitizers, safeValues, file));
}
function resolveHandler(expression, handlers) {
    if (ts.isArrowFunction(expression) || ts.isFunctionExpression(expression))
        return expression;
    return ts.isIdentifier(expression) ? handlers.get(expression.text) : undefined;
}
function handlerGuardsExpression(handler, href, sanitizers, file) {
    const target = compactExpression(href.getText(file));
    let guarded = false;
    function visit(node) {
        if (guarded || (node !== handler && ts.isFunctionLike(node)))
            return;
        if (ts.isCallExpression(node) && isGuardCall(node, sanitizers) && node.arguments.some((argument) => compactExpression(argument.getText(file)) === target))
            guarded = true;
        ts.forEachChild(node, visit);
    }
    visit(handler);
    return guarded;
}
function isGuardCall(expression, sanitizers) {
    if (!ts.isCallExpression(expression))
        return false;
    if (ts.isIdentifier(expression.expression))
        return sanitizers.has(expression.expression.text) || looksLikeUrlGuard(expression.expression.text);
    return ts.isPropertyAccessExpression(expression.expression) && looksLikeUrlGuard(expression.expression.name.text);
}
function compactExpression(value) {
    return value.replace(/\s+/g, "");
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locate(source, expression) {
    const match = new RegExp(expression.pattern, expression.flags).exec(source);
    if (match?.index === undefined)
        return undefined;
    const line = source.slice(0, match.index).split(/\r?\n/).length;
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
function locateFromIndex(source, index) {
    const line = source.slice(0, index).split(/\r?\n/).length;
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}

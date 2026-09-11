import ts from "typescript";

type Component = (ts.FunctionDeclaration | ts.ArrowFunction) & { body: ts.Block };
type Range = { line: number; endLine: number };
export type LayoutHit = Range & { content: string; ranges: Range[] };
type Hooks = Map<string, string>;

function walk(node: ts.Node, visit: (node: ts.Node) => void): void {
  visit(node);
  ts.forEachChild(node, child => walk(child, visit));
}
function walkRender(node: ts.Node, visit: (node: ts.Node) => void): void {
  if (ts.isFunctionLike(node)) return;
  visit(node);
  ts.forEachChild(node, child => walkRender(child, visit));
}
function range(file: ts.SourceFile, node: ts.Node): Range {
  return { line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1, endLine: file.getLineAndCharacterOfPosition(node.end).line + 1 };
}
function reactHooks(file: ts.SourceFile): Hooks {
  const hooks: Hooks = new Map();
  for (const stmt of file.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || stmt.moduleSpecifier.text !== "react") continue;
    const bindings = stmt.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const item of bindings.elements) hooks.set(item.name.text, item.propertyName?.text ?? item.name.text);
  }
  return hooks;
}
function hookCall(node: ts.Node | undefined, name: string, hooks: Hooks): node is ts.CallExpression {
  return !!node && ts.isCallExpression(node) && ts.isIdentifier(node.expression) && hooks.get(node.expression.text) === name;
}
function componentNode(node: ts.Node): node is Component {
  return (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node)) && !!node.body && ts.isBlock(node.body);
}
function bindingName(node: ts.ArrayBindingElement | undefined): string | undefined {
  return node && ts.isBindingElement(node) && ts.isIdentifier(node.name) ? node.name.text : undefined;
}
function componentBindings(body: ts.Block, hooks: Hooks) {
  const refs = new Set<string>();
  const setters = new Map<string, string>();
  for (const statement of body.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const d of statement.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && hookCall(d.initializer, "useRef", hooks)) refs.add(d.name.text);
      if (!ts.isArrayBindingPattern(d.name) || !hookCall(d.initializer, "useState", hooks)) continue;
      const state = bindingName(d.name.elements[0]);
      const setter = bindingName(d.name.elements[1]);
      if (setter && state) setters.set(setter, state);
    }
  }
  return { refs, setters };
}
function propNames(component: Component): Set<string> {
  return new Set(component.parameters.flatMap(p => {
    if (ts.isIdentifier(p.name)) return [p.name.text];
    if (!ts.isObjectBindingPattern(p.name)) return [];
    return p.name.elements.flatMap(e => ts.isIdentifier(e.name) ? [e.name.text] : []);
  }));
}
function renderedIdentifiers(body: ts.Block): Set<string> {
  const names = new Set<string>();
  walkRender(body, node => {
    if (!ts.isJsxExpression(node) || !node.expression) return;
    walkRender(node.expression, child => { if (ts.isIdentifier(child)) names.add(child.text); });
  });
  return names;
}
function attributeExpression(attrs: ts.JsxAttributes, name: string): ts.Expression | undefined {
  for (const attr of attrs.properties) {
    if (!ts.isJsxAttribute(attr) || attr.name.getText() !== name) continue;
    return attr.initializer && ts.isJsxExpression(attr.initializer) ? attr.initializer.expression : undefined;
  }
  return undefined;
}
function reactiveElements(component: Component, refs: Set<string>): Map<string, ts.Node[]> {
  const result = new Map<string, ts.Node[]>();
  const props = propNames(component);
  walkRender(component.body, node => {
    if (!ts.isJsxOpeningElement(node) && !ts.isJsxSelfClosingElement(node)) return;
    if (!ts.isIdentifier(node.tagName) || !/^[a-z]/.test(node.tagName.text)) return;
    // Keyed element and observer lifecycles need broader reasoning.
    if (node.attributes.properties.some(a => ts.isJsxAttribute(a) && a.name.getText() === "key")) return;
    const ref = attributeExpression(node.attributes, "ref");
    const html = attributeExpression(node.attributes, "dangerouslySetInnerHTML");
    if (!ref || !ts.isIdentifier(ref) || !refs.has(ref.text) || !html || !ts.isObjectLiteralExpression(html)) return;
    const value = html.properties.find(p => ts.isPropertyAssignment(p) && p.name.getText() === "__html");
    if (!value || !ts.isPropertyAssignment(value)) return;
    let reactive = false;
    walk(value.initializer, n => { if (ts.isIdentifier(n) && props.has(n.text)) reactive = true; });
    if (reactive) result.set(ref.text, [...(result.get(ref.text) ?? []), node]);
  });
  return result;
}
function measuredRef(node: ts.Node): string | undefined {
  if (!ts.isPropertyAccessExpression(node) || !["scrollHeight", "clientHeight", "scrollWidth", "clientWidth"].includes(node.name.text)) return;
  const current = node.expression;
  if (ts.isPropertyAccessExpression(current) && current.name.text === "current" && ts.isIdentifier(current.expression)) return current.expression.text;
}
function measurementRefs(callback: ts.Node, setters: Map<string, string>, rendered: Set<string>): Set<string> {
  const result = new Set<string>();
  walk(callback, node => {
    if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression)) return;
    const state = setters.get(node.expression.text);
    if (!state || !rendered.has(state)) return;
    walk(node, read => { const ref = measuredRef(read); if (ref) result.add(ref); });
  });
  return result;
}
function mountCallback(call: ts.CallExpression): ts.ConciseBody | undefined {
  const [callback, deps] = call.arguments;
  if (!callback || !(ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) return;
  if (!deps || !ts.isArrayLiteralExpression(deps) || deps.elements.length !== 0) return;
  return callback.body;
}
function componentHits(file: ts.SourceFile, component: Component, hooks: Hooks): LayoutHit[] {
  const body = component.body;
  if (component.parameters.some(p => hooks.has(p.name.getText(file)))) return [];
  if (/\b(?:ResizeObserver|MutationObserver|requestAnimationFrame|setInterval)\b/.test(body.getText(file))) return [];
  const { refs, setters } = componentBindings(body, hooks);
  const elements = reactiveElements(component, refs);
  const rendered = renderedIdentifiers(body);
  const hits: LayoutHit[] = [];
  for (const statement of body.statements) {
    if (!ts.isExpressionStatement(statement)) continue;
    const call = statement.expression;
    if (!hookCall(call, "useEffect", hooks) && !hookCall(call, "useLayoutEffect", hooks)) continue;
    const callback = mountCallback(call);
    if (!callback) continue;
    const targets = [...measurementRefs(callback, setters, rendered)].flatMap(ref => elements.get(ref) ?? []);
    if (targets.length === 0) continue;
    const effectRange = range(file, call);
    hits.push({ ...effectRange, content: call.getText(file), ranges: [effectRange, ...targets.map(node => range(file, node))] });
  }
  return hits;
}

// Bounded source analysis only; no target code is executed.
export function staleLayoutEffects(path: string, source: string): LayoutHit[] {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const hooks = reactHooks(file);
  const result: LayoutHit[] = [];
  walk(file, node => { if (componentNode(node)) result.push(...componentHits(file, node, hooks)); });
  return result;
}

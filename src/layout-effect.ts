import ts from "typescript";

// Deliberately bounded: a component-local ref, HTML prop, state setter and
// mount-only measurement must all refer to the same component. No target code runs.
export function staleLayoutEffects(path: string, source: string): { line: number; endLine: number; content: string }[] {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const hooks = new Map<string, string>();
  for (const stmt of file.statements) if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier) && stmt.moduleSpecifier.text === "react") {
    const bindings = stmt.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) for (const item of bindings.elements) hooks.set(item.name.text, item.propertyName?.text ?? item.name.text);
  }
  const result: { line: number; endLine: number; content: string }[] = [];
  const walk = (node: ts.Node, visit: (node: ts.Node) => void): void => { visit(node); ts.forEachChild(node, child => walk(child, visit)); };
  const hook = (node: ts.Node | undefined, name: string): node is ts.CallExpression => !!node && ts.isCallExpression(node) && ts.isIdentifier(node.expression) && hooks.get(node.expression.text) === name;
  walk(file, component => {
    if (!(ts.isFunctionDeclaration(component) || ts.isArrowFunction(component)) || !component.body || !ts.isBlock(component.body)) return;
    const body = component.body;
    if (component.parameters.some(p => hooks.has(p.name.getText(file)))) return;
    const walkRender = (node: ts.Node, visit: (node: ts.Node) => void): void => {
      if (ts.isFunctionLike(node)) return;
      visit(node); ts.forEachChild(node, child => walkRender(child, visit));
    };
    // Observer/timer-driven or ref reassignment lifecycles need broader reasoning.
    if (/\b(?:ResizeObserver|MutationObserver|requestAnimationFrame|setInterval)\b/.test(body.getText(file))) return;
    const refs = new Set<string>();
    const setters = new Map<string, string>();
    for (const statement of body.statements) if (ts.isVariableStatement(statement)) for (const d of statement.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && hook(d.initializer, "useRef")) refs.add(d.name.text);
      if (ts.isArrayBindingPattern(d.name) && hook(d.initializer, "useState")) {
        const setter = d.name.elements[1];
        const state = d.name.elements[0];
        if (setter && ts.isBindingElement(setter) && ts.isIdentifier(setter.name) && state && ts.isBindingElement(state) && ts.isIdentifier(state.name)) setters.set(setter.name.text, state.name.text);
      }
    }
    // A layout snapshot used only for initial telemetry is not stale UI state.
    const renderedState = new Set<string>();
    walkRender(body, node => {
      if (!ts.isJsxExpression(node) || !node.expression) return;
      walkRender(node.expression, child => { if (ts.isIdentifier(child)) renderedState.add(child.text); });
    });
    const dynamicRefs = new Set<string>();
    walkRender(body, node => {
      if (!ts.isJsxOpeningElement(node) && !ts.isJsxSelfClosingElement(node)) return;
      if (!ts.isIdentifier(node.tagName) || !/^[a-z]/.test(node.tagName.text)) return;
      const attrs = node.attributes.properties;
      const ref = attrs.find(a => ts.isJsxAttribute(a) && a.name.getText(file) === "ref");
      const html = attrs.find(a => ts.isJsxAttribute(a) && a.name.getText(file) === "dangerouslySetInnerHTML");
      if (!ref || !html || !ts.isJsxAttribute(ref) || !ts.isJsxAttribute(html) || !ref.initializer || !html.initializer ||
          !ts.isJsxExpression(ref.initializer) || !ref.initializer.expression || !ts.isIdentifier(ref.initializer.expression) ||
          !refs.has(ref.initializer.expression.text) || !ts.isJsxExpression(html.initializer) || !html.initializer.expression || !ts.isObjectLiteralExpression(html.initializer.expression)) return;
      const value = html.initializer.expression.properties.find(p => ts.isPropertyAssignment(p) && p.name.getText(file) === "__html");
      if (!value || !ts.isPropertyAssignment(value)) return;
      // Props are reactive; local constants and arbitrary helper results are not proof.
      const propNames = new Set(component.parameters.flatMap(p => ts.isIdentifier(p.name) ? [p.name.text] : ts.isObjectBindingPattern(p.name) ? p.name.elements.filter(e => ts.isIdentifier(e.name)).map(e => e.name.getText(file)) : []));
      let reactive = false;
      walk(value.initializer, n => { if (ts.isIdentifier(n) && propNames.has(n.text)) reactive = true; });
      if (!reactive) return;
      // A key on the measured element can remount it; avoid this ambiguous case.
      if (attrs.some(a => ts.isJsxAttribute(a) && a.name.getText(file) === "key")) return;
      dynamicRefs.add(ref.initializer.expression.text);
    });
    for (const stmt of body.statements) {
      if (!ts.isExpressionStatement(stmt) || !(hook(stmt.expression, "useEffect") || hook(stmt.expression, "useLayoutEffect"))) continue;
      const call = stmt.expression;
      const [callback, deps] = call.arguments;
      if (!callback || !(ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) || !deps || !ts.isArrayLiteralExpression(deps) || deps.elements.length !== 0) continue;
      let measured = false;
      walk(callback.body, node => {
        if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || !setters.has(node.expression.text) || !renderedState.has(setters.get(node.expression.text)!)) return;
        walk(node, read => {
          if (!ts.isPropertyAccessExpression(read) || !["scrollHeight", "clientHeight", "scrollWidth", "clientWidth"].includes(read.name.text)) return;
          const current = read.expression;
          if (ts.isPropertyAccessExpression(current) && current.name.text === "current" && ts.isIdentifier(current.expression) && dynamicRefs.has(current.expression.text)) measured = true;
        });
      });
      if (measured) result.push({ line: file.getLineAndCharacterOfPosition(call.getStart(file)).line + 1, endLine: file.getLineAndCharacterOfPosition(call.end).line + 1, content: call.getText(file) });
    }
  });
  return result;
}

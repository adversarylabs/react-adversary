import assert from "node:assert/strict";
import test from "node:test";
import { staleLayoutEffects } from "../src/layout-effect.js";
const fixture = (deps = "[]", extra = "", html = "markup", ref = "box") => `
import { useEffect, useRef, useState } from "react";
function Preview({markup}: {markup: string}) {
 const box = useRef(null);
 const [clipped, setClipped] = useState(false);
 useEffect(() => {
   const measure = () => { if (box.current) setClipped(box.current.scrollHeight > box.current.clientHeight); };
   measure(); window.addEventListener('resize', measure);
   return () => window.removeEventListener('resize', measure);
 }, ${deps});
 ${extra}
 return <section><div ref={${ref}} dangerouslySetInnerHTML={{__html: ${html}}} />{clipped && <button>Expand</button>}</section>;
}`;
test("connects prop-derived HTML with its mount-only layout state", () => {
 const hits = staleLayoutEffects("Preview.tsx", fixture());
 assert.equal(hits.length, 1); assert.equal(hits[0].line, 6);
});
test("accepts reactive, observed, static and unrelated-ref layouts", () => {
 for (const text of [fixture("[markup]"), fixture("[]", "new MutationObserver(update).observe(box.current, {childList:true});"), fixture("[]", "", "'static'"), fixture("[]", "", "markup", "other"), fixture().replace('from "react"', 'from "custom-hooks"'), fixture().replace('{clipped && <button>Expand</button>}', '')])
   assert.deepEqual(staleLayoutEffects("Preview.tsx", text), []);
});

test("returns both changed effect and measured JSX evidence ranges", () => {
 const text = fixture(); const hit = staleLayoutEffects("Preview.tsx", text)[0]!;
 const jsxLine = text.split("\n").findIndex(line => line.includes("dangerouslySetInnerHTML")) + 1;
 assert.ok(hit.ranges.some(range => jsxLine >= range.line && jsxLine <= range.endLine));
 assert.ok(hit.ranges.some(range => hit.line >= range.line && hit.line <= range.endLine));
});

test("skips shadowed props, non-reference property names and timeout lifecycles", () => {
 const nested = fixture().replace("return <section>", "{ const markup = 'fixed'; return <section>").replace("</section>;", "</section>; }");
 assert.deepEqual(staleLayoutEffects("Preview.tsx", nested), []);
 assert.deepEqual(staleLayoutEffects("Preview.tsx", fixture("[]", "const data = {markup:'fixed'};", "data.markup")), []);
 assert.deepEqual(staleLayoutEffects("Preview.tsx", fixture("[]", "setTimeout(measure, 100);")), []);
});

test("skips shadowed imported hooks and measurement bindings", () => {
 assert.deepEqual(staleLayoutEffects("Preview.tsx", fixture().replace(" const box", " function useEffect(callback: () => void) {}\n const box")), []);
 assert.deepEqual(staleLayoutEffects("Preview.tsx", fixture().replace("const measure = () =>", "const measure = (box: any) =>")), []);
});

test("ignores unused measurement helpers but follows direct helper calls", () => {
 const unused = fixture().replace("measure(); window.addEventListener('resize', measure);", "");
 assert.deepEqual(staleLayoutEffects("Preview.tsx", unused), []);
 assert.equal(staleLayoutEffects("Preview.tsx", fixture()).length, 1);
 const recursive = fixture().replace("measure(); window", "const run = () => { measure(); run(); }; run(); window");
 assert.equal(staleLayoutEffects("Preview.tsx", recursive).length, 1);
});

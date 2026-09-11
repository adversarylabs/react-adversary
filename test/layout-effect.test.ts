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

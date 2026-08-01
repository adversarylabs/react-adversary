# Checks — what react detects

This file is the **public audit list** of detectors for the **web/react** adversary. High-confidence React security defects with file:line evidence in JSX/TSX. This adversary does **not** duplicate eslint-plugin-react/react-hooks defaults (keys, deps arrays, hook rules) — teams already run those; we only ship what a staff security review adds on top.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `*.jsx`, `*.tsx`, and `*.js`/`*.ts` files importing React. Framework-specific config (Next.js) is owned by `web/nextjs`.

**Precision stance:** XSS sinks fire on non-literal input only. Claims must match current browser/React behavior — no findings based on threats browsers have since mitigated (see `reverse-tabnabbing`, kept at low with honest framing).

Public grounding: React docs on `dangerouslySetInnerHTML`, DOMPurify, React 16.9+ `javascript:` URL deprecation, and browser-default `noopener` behavior (Chrome 88+, Firefox 79+, Safari 12.1+).

---

## High

### `react.unsafe-html`

| | |
| --- | --- |
| **What** | HTML injected into the DOM from non-literal input |
| **Why** | `dangerouslySetInnerHTML` (and raw `ref.innerHTML =` writes) with anything user-influenced is direct XSS |
| **Looks for** | `dangerouslySetInnerHTML={{ __html: X }}` and `.innerHTML = X` / `insertAdjacentHTML(..., X)` where X is a variable/prop/fetch result, not a constant literal |
| **Stays quiet when** | Constant literal HTML; input passed through a maintained sanitizer (DOMPurify/sanitize-html) immediately at the sink; trusted-types enforced |
| **Public examples** | React docs name the prop "dangerously" for this reason; DOMPurify README; endless CMS-content XSS reports |
| **Remediation** | Render text normally; when HTML is required, sanitize with a maintained allowlist sanitizer at the sink |

### `react.dynamic-eval`

| | |
| --- | --- |
| **What** | Dynamic code evaluation from non-literal input in client code |
| **Why** | `eval`/`new Function`/string-form `setTimeout` on dynamic data is XSS with extra steps; also breaks CSP |
| **Looks for** | `eval(X)`, `new Function(X)`, `setTimeout/setInterval("...", …)` string form, where X is non-literal |
| **Stays quiet when** | Constant literals (still discouraged — note, don't fire high); build-time codegen files |
| **Public examples** | OWASP DOM-XSS sinks; CSP `unsafe-eval` guidance |
| **Remediation** | Replace dynamic evaluation with explicit parsing (`JSON.parse`, lookup tables) |

### `react.client-env-secret`

| | |
| --- | --- |
| **What** | Secret-shaped values referenced through client-exposed env vars |
| **Why** | `REACT_APP_*` / `VITE_*` / `PUBLIC_*` vars are compiled into the public bundle — a "secret" there is published to every visitor. One of the most common real-world React security mistakes |
| **Looks for** | `process.env.REACT_APP_X` / `import.meta.env.VITE_X` where X matches `SECRET|TOKEN|PRIVATE|API_KEY|PASSWORD`, especially flowing into `Authorization` headers or SDK constructors for privileged APIs |
| **Stays quiet when** | Publishable-by-design keys (Stripe `pk_`, Maps browser keys, Sentry DSNs, Firebase client config); names matching but values referencing public identifiers |
| **Public examples** | CRA/Vite docs both warn env vars are embedded in the build; leaked-key writeups from deployed bundles |
| **Remediation** | Move the call server-side (BFF/API route); browser code gets only publishable keys |

---

## Medium

### `react.href-user-input`

| | |
| --- | --- |
| **What** | User-influenced values in `href` / `src` navigation attributes without protocol validation |
| **Why** | `javascript:` URLs execute on click. React ≥ 16.9 logs a warning for `javascript:` URLs but still renders them — the warning is not a sanitizer |
| **Looks for** | `href={X}` / `<Link to={X}>` / `window.location = X` where X derives from user input/query params with no protocol allowlist |
| **Stays quiet when** | Values validated against `http(s):`/relative-path allowlists; URL objects constructed with fixed origins; constant literals |
| **Public examples** | React 16.9 deprecation notice for `javascript:` URLs; DOM-XSS via location sinks |
| **Remediation** | Allowlist protocols (`http:`, `https:`, relative) before rendering user-supplied URLs |

### `react.token-in-localstorage`

| | |
| --- | --- |
| **What** | Auth tokens/session credentials stored in `localStorage`/`sessionStorage` |
| **Why** | Any XSS anywhere in the app (or a compromised dependency — see 2025 npm worm wave) can exfiltrate storage; HttpOnly cookies are inaccessible to script. LLM-gated because the httpOnly-cookie alternative isn't available to every architecture — this is a "know the trade-off" finding, not a hard fail |
| **Looks for** | `localStorage.setItem` with keys/values matching token/JWT patterns (`token`, `jwt`, `access_token`, `eyJ` prefixes) |
| **Stays quiet when** | Non-sensitive preferences/cache; short-lived tokens with documented refresh design where the team explicitly accepted the trade-off |
| **Public examples** | OWASP JWT storage cheat sheet; token-theft chains in XSS incident reports |
| **Remediation** | Prefer HttpOnly SameSite cookies for session credentials; if storage is unavoidable, keep tokens short-lived and scoped |

---

## Low

### `react.reverse-tabnabbing`

| | |
| --- | --- |
| **What** | `target="_blank"` links without `rel="noopener noreferrer"` |
| **Why** | Honest framing: all evergreen browsers (Chrome 88+, Firefox 79+, Safari 12.1+) now imply `noopener` for `target="_blank"`, so classic tabnabbing is mitigated by default. Residual value is legacy/embedded browsers and `noreferrer` (referrer-leakage control). Do not claim this is an active XSS-class risk |
| **Looks for** | `target="_blank"` on anchors with user-influenced or external `href` and no `rel` |
| **Stays quiet when** | `rel` present; internal fixed links; `window.open` with explicit `noopener` |
| **Public examples** | Browser release notes shipping implicit noopener; original tabnabbing research (historical) |
| **Remediation** | Add `rel="noopener noreferrer"` — cheap, harmless, closes the legacy gap |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| Next.js config/middleware/Server Actions | `nextjs` |
| Hooks rules, key props, deps arrays, a11y | eslint-plugin-react / react-hooks / jsx-a11y — deliberately not duplicated |
| package.json / lockfile supply chain | `npm` / `yarn` |
| Committed secret values | `security/secrets` |
| Generic TS type-safety | `typescript` |

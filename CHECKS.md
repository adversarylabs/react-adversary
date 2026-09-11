# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `react.stale-layout-measurement` | Medium | Mount-only layout state for prop-derived HTML; changes to either the effect or measured JSX qualify |
| `react.client-env-secret` | High | Secret-shaped values referenced through client-exposed env vars |
| `react.dynamic-eval` | High | Dynamic code evaluation from non-literal input in client code |
| `react.href-user-input` | Medium | User-influenced values in `href` / `src` navigation attributes without protocol validation |
| `react.raw-href-handler-guard` | High | A dynamic anchor href remains raw while its click handler treats URL validation as the security boundary |
| `react.reverse-tabnabbing` | Low | `target="_blank"` links without `rel="noopener noreferrer"` |
| `react.token-in-localstorage` | Medium | Auth tokens/session credentials stored in `localStorage`/`sessionStorage` |
| `react.unsafe-html` | High | HTML injected into the DOM from non-literal input |

## Reactive layout measurements

Report a component-local mount-only effect that sets state from a ref measurement while the same element renders prop-derived HTML. Require imported React hooks and matching ref/state ownership. Skip observed/timer-driven layouts and keyed elements; do not demand dependencies on arbitrary effects.

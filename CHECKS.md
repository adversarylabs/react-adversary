# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `react.client-env-secret` | High | Secret-shaped values referenced through client-exposed env vars |
| `react.dynamic-eval` | High | Dynamic code evaluation from non-literal input in client code |
| `react.href-user-input` | Medium | User-influenced values in `href` / `src` navigation attributes without protocol validation |
| `react.raw-href-handler-guard` | High | A dynamic anchor href remains raw while its click handler treats URL validation as the security boundary |
| `react.reverse-tabnabbing` | Low | `target="_blank"` links without `rel="noopener noreferrer"` |
| `react.token-in-localstorage` | Medium | Auth tokens/session credentials stored in `localStorage`/`sessionStorage` |
| `react.unsafe-html` | High | HTML injected into the DOM from non-literal input |

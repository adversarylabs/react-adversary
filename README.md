# React adversary

Reviews React source for raw HTML injection, opener attacks, and dynamic code execution.

## Checks

- **React renders raw HTML:** Render text normally or sanitize with a maintained allowlist sanitizer.
- **Blank-target link lacks opener isolation:** Add rel="noopener noreferrer".
- **React client executes dynamic JavaScript:** Replace dynamic evaluation with explicit parsing.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the react adversary when changes include `**/*.jsx` or `**/*.tsx`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.

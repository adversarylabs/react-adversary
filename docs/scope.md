# web/react — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `react`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** React

## Mission

Review React for raw HTML injection, opener attacks, and dynamic code execution.

## In scope (fair miss if humans raised it and we did not)

- dangerouslySetInnerHTML / XSS vectors
- window.opener attacks
- Dynamic code execution in React code

## Out of scope (not a miss for this adversary)

- Generic TS without React
- Backend Go

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading

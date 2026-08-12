import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
interface RawHrefHandlerGuardMatch { kind: "raw-href-handler-guard"; files: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch | RawHrefHandlerGuardMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

const SOURCE_FILES = ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"] as const;
const JSX_FILES = ["**/*.jsx", "**/*.tsx"] as const;

export const spec = {
  "id": "react",
  "displayName": "React",
  "description": "Reviews React source for raw HTML injection, opener attacks, and dynamic code execution.",
  "files": [...SOURCE_FILES],
  "rules": [
    {
      "id": "react.unsafe-html",
      "title": "React renders raw HTML",
      "summary": "React renders raw HTML",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "dangerouslySetInnerHTML and innerHTML writes with non-literal input are direct XSS sinks.",
      "impact": "Attacker-controlled markup executes in the user session.",
      "recommendation": "Render text normally; when HTML is required, sanitize with a maintained allowlist sanitizer at the sink.",
      "complexity": "small",
      "tags": ["security", "unsafe-html", "xss"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "(?:dangerouslySetInnerHTML\\s*=\\s*\\{\\{|\\.innerHTML\\s*=|insertAdjacentHTML\\s*\\()",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "react.dynamic-eval",
      "title": "React client executes dynamic JavaScript",
      "summary": "React client executes dynamic JavaScript",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "eval/new Function/string-form timers on dynamic data is XSS with extra steps and breaks CSP.",
      "impact": "Remote code execution in the browser when any user-influenced string reaches the sink.",
      "recommendation": "Replace dynamic evaluation with explicit parsing (JSON.parse, lookup tables).",
      "complexity": "small",
      "tags": ["security", "dynamic-eval"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "\\b(?:eval|new\\s+Function)\\s*\\(|(?:setTimeout|setInterval)\\s*\\(\\s*[\"'`]",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "react.client-env-secret",
      "title": "Secret-shaped value referenced via client-exposed env",
      "summary": "Secret-shaped value referenced via client-exposed env",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "REACT_APP_*/VITE_*/PUBLIC_* vars are compiled into the public bundle.",
      "impact": "API secrets and private tokens are published to every visitor.",
      "recommendation": "Move privileged calls server-side; browser code gets only publishable keys.",
      "complexity": "small",
      "tags": ["secrets", "client-env"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "(?:process\\.env\\.(?:REACT_APP|NEXT_PUBLIC|PUBLIC)_(?:[A-Z0-9_]*?(?:SECRET|TOKEN|PRIVATE|PASSWORD|API_KEY|SERVICE_ROLE)[A-Z0-9_]*)|import\\.meta\\.env\\.VITE_(?:[A-Z0-9_]*?(?:SECRET|TOKEN|PRIVATE|PASSWORD|API_KEY)[A-Z0-9_]*))",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "react.raw-href-handler-guard",
      "title": "Link URL is guarded only in its click handler",
      "summary": "Link URL is guarded only in its click handler",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "An anchor href is an active browser sink that native navigation paths can use independently of the click handler's intended validation flow.",
      "impact": "A dangerous URL can remain available to middle-click, keyboard activation, context-menu navigation, or link copying.",
      "recommendation": "Neutralize dangerous values in the rendered href itself; preserve safe URL bytes when no rewrite is needed.",
      "complexity": "small",
      "tags": ["security", "href", "defense-in-depth"],
      "match": {
        "kind": "raw-href-handler-guard",
        "files": [...JSX_FILES]
      }
    },
    {
      "id": "react.href-user-input",
      "title": "User-influenced value used in navigation attribute",
      "summary": "User-influenced value used in navigation attribute",
      "category": "security",
      "severity": "medium",
      "confidence": "medium",
      "whyItMatters": "javascript: URLs and open redirects via user-controlled href/src remain DOM-XSS sinks.",
      "impact": "Click-driven script execution or phishing redirects from rendered links.",
      "recommendation": "Allowlist protocols (http:, https:, relative) before rendering user-supplied URLs.",
      "complexity": "small",
      "tags": ["security", "href", "xss"],
      "match": {
        "kind": "content",
        "files": [...JSX_FILES],
        "pattern": {
          "pattern": "(?:href|to|src)=\\{(?:props\\.|[\\w.]*?(?:query|searchParams|params|userInput|userUrl|urlFromUser)[\\w.]*|location\\.search)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "react.token-in-localstorage",
      "title": "Auth token stored in web storage",
      "summary": "Auth token stored in web storage",
      "category": "security",
      "severity": "medium",
      "confidence": "medium",
      "whyItMatters": "Any XSS or compromised dependency can exfiltrate localStorage/sessionStorage tokens.",
      "impact": "Session theft without needing HttpOnly cookie access.",
      "recommendation": "Prefer HttpOnly SameSite cookies for session credentials; keep tokens short-lived if storage is unavoidable.",
      "complexity": "medium",
      "tags": ["security", "storage", "token"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "(?:localStorage|sessionStorage)\\.setItem\\s*\\(\\s*[\"'][^\"']*(?:token|jwt|access_token|refresh_token|id_token|auth)[^\"']*[\"']",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "react.reverse-tabnabbing",
      "title": "Blank-target link lacks opener isolation",
      "summary": "Blank-target link lacks opener isolation",
      "category": "security",
      "severity": "low",
      "confidence": "high",
      "whyItMatters": "Modern browsers imply noopener for target=_blank; residual value is legacy browsers and referrer control.",
      "impact": "Low residual risk of opener abuse on older or embedded browsers.",
      "recommendation": "Add rel=\"noopener noreferrer\".",
      "complexity": "trivial",
      "tags": ["security", "reverse-tabnabbing"],
      "match": {
        "kind": "content",
        "files": [...JSX_FILES],
        "pattern": {
          "pattern": "target=[\"']_blank[\"'](?![^>]*rel=[\"'][^\"']*(?:noopener|noreferrer))",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;

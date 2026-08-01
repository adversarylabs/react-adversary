import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "react";
    readonly displayName: "React";
    readonly description: "Reviews React source for raw HTML injection, opener attacks, and dynamic code execution.";
    readonly files: ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"];
    readonly rules: [{
        readonly id: "react.unsafe-html";
        readonly title: "React renders raw HTML";
        readonly summary: "React renders raw HTML";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "dangerouslySetInnerHTML and innerHTML writes with non-literal input are direct XSS sinks.";
        readonly impact: "Attacker-controlled markup executes in the user session.";
        readonly recommendation: "Render text normally; when HTML is required, sanitize with a maintained allowlist sanitizer at the sink.";
        readonly complexity: "small";
        readonly tags: ["security", "unsafe-html", "xss"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "(?:dangerouslySetInnerHTML\\s*=\\s*\\{\\{|\\.innerHTML\\s*=|insertAdjacentHTML\\s*\\()";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "react.dynamic-eval";
        readonly title: "React client executes dynamic JavaScript";
        readonly summary: "React client executes dynamic JavaScript";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "eval/new Function/string-form timers on dynamic data is XSS with extra steps and breaks CSP.";
        readonly impact: "Remote code execution in the browser when any user-influenced string reaches the sink.";
        readonly recommendation: "Replace dynamic evaluation with explicit parsing (JSON.parse, lookup tables).";
        readonly complexity: "small";
        readonly tags: ["security", "dynamic-eval"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "\\b(?:eval|new\\s+Function)\\s*\\(|(?:setTimeout|setInterval)\\s*\\(\\s*[\"'`]";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "react.client-env-secret";
        readonly title: "Secret-shaped value referenced via client-exposed env";
        readonly summary: "Secret-shaped value referenced via client-exposed env";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "REACT_APP_*/VITE_*/PUBLIC_* vars are compiled into the public bundle.";
        readonly impact: "API secrets and private tokens are published to every visitor.";
        readonly recommendation: "Move privileged calls server-side; browser code gets only publishable keys.";
        readonly complexity: "small";
        readonly tags: ["secrets", "client-env"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "(?:process\\.env\\.(?:REACT_APP|NEXT_PUBLIC|PUBLIC)_(?:[A-Z0-9_]*?(?:SECRET|TOKEN|PRIVATE|PASSWORD|API_KEY|SERVICE_ROLE)[A-Z0-9_]*)|import\\.meta\\.env\\.VITE_(?:[A-Z0-9_]*?(?:SECRET|TOKEN|PRIVATE|PASSWORD|API_KEY)[A-Z0-9_]*))";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "react.href-user-input";
        readonly title: "User-influenced value used in navigation attribute";
        readonly summary: "User-influenced value used in navigation attribute";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "medium";
        readonly whyItMatters: "javascript: URLs and open redirects via user-controlled href/src remain DOM-XSS sinks.";
        readonly impact: "Click-driven script execution or phishing redirects from rendered links.";
        readonly recommendation: "Allowlist protocols (http:, https:, relative) before rendering user-supplied URLs.";
        readonly complexity: "small";
        readonly tags: ["security", "href", "xss"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx"];
            readonly pattern: {
                readonly pattern: "(?:href|to|src)=\\{(?:props\\.|[\\w.]*?(?:query|searchParams|params|userInput|userUrl|urlFromUser)[\\w.]*|location\\.search)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "react.token-in-localstorage";
        readonly title: "Auth token stored in web storage";
        readonly summary: "Auth token stored in web storage";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "medium";
        readonly whyItMatters: "Any XSS or compromised dependency can exfiltrate localStorage/sessionStorage tokens.";
        readonly impact: "Session theft without needing HttpOnly cookie access.";
        readonly recommendation: "Prefer HttpOnly SameSite cookies for session credentials; keep tokens short-lived if storage is unavoidable.";
        readonly complexity: "medium";
        readonly tags: ["security", "storage", "token"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "(?:localStorage|sessionStorage)\\.setItem\\s*\\(\\s*[\"'][^\"']*(?:token|jwt|access_token|refresh_token|id_token|auth)[^\"']*[\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "react.reverse-tabnabbing";
        readonly title: "Blank-target link lacks opener isolation";
        readonly summary: "Blank-target link lacks opener isolation";
        readonly category: "security";
        readonly severity: "low";
        readonly confidence: "high";
        readonly whyItMatters: "Modern browsers imply noopener for target=_blank; residual value is legacy browsers and referrer control.";
        readonly impact: "Low residual risk of opener abuse on older or embedded browsers.";
        readonly recommendation: "Add rel=\"noopener noreferrer\".";
        readonly complexity: "trivial";
        readonly tags: ["security", "reverse-tabnabbing"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx"];
            readonly pattern: {
                readonly pattern: "target=[\"']_blank[\"'](?![^>]*rel=[\"'][^\"']*(?:noopener|noreferrer))";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};

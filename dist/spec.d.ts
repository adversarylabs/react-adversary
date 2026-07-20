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
        readonly whyItMatters: "React renders raw HTML weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Render text normally or sanitize with a maintained allowlist sanitizer.";
        readonly complexity: "small";
        readonly tags: ["security", "unsafe-html"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "dangerouslySetInnerHTML\\s*=\\s*\\{\\{";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "react.reverse-tabnabbing";
        readonly title: "Blank-target link lacks opener isolation";
        readonly summary: "Blank-target link lacks opener isolation";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Blank-target link lacks opener isolation weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Add rel=\"noopener noreferrer\".";
        readonly complexity: "small";
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
    }, {
        readonly id: "react.dynamic-eval";
        readonly title: "React client executes dynamic JavaScript";
        readonly summary: "React client executes dynamic JavaScript";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "React client executes dynamic JavaScript weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Replace dynamic evaluation with explicit parsing.";
        readonly complexity: "small";
        readonly tags: ["security", "dynamic-eval"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "\\b(?:eval|new\\s+Function)\\s*\\(";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};

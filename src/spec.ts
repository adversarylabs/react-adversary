import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "react",
  "displayName": "React",
  "description": "Reviews React source for raw HTML injection, opener attacks, and dynamic code execution.",
  "files": [
    "**/*.jsx",
    "**/*.tsx",
    "**/*.js",
    "**/*.ts"
  ],
  "rules": [
    {
      "id": "react.unsafe-html",
      "title": "React renders raw HTML",
      "summary": "React renders raw HTML",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "React renders raw HTML weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Render text normally or sanitize with a maintained allowlist sanitizer.",
      "complexity": "small",
      "tags": [
        "security",
        "unsafe-html"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.jsx",
          "**/*.tsx",
          "**/*.js",
          "**/*.ts"
        ],
        "pattern": {
          "pattern": "dangerouslySetInnerHTML\\s*=\\s*\\{\\{",
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
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "Blank-target link lacks opener isolation weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Add rel=\"noopener noreferrer\".",
      "complexity": "small",
      "tags": [
        "security",
        "reverse-tabnabbing"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.jsx",
          "**/*.tsx"
        ],
        "pattern": {
          "pattern": "target=[\"']_blank[\"'](?![^>]*rel=[\"'][^\"']*(?:noopener|noreferrer))",
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
      "whyItMatters": "React client executes dynamic JavaScript weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Replace dynamic evaluation with explicit parsing.",
      "complexity": "small",
      "tags": [
        "security",
        "dynamic-eval"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.jsx",
          "**/*.tsx",
          "**/*.js",
          "**/*.ts"
        ],
        "pattern": {
          "pattern": "\\b(?:eval|new\\s+Function)\\s*\\(",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated edit does not surface a legacy React finding", async () => {
  const repo = await committedRepository({
    "src/Panel.tsx": unsafeHtmlSource("old diagnostic", true),
  });
  await writeFile(join(repo, "src/Panel.tsx"), unsafeHtmlSource("new diagnostic", true));

  const output = await changedReview(repo, ["src/Panel.tsx"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "react.unsafe-html"),
    false,
  );
});

test("a direct finding on a changed line remains eligible", async () => {
  const repo = await committedRepository({
    "src/Panel.tsx": unsafeHtmlSource("unchanged", false),
  });
  await writeFile(join(repo, "src/Panel.tsx"), unsafeHtmlSource("unchanged", true));

  const output = await changedReview(repo, ["src/Panel.tsx"]);

  const finding = output.findings.find((item) => item.ruleId === "react.unsafe-html");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 3);
});

test("a changed occurrence is found after an unchanged legacy occurrence", async () => {
  const original = `export const first = (html: string) => <div dangerouslySetInnerHTML={{ __html: html }} />;
export const second = (html: string) => <div>{html}</div>;
`;
  const updated = original.replace("<div>{html}</div>", "<div dangerouslySetInnerHTML={{ __html: html }} />");
  const repo = await committedRepository({ "src/Panels.tsx": original });
  await writeFile(join(repo, "src/Panels.tsx"), updated);

  const output = await changedReview(repo, ["src/Panels.tsx"]);

  const finding = output.findings.find((item) => item.ruleId === "react.unsafe-html");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 2);
});

test("unchanged named-handler context supports a changed href anchor", async () => {
  const original = guardedLink("safeUrl(url)");
  const repo = await committedRepository({ "src/Link.tsx": original });
  await writeFile(join(repo, "src/Link.tsx"), guardedLink("url"));

  const output = await changedReview(repo, ["src/Link.tsx"]);

  const finding = output.findings.find(
    (item) => item.ruleId === "react.raw-href-handler-guard",
  );
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 10);
});

test("a changed handler guard uses unchanged href context as evidence", async () => {
  const original = guardedLink("url", "console.log(url)");
  const repo = await committedRepository({ "src/Link.tsx": original });
  await writeFile(join(repo, "src/Link.tsx"), guardedLink("url", "safeUrl(url)"));

  const output = await changedReview(repo, ["src/Link.tsx"]);

  const finding = output.findings.find(
    (item) => item.ruleId === "react.raw-href-handler-guard",
  );
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 6);
});

test("an unrelated edit does not reactivate a legacy AST finding", async () => {
  const original = guardedLink("url");
  const repo = await committedRepository({ "src/Link.tsx": original });
  await writeFile(join(repo, "src/Link.tsx"), original.replace("Open", "Open link"));

  const output = await changedReview(repo, ["src/Link.tsx"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "react.raw-href-handler-guard"),
    false,
  );
});

test("an added React file remains eligible in full", async () => {
  const repo = await committedRepository({ "src/App.tsx": "export const App = () => <main />;\n" });
  await writeRepositoryFile(repo, "src/Panel.tsx", unsafeHtmlSource("added", true));

  const output = await changedReview(repo, ["src/Panel.tsx"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "react.unsafe-html"),
    true,
  );
});

test("an all-files review remains eligible in full", async () => {
  const repo = await committedRepository({
    "src/Panel.tsx": unsafeHtmlSource("old diagnostic", true),
  });
  await writeFile(join(repo, "src/Panel.tsx"), unsafeHtmlSource("new diagnostic", true));

  const output = await createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "all",
        changed_files: ["src/Panel.tsx"],
      },
    },
  });

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "react.unsafe-html"),
    true,
  );
});

async function committedRepository(files: Record<string, string>): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "react-adversary-scope-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  for (const [path, source] of Object.entries(files)) await writeRepositoryFile(repo, path, source);
  await execute("git", ["add", "."], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

async function writeRepositoryFile(repo: string, path: string, source: string): Promise<void> {
  await mkdir(join(repo, dirname(path)), { recursive: true });
  await writeFile(join(repo, path), source);
}

async function changedReview(repoPath: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}

function unsafeHtmlSource(diagnostic: string, unsafe: boolean): string {
  const body = unsafe
    ? "<div dangerouslySetInnerHTML={{ __html: html }} />"
    : "<div>{html}</div>";
  return `export function Panel({ html }: { html: string }) {
  console.log(${JSON.stringify(diagnostic)});
  return ${body};
}
`;
}

function guardedLink(href: string, guard = "safeUrl(url)"): string {
  return `function safeUrl(value: string) {
  return value.startsWith("https://") ? value : "about:blank";
}

export function Link({ url }: { url: string }) {
  function open() { ${guard}; }
  return (
    <a
      onClick={open}
      href={${href}}
    >Open</a>
  );
}
`;
}

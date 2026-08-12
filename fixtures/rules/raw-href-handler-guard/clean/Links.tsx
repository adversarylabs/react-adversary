import { sanitizeUrl as cleanUrl } from "@braintree/sanitize-url";

export function SafeSink({ url }: { url: string }) {
  const safeUrl = cleanUrl(url);
  return <a href={safeUrl} onClick={() => window.open(safeUrl)}>Open</a>;
}

export function InlineSafeSink({ url }: { url: string }) {
  return <a href={cleanUrl(url)} onClick={() => cleanUrl(url)}>Open</a>;
}

export function PreservedSafeBytes({ url }: { url: string }) {
  const safeUrl = cleanUrl(url);
  const href = safeUrl === "about:blank" ? "about:blank" : url;
  return <a href={href} onClick={() => cleanUrl(url)}>Open</a>;
}

export function Analytics({ url }: { url: string }) {
  return <a href={url} onClick={() => console.log("clicked")}>Open</a>;
}

export function Literal() {
  return <a href="https://example.com" onClick={() => cleanUrl("https://example.com")}>Open</a>;
}

export function Button({ url }: { url: string }) {
  return <button onClick={() => window.open(cleanUrl(url))}>Open</button>;
}

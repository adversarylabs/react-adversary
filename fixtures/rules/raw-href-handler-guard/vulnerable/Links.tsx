import { sanitizeUrl as cleanUrl } from "@braintree/sanitize-url";

export function InlineLink({ url }: { url: string }) {
  return (
    <a
      href={url}
      onClick={(event) => {
        event.preventDefault();
        const safe = cleanUrl(url);
        if (safe !== "about:blank") window.open(safe);
      }}
    >
      Open
    </a>
  );
}

export function NamedLink({ button }: { button: { url: string } }) {
  function openButton(event: React.MouseEvent) {
    const safeUrl = cleanUrl(button.url);
    event.preventDefault();
    if (safeUrl === "about:blank") return;
    window.open(safeUrl);
  }
  return <a href={button.url} onClick={openButton}>Open button</a>;
}

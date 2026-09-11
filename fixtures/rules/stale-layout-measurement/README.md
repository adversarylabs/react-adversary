# Layout invalidation fixtures

These are inert source fixtures read by the adversary, not an application served to users. Both intentionally use a raw-HTML sink to exercise the layout rule. `clean` means clean for `react.stale-layout-measurement` (its effect tracks the HTML prop), not clean for the separate raw-HTML security rule. Tests assert each rule independently. Production code should separately sanitize untrusted HTML.

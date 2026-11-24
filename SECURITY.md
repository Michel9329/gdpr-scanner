# Security

Please report vulnerabilities privately through GitHub: open the Security tab of this repository and choose "Report a vulnerability". Do not open a public issue for a security problem.

This project is maintained by one person, so there is no guaranteed response time, but every report is read and answered.

Supported version: the latest commit on `main`.

What the scanner checks at each step, and what remains open, is written down in the
[Security section of the README](README.md#security). The open items are known: requests to a public
name that resolves to a private address, sent before an answer shows the address (all of them when
that address never answers over HTTP), the first request of a popup, the requests of dedicated,
shared and service workers, WebSocket and WebRTC connections, and the page's own variables, which are
bounded only once they reach the Worker. A report about one of them is still welcome if it
shows more than the README says.

The scanner is not a firewall. Run under `wrangler dev`, the browser is on your machine and reaches
what your machine reaches: scan only sites you trust there.

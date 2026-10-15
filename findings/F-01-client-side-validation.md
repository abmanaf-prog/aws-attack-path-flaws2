# F-01 — Input validation enforced only on the client side

| | |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3** |
| **CWE** | CWE-602: Client-Side Enforcement of Server-Side Security |
| **MITRE ATT&CK** | T1190 — Exploit Public-Facing Application |
| **Affected** | Internet-facing serverless API endpoint |

## Description & root cause
The application accepted a value through a web form and enforced its only validation ("the value must be numeric") in **client-side JavaScript**. The backend serverless function performed no equivalent server-side check. Because client-side code runs entirely under the attacker's control, the check is trivially bypassed by sending a request straight to the API.

This weakness is low-impact in isolation, but it is the **entry point** that enables [F-02](F-02-sensitive-data-exposure-serverless.md): the unexpected input the backend never anticipated triggers the error path that leaks credentials.

## Evidence (redacted)
- Page source revealed a form posting to an API Gateway endpoint, with a JS function rejecting non-numeric input.
- A request issued directly to the API (outside the browser) with a non-numeric value was processed by the backend — proving no server-side validation.

## Impact
Allows an unauthenticated attacker to submit arbitrary, unvalidated input to backend logic, reaching code paths the developers assumed were unreachable. Here it directly enabled credential disclosure.

## Remediation
Re-validate all input **server-side** (type, format, range), independent of client checks. See [`remediation.md`](../remediation.md) P6.

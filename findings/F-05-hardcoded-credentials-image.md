# F-05 — Hard-coded credentials embedded in a container image

| | |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` → **7.7** |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **MITRE ATT&CK** | T1552.001 — Unsecured Credentials: Credentials In Files |
| **Affected** | Container image / downstream proxy service |

## Description & root cause
The container image created an HTTP Basic-Auth credential file during build by passing the **username and password as plaintext arguments to a `RUN` instruction**. Build-time command arguments are permanently preserved in the image's layer metadata ("build history") and are recoverable by anyone who can pull the image — even if the resulting file is later deleted. The recovered credentials protected an internal service, so disclosing them defeated that service's authentication.

## Evidence (redacted)
```bash
docker history --no-trunc <IMAGE>
# -> ...RUN htpasswd -b <path> <BASIC_AUTH_USER> <BASIC_AUTH_PASS>   (plaintext, in the clear)
```
The credentials were then accepted by the internal proxy service's Basic-Auth prompt.

## Impact
Authentication bypass of the internal service via legitimately recovered credentials. This unlocked the SSRF-vulnerable proxy ([F-06](F-06-ssrf-metadata-credential-theft.md)), the next pivot. More broadly, secrets in images leak to anyone in the image's distribution path (registry, CI caches, developer laptops).

## Remediation
Never pass secrets as build args / `RUN` arguments. Inject at runtime via Secrets Manager / SSM SecureString. Rotate the exposed secret. Add image + secret scanning to CI. See [`remediation.md`](../remediation.md) P2.

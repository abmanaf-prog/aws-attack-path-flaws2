# F-06 — SSRF enabling local file read and cloud-metadata credential theft

| | |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` → **8.5** |
| **CWE** | CWE-918: Server-Side Request Forgery (SSRF) |
| **MITRE ATT&CK** | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| **Affected** | Internal proxy service / ECS task metadata service |

## Description & root cause
The internal service exposed a proxy that **fetched arbitrary URLs supplied by the user, server-side** — a textbook SSRF. Its source (recovered from the pulled image) passed user input directly into a URL-opening call with **no scheme restriction**, so non-HTTP schemes such as `file://` were honoured, extending SSRF into **arbitrary local file read (LFI)**.

The chain:
1. `file://` read of `/proc/self/environ` disclosed the container's environment, including the **relative path to the ECS task metadata credentials endpoint** (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`).
2. Requesting `169.254.170.2/<that-path>` **through the SSRF** returned the **task role (ROLE-B) credentials**.

Root causes: (a) an unauthenticated-destination server-side fetcher, (b) no URL-scheme allowlist, (c) application-layer reachability of the link-local metadata endpoint.

## Evidence (redacted)
```bash
# SSRF confirmed by proxying an external URL, then:
# file:// LFI -> container environment:
#   AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = /v2/credentials/<redacted>
#   AWS_EXECUTION_ENV = AWS_ECS_FARGATE
# SSRF -> metadata endpoint -> ROLE-B credentials:
#   {"RoleArn":"arn:aws:iam::TARGET_ACCOUNT:role/ROLE-B",
#    "AccessKeyId":"<ACCESS_KEY>","SecretAccessKey":"<SECRET_KEY>","Token":"<SESSION_TOKEN>"}
aws sts get-caller-identity --profile role-b   # -> assumed-role/ROLE-B/...
```

## Impact
Theft of a second, broader workload identity (ROLE-B), proven to enumerate every bucket in the account (`s3:ListAllMyBuckets`). SSRF-to-metadata is the highest-leverage web-to-cloud pivot and the pattern behind major real-world cloud breaches. Rated **High (CVSS 8.5)** in isolation, but it is the single most severe and highest-leverage link in the chain: network-reachable, low-complexity, scope-changing credential theft enabling account-wide enumeration.

## Remediation (highest priority)
Allowlist URL schemes to `http/https`; block link-local/metadata ranges at app and network layers; validate/canonicalize destinations; enforce IMDSv2 on EC2 and restrict egress to the task metadata endpoint on ECS; minimize the task role's privileges. See [`remediation.md`](../remediation.md) P1.

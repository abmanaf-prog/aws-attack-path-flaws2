# F-03 — Over-privileged function execution role

| | |
|---|---|
| **Severity** | Contributing weakness (no standalone CVSS) |
| **CVSS v3.1** | Not scored as a standalone vulnerability — a defense-in-depth failing that *amplifies* credential theft rather than being independently exploitable. |
| **CWE** | CWE-250: Execution with Unnecessary Privileges; CWE-269: Improper Privilege Management |
| **MITRE ATT&CK** | No precise technique (ATT&CK describes adversary actions, not configuration weaknesses); this weakness *amplifies* T1078.004 / T1552.001 once the role's credentials are used |
| **Affected** | IAM role (ROLE-A) attached to the serverless function |

## Description & root cause
The serverless function's execution role (ROLE-A) held **container-registry permissions that its workload never required** — a PIN-checking function has no legitimate need to interact with a container registry. This is a least-privilege violation. On its own it grants nothing to an outsider, but once ROLE-A's credentials were stolen ([F-02](F-02-sensitive-data-exposure-serverless.md)), the excess permissions **widened the blast radius**, enabling the attacker to list and pull the private image ([F-04](F-04-public-container-registry.md)).

Observed least-privilege behaviour for contrast: ROLE-A was **correctly denied** `s3:ListAllMyBuckets`, showing partial scoping — but the registry permissions were an oversight.

## Evidence (redacted)
- `ROLE-A` successfully performed `ecr:ListImages`, `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`.
- `ROLE-A` was denied `s3:ListAllMyBuckets` (`no identity-based policy allows...`), demonstrating the permissions were inconsistently scoped.

## Impact
Amplifies any credential theft of the role. Removing the unused registry permissions alone would have broken the pivot from the function to the image.

## Remediation
Scope the role to only what the workload uses (here: its own logging). Use Access Analyzer / Access Advisor to find and remove unused permissions. See [`remediation.md`](../remediation.md) P4.

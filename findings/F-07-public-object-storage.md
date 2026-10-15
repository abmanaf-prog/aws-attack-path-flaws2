# F-07 — Publicly readable object storage

| | |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3** *(C:L reflects low-sensitivity lab objects; raise to C:H → 7.5 if a bucket holds sensitive data)* |
| **CWE** | CWE-732: Incorrect Permission Assignment for Critical Resource |
| **MITRE ATT&CK** | T1530 — Data from Cloud Storage Object (reading objects); T1619 — Cloud Storage Object Discovery (the account-wide bucket enumeration) |
| **Affected** | Object-storage buckets |

## Description & root cause
Multiple object-storage buckets were readable by principals outside the owning account. Log analysis (defender phase) confirmed objects were retrieved by an **external AWS account** (`userIdentity.type = AWSAccount`), proving public/cross-account readability. One object with an unguessable name was still retrievable once its key was known — demonstrating that an unguessable filename is **not** an access control.

Root cause: bucket/object permissions granting read to a broad audience (e.g. all/authenticated AWS users) instead of specific principals.

## Evidence (redacted)
From CloudTrail (defender phase):
```
GetObject  userIdentity.type=AWSAccount  bucket=<BUCKET>  key=<redacted object>
```
Repeated for several buckets, including one serving a non-linked "secret" object whose content pointed to the next resource.

## Impact
Information disclosure of object contents to anyone, with no credentials needed to read a known key. In production the equivalent is leaked documents, backups, or configuration.

## Note
Discovery of the non-linked object required a **listing** permission (via a stolen role), but **reading** it required nothing — reinforcing that both "list" exposure and public "read" are distinct risks.

## Remediation
Enable S3 Block Public Access; replace broad grants with least-privilege bucket policies; enable S3 data events for auditing. See [`remediation.md`](../remediation.md) P7.

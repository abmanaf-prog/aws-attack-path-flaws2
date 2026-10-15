# Detection & Response Coverage

This maps each attacker action to the telemetry it produces (or does **not** produce), with example detection logic. Items I am not fully certain of are flagged **`verify`**.

> Key limitation observed: several attack steps generate **no CloudTrail management-event record** because they occur inside the application/runtime, not via the AWS control plane. Detection therefore depends on (a) the *downstream* misuse of stolen credentials and (b) GuardDuty behavioural findings.

---

## 1. What each step logs

| Attacker action | CloudTrail / telemetry | Notes |
|---|---|---|
| Submit malformed input to the serverless endpoint | **Not in CloudTrail** | API Gateway / Lambda invocation is data-plane; requires API Gateway access logging or Lambda logging to see it |
| Function leaks env vars in response | **Not in CloudTrail** | Visible only in the function's own application logs, if the error is logged |
| Assume ROLE-A (by the service) | `AssumeRole` (`sts`), `sourceIPAddress` = an AWS service principal | Legitimate baseline |
| **Use ROLE-A creds from attacker host** | `ListObjects`, `ListImages`, `BatchGetImage`, `GetDownloadUrlForLayer` with `userIdentity.arn` = ROLE-A **but `sourceIPAddress` = external IP** | 🚨 **Primary detection** |
| Pull container image | `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:ListImages` | Management events present |
| SSRF → read `/proc/self/environ` | **Not in CloudTrail** | Happens inside the container |
| SSRF → ECS task metadata request | **Not in CloudTrail** | Link-local metadata call, not a control-plane API call |
| **Use ROLE-B creds from attacker host** | `ListBuckets` (and any S3 reads) with `userIdentity.arn` = ROLE-B **from external IP** | 🚨 **Primary detection** |
| Read public objects as an outside account | `GetObject` with `userIdentity.type = AWSAccount` (cross-account) | Requires S3 **data events** enabled |

---

## 2. High-fidelity detection: role credentials used outside their environment

A Lambda/ECS role should only ever call AWS APIs from **inside AWS**. The same role appearing from a public internet IP is a strong indicator of credential theft.

### Athena / CloudTrail SQL (concept)
```sql
SELECT eventtime, sourceipaddress, useridentity.arn AS who, eventname
FROM cloudtrail_logs
WHERE useridentity.arn LIKE '%assumed-role/%'
  AND sourceipaddress NOT LIKE '%.amazonaws.com'   -- exclude AWS service calls
  AND sourceipaddress NOT LIKE '10.%'              -- exclude internal ranges (tune to your VPC CIDRs)  verify
ORDER BY eventtime;
```
During the engagement this returned exactly the attacker's external IP using ROLE-A and ROLE-B — the credential theft, caught.

### Sigma-style rule (concept) — `verify` field names against your log schema
```yaml
title: IAM Role Credentials Used From Outside AWS
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: AssumedRole
  filter_aws_service:
    sourceIPAddress|endswith: '.amazonaws.com'
  filter_internal:
    sourceIPAddress|cidr:
      - '10.0.0.0/8'      # tune to your environment
  condition: selection and not filter_aws_service and not filter_internal
level: high
falsepositives:
  - Legitimate cross-account automation calling from corporate NAT egress IPs
  - CI/CD or admin tooling assuming roles from known office ranges (allowlist them)
```

**False-positive considerations:** many orgs legitimately use assumed roles from outside AWS (SSO, CI/CD, admin laptops). Tune with an **allowlist of known egress IPs** and by scoping to *workload* roles (Lambda/ECS execution roles) that should never be used interactively.

---

## 3. GuardDuty findings expected (`verify` exact finding types for your account)

- **`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`** — role/instance credentials used from an external IP. This is the behavioural equivalent of the Athena query above and would likely fire for both pivots. `verify`
- **`Discovery:S3/...` / `Exfiltration:S3/...`** — unusual enumeration/read of buckets. `verify`
- GuardDuty does **not** see the SSRF or the in-container metadata call directly; it infers compromise from the *credential misuse pattern* afterwards.

---

## 4. Response recommendations

1. **Contain:** immediately revoke/rotate the exposed role sessions (deny the session, rotate any long-term keys, update trust where applicable).
2. **Eradicate:** fix the SSRF and the env-dump (root causes); strip registry permissions from the function role.
3. **Scope:** use CloudTrail + S3 data events to list every object the attacker's external IP accessed under ROLE-A/ROLE-B.
4. **Harden detection:** enable GuardDuty, CloudTrail with data events, and the "role used from outside AWS" alert above.

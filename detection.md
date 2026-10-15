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

## 2. High-fidelity detection: workload-role credentials used outside their environment

A Lambda/ECS execution role should only ever call AWS APIs from inside its own workload. The same role appearing from an **unexpected** source is a strong indicator of credential theft.

> **Important nuance (why the obvious query is wrong).** Calls made *from inside* Lambda or Fargate do **not** show a `*.amazonaws.com` hostname or an RFC-1918 (`10.x`) address in `sourceIPAddress` — they show an **AWS-owned *public* IP**. In this engagement the legitimate `level1` executions came from one AWS public IP (`LEGIT_EXEC_IP`) and the attacker from another public IP (`ATTACKER_IP`). So a filter that merely excludes `*.amazonaws.com` and `10.0.0.0/8` would *also* flag your own healthy workloads. You need range- or baseline-aware logic instead.

### Approach A — compare against AWS's published IP ranges
Flag a workload role used from an IP that is **not** in AWS's published ranges (`ip-ranges.json`). Caveat: an attacker who replays the credentials from *their own EC2 instance* is still inside AWS ranges (GuardDuty's `InsideAWS` case), so pair this with Approach B.

```sql
-- Concept: a workload (assumed-role) credential used from a non-AWS-owned IP.
-- Requires a side table `aws_ip_ranges(ip_prefix)` loaded from ip-ranges.json,
-- and your engine's CIDR-match function.  verify
SELECT eventtime, sourceipaddress, useridentity.arn AS who, eventname
FROM cloudtrail_logs c
WHERE useridentity.arn LIKE '%assumed-role/%'
  AND sourceipaddress NOT LIKE '%.amazonaws.com'            -- drop service-initiated calls
  AND NOT EXISTS (
        SELECT 1 FROM aws_ip_ranges r
        WHERE ip_in_cidr(c.sourceipaddress, r.ip_prefix)    -- range match (engine-specific)
      )
ORDER BY eventtime;
```

### Approach B — per-role IP / behaviour baseline (most reliable)
Workload roles have a small, stable set of egress IPs and a narrow set of actions. Alert when a role is seen from an IP outside its learned baseline, or performing API calls it never normally makes (e.g. a PIN-check Lambda role suddenly calling `ecr:*` / `s3:ListBuckets`).

![CloudTrail timeline: the same level1 role appears from its legitimate execution IP (CreateLogStream) and from an external attacker IP performing S3/ECR actions; level3 then lists buckets from the attacker IP](evidence/defender-timeline.png)

> In this lab the attacker's IP happened to fall outside AWS ranges, so even a naive query surfaced it — but only because the account had almost no other traffic. In a production account, use the range/baseline logic above or the rule is noisy and unreliable.

### Sigma-style rule (concept) — `verify` field names against your log schema
```yaml
title: Workload (Assumed-Role) Credentials Used From Unexpected Source
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: AssumedRole
  filter_aws_service:
    sourceIPAddress|endswith: '.amazonaws.com'
  # NOTE: cannot simply exclude 10.x — Lambda/Fargate egress is an AWS *public* IP.
  # Enrich sourceIPAddress against AWS ip-ranges / a per-role baseline before alerting.
  filter_known_workload_ips:
    sourceIPAddress:
      - '<role baseline egress IPs / your AWS ranges>'   # enrichment required
  condition: selection and not filter_aws_service and not filter_known_workload_ips
level: high
falsepositives:
  - Legitimate cross-account automation or CI/CD assuming roles from known egress (allowlist them)
```

**False-positive considerations:** many orgs legitimately use assumed roles from outside AWS (SSO, CI/CD, admin laptops). Scope this to *workload* execution roles (Lambda/ECS) that should never be used interactively, and drive it from IP-range enrichment or a per-role baseline rather than a static CIDR exclusion.

---

## 3. GuardDuty findings expected

**Match the finding type to the compute service — they are not interchangeable:**

- **`UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS`** — this is the one that fits **ROLE-B**, the **ECS/Fargate task role**, used from outside AWS. AWS added this finding specifically to cover non-EC2 resource credentials (including ECS task roles); it is the right match for the second pivot here.
- **`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`** — this one is **EC2-instance-role specific**. There is **no EC2 instance** in this attack path, so, despite its familiar name, it would **not** fire for this chain. (Listed here precisely to avoid the common mistake of citing it for Lambda/ECS.)
- **ROLE-A (the Lambda execution role):** GuardDuty's coverage of *Lambda* role-credential replay is weaker/less clearly documented than EC2 or ECS. Don't assume a finding fires — lean on the CloudTrail IP-range / baseline detection in §2 for this pivot. `verify` for your account/region.
- **`Discovery:S3/...` / unusual S3 enumeration findings** — may fire on the cross-account/bucket enumeration. `verify`
- GuardDuty does **not** see the SSRF or the in-container metadata call directly; it infers compromise from the *credential-misuse pattern* afterwards.

---

## 4. Response recommendations

1. **Contain:** immediately revoke/rotate the exposed role sessions (deny the session, rotate any long-term keys, update trust where applicable).
2. **Eradicate:** fix the SSRF and the env-dump (root causes); strip registry permissions from the function role.
3. **Scope:** use CloudTrail + S3 data events to list every object the attacker's external IP accessed under ROLE-A/ROLE-B.
4. **Harden detection:** enable GuardDuty, CloudTrail with data events, and the "role used from outside AWS" alert above.

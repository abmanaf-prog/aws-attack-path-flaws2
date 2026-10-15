# Remediation

Fixes are ordered by priority (impact × ease). Example policies are illustrative — adapt resource ARNs and conditions to the target environment and test before applying.

---

## P1 — Eliminate the SSRF and block metadata access from app code (Finding F-06)

The SSRF → metadata chain is the most damaging link; fixing it alone prevents the second credential theft.

- **Whitelist URL schemes** to `http`/`https` only in the proxy. Reject `file://`, `ftp://`, `gopher://`, etc.
- **Block requests to link-local / metadata ranges** in the application and at the network layer: `169.254.169.254/32`, `169.254.170.2/32`, and the full `169.254.0.0/16` link-local range.
- **Validate and canonicalize** the target host; deny private/loopback/link-local resolved addresses (defends against DNS-rebinding and redirects).
- **Enforce IMDSv2** on EC2 workloads (session-token-required metadata; blocks naive GET-based SSRF). *Note: this target ran on ECS Fargate, which has no EC2 IMDS — there, the control is network egress restriction to the task metadata endpoint and not exposing a server-side URL fetcher.*
- Give the workload **the least-privileged task/execution role possible**, so stolen metadata credentials are low-value.

```python
# Illustrative: scheme + destination allowlist before any server-side fetch
from urllib.parse import urlparse
import ipaddress, socket

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_NETS = [ipaddress.ip_network("169.254.0.0/16"),
                ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("10.0.0.0/8")]  # tune

def is_safe(url: str) -> bool:
    u = urlparse(url)
    if u.scheme not in ALLOWED_SCHEMES:
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
    return not any(ip in net for net in BLOCKED_NETS)
```

---

## P2 — Remove hard-coded secrets from images (Finding F-05)

- **Never** pass secrets as build-time arguments or `RUN` arguments — they persist in image history permanently.
- Inject secrets **at runtime** from **AWS Secrets Manager** / **SSM Parameter Store** (SecureString), or mounted files.
- **Rotate** the exposed credential immediately.
- Add **image scanning** (ECR scan-on-push, or Trivy/Grype in CI) and secret-scanning (gitleaks/trufflehog) to the pipeline to catch baked-in secrets before publish.

---

## P3 — Lock down the container registry (Finding F-04)

- Restrict the **ECR repository policy** to only the specific deploy roles/accounts that must pull. Remove any `Principal: "*"` or broad `AWS` grants.
- Enable **scan-on-push** and tag immutability.

```json
// Illustrative least-privilege ECR repository policy
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowPullFromDeployRoleOnly",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::TARGET_ACCOUNT:role/ecs-task-execution-role" },
    "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability"]
  }]
}
```

---

## P4 — Apply least privilege to workload roles (Finding F-03)

- The function role held **registry permissions it never used**. Scope each role to the minimum actions/resources its workload needs.
- Use **IAM Access Analyzer** and **Access Advisor** (last-accessed data) to find and remove unused permissions; tools like CloudTracker/RepoKid can automate right-sizing.

```json
// Illustrative: a PIN-check Lambda needs only its own logging — nothing else
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "arn:aws:logs:*:TARGET_ACCOUNT:log-group:/aws/lambda/<function>:*"
  }]
}
```

---

## P5 — Sanitize error handling (Finding F-02)

- Return **generic error messages**; never serialize environment variables, stack traces, or config into responses.
- Log detailed errors **server-side only**, and scrub secrets from logs.
- Treat the environment of any function/container as sensitive — it holds the role credentials.

---

## P6 — Validate input server-side (Finding F-01)

- Re-validate **all** input in the backend (type, range, format), independent of any client-side checks.
- In chained/serverless architectures, never assume an upstream component already validated — assumptions break as the architecture changes.

---

## P7 — Remove public access from object storage (Finding F-07)

- Enable **S3 Block Public Access** at the account and bucket level.
- Replace public/`AllUsers`/`AuthenticatedUsers` grants with least-privilege bucket policies scoped to specific principals.
- Enable **S3 data events** in CloudTrail for sensitive buckets so object reads are auditable.

---

## Preventative guardrails (organization-wide)

- **SCPs** to deny creation of public resources and to require IMDSv2 / block disabling of Block Public Access.
- **GuardDuty** enabled across accounts.
- **CloudTrail** (all regions, management + selective data events) delivered to a locked-down logging account.
- Alert on **workload-role credentials used from outside AWS** (see [`detection.md`](detection.md)).

### Priority order
1. P1 (SSRF/metadata) → 2. P2 (image secrets) → 3. P3 (registry) → 4. P4 (least privilege) → 5. P5 (error handling) → 6. P6 (validation) → 7. P7 (public storage) → guardrails.

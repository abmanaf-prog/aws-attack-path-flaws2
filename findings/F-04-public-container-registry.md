# F-04 — Private container registry exposed to unauthorized principals

| | |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → **7.5** |
| **CWE** | CWE-732: Incorrect Permission Assignment for Critical Resource |
| **MITRE ATT&CK** | T1530 — Data from Cloud Storage Object *(approximate — ATT&CK has no technique precisely covering container-registry image theft)* |
| **Affected** | Private container registry repository |

## Description & root cause
The container registry repository holding the application image was protected by an **over-permissive repository policy**, allowing principals that should have no access to **list and pull** the private image. Container registries are private by default; an explicit resource policy had widened access. Because a container image bundles the application's filesystem, configuration, and (here) secrets, pulling it is equivalent to exfiltrating the application's source and configuration.

## Evidence (redacted)
```bash
aws ecr list-images --repository-name <REPO> --registry-id TARGET_ACCOUNT --region <REGION>
# -> returned the image inventory (repo is listable)
aws ecr get-login-password ... | docker login ...        # Login Succeeded
docker pull <IMAGE>                                       # all layers pulled
```
The `list-images` call confirming the exposure is **information disclosure**; the successful `pull` is the actual data breach.

## Impact
Any party with the exposed access can retrieve the private image and mine it for secrets, configuration, and logic — which is exactly what enabled [F-05](F-05-hardcoded-credentials-image.md).

## Note on defense-in-depth
This finding combined with [F-03](F-03-excessive-iam-permissions.md): even a true outsider could reach the registry via the open policy, and the stolen over-privileged role made it trivial. Either control, correctly set, would have helped.

The CVSS vector uses `PR:N` because the repository policy exposed the image to *any* principal. In this engagement the image was pulled using a stolen in-account role, but the public policy means no legitimate credentials are required to realize the exposure.

## Remediation
Restrict the repository policy to only the deploy roles that must pull; remove `Principal:"*"`/broad grants; enable scan-on-push. See [`remediation.md`](../remediation.md) P3.

# Attack Path Diagram & Narrative

## Full chain

```mermaid
%%{init: {'theme':'base', 'themeVariables': {
  'fontSize':'14px',
  'lineColor':'#6b7280',
  'primaryColor':'#eef2f7',
  'primaryTextColor':'#111827',
  'primaryBorderColor':'#4b5563'
}}}%%
flowchart TD
    subgraph P1 [Phase 1 &middot; Initial Access]
      direction LR
      A([Unauthenticated<br/>attacker]) --> B[Client-side-only<br/>PIN validation] --> C[Verbose error<br/>leaks environment]
    end
    subgraph P2 [Phase 2 &middot; Credential Access I]
      direction LR
      D[Assume ROLE-A<br/>insider of account] --> E[Over-permissive access<br/>to private registry] --> F[Secret in image<br/>build history]
    end
    subgraph P3 [Phase 3 &middot; Lateral Movement / SSRF]
      direction LR
      G[Authenticate to<br/>internal proxy] --> H{SSRF +<br/>no scheme check} --> I[file:// LFI<br/>read /proc/self/environ] --> J[ECS task metadata<br/>169.254.170.2]
    end
    subgraph P4 [Phase 4 &middot; Impact]
      direction LR
      K[Assume ROLE-B] --> L([Enumerate ALL buckets<br/>objective bucket public])
    end

    C -->|ROLE-A credentials| D
    F -->|hard-coded credentials| G
    J -->|ROLE-B credentials| K

    classDef step fill:#eef2f7,stroke:#4b5563,color:#111827;
    classDef danger fill:#fde2e2,stroke:#cc0000,color:#111827;
    classDef goal fill:#d7f5d7,stroke:#00870e,color:#111827;

    class A,B,D,E,G,I,K step;
    class C,F,H,J danger;
    class L goal;
```

## Narrative (one paragraph)

The attack begins with an internet-facing serverless endpoint whose only input check runs in the browser. Submitting unexpected input straight to the API causes the function to leak its runtime environment — and with it, the temporary credentials of its execution role (**ROLE-A**). Those credentials make the attacker an insider of the target account, which is enough to reach a private container registry left open by an over-permissive policy (and reachable because the function role carried registry permissions it never needed). Pulling the image and reading its build history exposes a hard-coded password that unlocks an internal proxy. The proxy is vulnerable to SSRF and, because it applies no URL-scheme restriction, also to local file read; reading the container's environment reveals the path to the ECS task metadata service, which is then queried *through the SSRF* to steal a second, broader credential set (**ROLE-B**). ROLE-B can enumerate every bucket in the account (`s3:ListAllMyBuckets`); the objective bucket was then read because it was itself public. Account-wide *enumeration* was reached entirely through chained misconfigurations.

## Phase mapping (Cyber Kill Chain / cloud)

| Phase | Step in this engagement |
|-------|-------------------------|
| Reconnaissance | Fingerprint the serverless backend from page source |
| Initial Access | Bypass client-side validation; trigger verbose error |
| Credential Access (1) | Harvest ROLE-A creds from leaked environment |
| Discovery / Lateral Movement | Enumerate + pull private container image |
| Credential Access (2) | Recover hard-coded secret; SSRF → metadata → ROLE-B creds |
| Collection / Impact | Enumerate all buckets account-wide; read the (public) objective bucket |

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
    A([Unauthenticated attacker]) --> B[Serverless PIN endpoint<br/>validation only in client-side JS]
    B -->|direct API request with<br/>unexpected input| C[Function error handler<br/>returns full environment]
    C -->|leaks ROLE-A credentials<br/>from env vars| D[Assume ROLE-A<br/>= insider of TARGET_ACCOUNT]
    D -->|over-permissive policy +<br/>unneeded ECR rights| E[Private container registry]
    E -->|pull private image| F[Inspect image build history]
    F -->|hard-coded basic-auth<br/>credentials in a RUN layer| G[Authenticate to internal proxy service]
    G -->|SSRF: proxy fetches<br/>arbitrary URLs| H{No URL scheme<br/>restriction}
    H -->|file:// = LFI| I[Read /proc/self/environ]
    I -->|recover metadata<br/>credentials path| J[ECS task metadata<br/>169.254.170.2]
    J -->|leaks ROLE-B credentials| K[Assume ROLE-B]
    K -->|ListAllMyBuckets allowed| L([Enumerate ALL buckets<br/>objective bucket itself public])

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

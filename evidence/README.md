# Evidence

Drop **sanitized** screenshots / terminal captures here and reference them from the finding files
(e.g. `![env var leak](../evidence/F-02-env-var-leak.png)`).

## Redact before committing anything here
Remove or blur: AWS **account IDs**, **access/secret keys**, **session tokens**, **source IPs**,
full **resource names/ARNs**, and any **lab-answer URLs or secret values**. Crop to just the
relevant line(s).

> Keep original **unredacted** captures OUT of git. Put them in a local `raw-evidence/` folder —
> it is already in `.gitignore`.

## Suggested files
| File | Shows |
|---|---|
| `F-02-env-var-leak.png` | serverless function returning env vars (keys redacted) |
| `F-04-ecr-list-pull.png` | listing/pulling the exposed image |
| `F-05-docker-history.png` | hard-coded credential in build history (password blurred) |
| `F-06-metadata-creds.png` | SSRF → metadata credential response (keys redacted) |
| `defender-timeline.png` | CloudTrail timeline showing role used from an external IP |

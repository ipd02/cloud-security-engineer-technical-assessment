# Part 2: Cloud security check

Review of the task's CloudFormation template and Dockerfile. The originals are kept unchanged. Hardened replacements, a scanner regression test and a prevention plan sit beside them.

## Layout

| Path | What |
| --- | --- |
| `cloudformation/original.yaml` | Task template, unchanged |
| `cloudformation/hardened.yaml` | Hardened template |
| `docker/Dockerfile.original` | Task Dockerfile, unchanged |
| `docker/Dockerfile.hardened` | Hardened Dockerfile (pinned by digest) |
| `docker/app.py`, `docker/.dockerignore` | Small service and build-context filter for the hardened image |
| `tests/assert-originals-fail.sh` | Proves the scanners reject the originals and accept the hardened files |
| `PREVENTION.md` | How to stop these mistakes from being introduced, by layer |
| `part.mk` | Make targets for this part |

## How to run

From the repository root:

```sh
make cloud-check-lint    # cfn-lint, hadolint on the hardened files
make cloud-check-scan    # checkov and trivy config on the hardened files
make cloud-check-test    # originals must fail, hardened must pass
make cloud-check-build   # build the hardened image (needs docker)
```

Tool versions used: cfn-lint 1.57.2, checkov 3.3.20, hadolint 2.15.1, trivy 0.75.0, Docker 29.9.0 (through colima), AWS CLI 2.37.13.

The two secret-looking values in `docker/Dockerfile.original` are the task's own sample values. `.gitleaks.toml` allows only those two literals, only in that file.

## 1. CloudFormation: what is wrong

Ranked by impact.

1. **The IAM user has `Action: "*"` on `Resource: "*"`.** That is full administrator access to the whole account, through an inline policy. Checkov fails 6 IAM checks on it (CKV_AWS_62, 63, 107, 108, 109, 110, 111 are the family that fire).
2. **A long-lived IAM user instead of a role.** A user means access keys or a password that do not expire and must be rotated by hand. A role gives short-lived credentials from STS. The policy is also attached to the user directly (trivy AWS-0143).
3. **The bucket is not protected from public exposure.** There is no `PublicAccessBlockConfiguration` (trivy AWS-0086, 0087, 0091, 0093, 0094, all HIGH except 0094).
4. **No encryption configuration.** S3 applies SSE-S3 by default, but nothing uses a customer-managed key, so there is no key policy, no key-level audit trail and no way to revoke access by disabling the key (trivy AWS-0132).
5. **No versioning.** An overwrite or delete cannot be undone (CKV_AWS_21, AWS-0090).
6. **No access logging.** Nothing records who read or wrote objects (CKV_AWS_18, AWS-0089).
7. **No TLS-only bucket policy.** Requests over plain HTTP are accepted.
8. **No ownership controls.** Object ACLs stay possible. `BucketOwnerEnforced` turns them off.
9. **No `DeletionPolicy` or `UpdateReplacePolicy` and no lifecycle rule.** A stack delete or replacement removes the bucket with its data, and old data is never expired.
10. **Smaller points.** The user name is hard-coded, so the template cannot be deployed twice and needs `CAPABILITY_NAMED_IAM`. The policy document has no `Version`, so it uses the old policy language. The policy has no `Sid`.

## 2. CloudFormation: hardened template

`cloudformation/hardened.yaml` makes these changes.

| Original problem | Change |
| --- | --- |
| IAM user with `*` on `*` | `AWS::IAM::Role` `DataAccessRole` plus a customer-managed `AWS::IAM::ManagedPolicy` |
| Trust | The role trusts one principal given by the `TrustedPrincipalArn` parameter. The trust policy requires `sts:ExternalId`, and `aws:MultiFactorAuthPresent` when `RequireMfa` is `"true"` (the default). Session length is capped at 3600 seconds. |
| Over-broad permissions | The policy lists named actions: `s3:ListBucket`, `s3:GetBucketLocation` on the bucket ARN, `s3:GetObject`, `s3:GetObjectVersion`, `s3:PutObject` on `bucket/*`, and `kms:Decrypt`, `kms:GenerateDataKey` on the one key. |
| Public access | All four public access block settings are on. |
| Encryption | SSE-KMS with a customer-managed key (`EnableKeyRotation: true`) and `BucketKeyEnabled: true` to cut KMS request cost. |
| Versioning | Enabled. |
| Logging | Server access logs go to a separate `LogBucket`, delivered by `logging.s3.amazonaws.com` and limited by `aws:SourceAccount` and `aws:SourceArn`. |
| Ownership | `BucketOwnerEnforced` on both buckets. |
| TLS | A bucket policy denies every request where `aws:SecureTransport` is `false`. |
| Lifecycle | Noncurrent versions expire after `DataRetentionDays` (default 90). Log objects expire after `LogRetentionDays` (default 365). Incomplete multipart uploads abort after 7 days. |
| Parameters | Every parameter has a type, description and constraints (`AllowedPattern`, `MinLength`, `MinValue`, `AllowedValues`). |
| Outputs | Data bucket ARN, log bucket name, key ARN, role ARN. |

Choices worth stating:

- **`DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain`** on the data bucket, the log bucket and the KMS key. A stack delete must not destroy data or the key that decrypts it. The cost is that someone must remove these on purpose later. The role and policies use the default `Delete`.
- **The log bucket uses SSE-S3, not SSE-KMS.** S3 server access log delivery cannot write to a bucket encrypted with a KMS key. The template says so in a comment.
- **One inline skip.** `CKV_AWS_18` (access logging) is skipped on `LogBucket` only. Logging the log bucket would need another log bucket, forever. The skip sits in the resource `Metadata` with its reason. There are no other skips.
- **No `BucketName`.** CloudFormation generates a unique name, so the template can be deployed in several accounts or stacks.
- **The key policy only delegates to IAM** for this account. Access is then granted by the role policy. A stricter setup would name key administrators and key users in the key policy.

Verification of this template is in "What was verified".

## 3. Assuming the user exists: find it and fix it

### Finding it

Each item names the primitive. The commands are real AWS CLI v2 commands. I could run only the ones that need no credentials here (see the status column).

| Step | Primitive | Command | Status |
| --- | --- | --- | --- |
| 1 | IAM credential report: users, key age, last use | `aws iam generate-credential-report` then `aws iam get-credential-report --query Content --output text \| base64 -d` | Skeleton checked with `--generate-cli-skeleton` (prints `{}`). Call itself not executed here: no credentials. |
| 2 | Who has an all-actions policy | `aws iam get-account-authorization-details --filter User --output json > authz.json`, then `jq -r '.UserDetailList[] \| select(.UserPolicyList[]?.PolicyDocument.Statement \| (if type=="array" then . else [.] end)[] \| select(.Action=="*" and .Resource=="*")) \| .UserName' authz.json` | AWS call not executed here. The `jq` filter ran against a hand-written sample file and printed the expected user. |
| 3 | Access Advisor: which services the user really used | `aws iam generate-service-last-accessed-details --arn <user-arn> --granularity ACTION_LEVEL` then `aws iam get-service-last-accessed-details --job-id <id>` | Skeleton checked (prints `Arn`, `Granularity`). Not executed here. |
| 4 | IAM Access Analyzer unused access: finds unused users, roles, keys and permissions | `aws accessanalyzer create-analyzer --analyzer-name unused --type ACCOUNT_UNUSED_ACCESS --configuration '{"unusedAccess":{"unusedAccessAge":90}}'` then `aws accessanalyzer list-findings-v2 --analyzer-arn <arn>` | Skeleton checked. Not executed here. |
| 5 | Access Analyzer policy validation, run on the policy before deploy | `aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policy.json` | `help` checked. Not executed here. |
| 6 | AWS Config managed rules | `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS`, `IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS`, `IAM_USER_UNUSED_CREDENTIALS_CHECK`, `S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED`, `S3_BUCKET_SSL_REQUESTS_ONLY`, `S3_BUCKET_VERSIONING_ENABLED`, `S3_BUCKET_LOGGING_ENABLED`. Read results with `aws configservice describe-compliance-by-config-rule`. | `help` checked. Not executed here. |
| 7 | Security Hub CSPM controls (AWS Foundational Security Best Practices and CIS) | Controls such as IAM.1 (no `*:*` policies), IAM.2 (no user policies), S3.1 to S3.5 and S3.9 | Not executed here. |
| 8 | CloudTrail: what has the user done | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=UnrestrictedUser` (90 days of management events). For longer history, query the trail in Athena or CloudTrail Lake. | `help` checked. Not executed here. |
| 9 | Ad hoc sweep with an open-source scanner | Prowler, for example `prowler aws --services iam s3` | Prowler is not installed here. Not executed here. |

For this specific template the fastest check is step 2 and step 8 together: list who holds an all-actions policy, then see what that principal actually called.

### Fixing it safely

1. **Inventory.** Use steps 1, 3 and 8 to learn which keys exist, which services and actions the user used, and which systems hold its credentials.
2. **Create the replacement.** Deploy `hardened.yaml`. The role exists beside the user, and nothing breaks yet.
3. **Switch consumers one at a time.** Each consumer assumes the role (with its ExternalId, and MFA for people) in place of using the user's keys. Use roles with OIDC or instance profiles for workloads.
4. **Tighten from observed use.** If a consumer needs more than the template grants, add named actions from the Access Advisor data. Do not copy the old wildcard. Access Analyzer can generate a policy from CloudTrail activity (`aws accessanalyzer start-policy-generation`).
5. **Retire the user.** Make the access keys inactive (`aws iam update-access-key --status Inactive`), wait one release cycle and watch CloudTrail for failures. Then delete the keys, the login profile and the inline policy, and delete the user.
6. **Backstop.** Add a Service Control Policy at the organisation level that denies `iam:CreateUser`, `iam:CreateAccessKey` and attaching `AdministratorAccess` outside an approved admin role. Details are in `PREVENTION.md`.

## 4. Dockerfile: what is wrong, and the fix for each

| # | Issue in `Dockerfile.original` | Why it matters | Fix in `Dockerfile.hardened` |
| --- | --- | --- | --- |
| 1 | `FROM ubuntu:18.04` | The release no longer gets standard security updates. The tag is also a moving target, so builds are not repeatable. | `python:3.13-slim-trixie` pinned by digest (`@sha256:70729b46...`). |
| 2 | `USER root`, and the app runs as root | A bug in the app gives root inside the container. Trivy DS-0002 (HIGH), checkov CKV_DOCKER_8. | Numeric user `10001:10001`, no shell (`/usr/sbin/nologin`), no home directory. |
| 3 | `ENV DB_PASSWORD=...` and `ENV API_KEY=...` | `ENV` values are stored in the image metadata and layers. Anyone who can pull the image reads them with `docker inspect` or `docker history`. They stay in the image even if a later layer unsets them. Trivy DS-0031 (CRITICAL, twice). | No secrets in the image. Inject them at run time (see "Secrets at run time"). The app reads `DB_PASSWORD_FILE`. |
| 4 | `chmod -R 777 /app` | Every user and process can modify the code. | `app.py` is `root:root`, mode `0444`. The directory is not writable by the app user. |
| 5 | `curl`, `vim`, `dnsutils`, `python3-pip` installed | More binaries mean more CVEs and more tools for an attacker. The app needs none of them. | Nothing is installed. pip, setuptools and wheel are removed. The health check uses Python itself. |
| 6 | `apt-get install` without `--no-install-recommends`, no cleanup, no version pins | Larger image, stale package lists in the layer. Trivy DS-0029 (HIGH), hadolint DL3008, DL3009, DL3015. | No apt step is needed, so none remains. |
| 7 | `COPY . /app` with no `.dockerignore` | Copies `.git`, local `.env` files, keys, the Dockerfile and anything else in the folder into the image. | `.dockerignore` excludes everything and allows only `app.py`. The `COPY` names that one file. |
| 8 | `EXPOSE 80` | Binding a port below 1024 needs root or `CAP_NET_BIND_SERVICE`. | The app listens on 8080. |
| 9 | `CMD python3 app.py` (shell form) | Runs under `/bin/sh -c`, so signals such as SIGTERM may not reach the app. Hadolint DL3025. | Exec form: `CMD ["python", "/app/app.py"]`. |
| 10 | No `HEALTHCHECK` | The runtime cannot tell a hung container from a healthy one. Trivy DS-0026, checkov CKV_DOCKER_2. | `HEALTHCHECK` calling `/healthz` with Python. |
| 11 | Single stage with build tools in the final image | Build tooling ships to production. | Not needed here: the app uses only the standard library and has no build step. A multi-stage build would add nothing. If dependencies are added later, build them in a first stage and copy only the result. |

### Secrets at run time

The image holds no secret. Pick one source per environment:

- **Docker or Compose:** a file mount, `-v ./secret:/run/secrets/db_password:ro -e DB_PASSWORD_FILE=/run/secrets/db_password`.
- **Kubernetes:** a Secret volume, or the Secrets Store CSI driver pointing at AWS Secrets Manager, GCP Secret Manager or HashiCorp Vault. Prefer a file mount over an environment variable so the value stays out of `docker inspect` and process listings.
- **ECS:** the `secrets` field in the task definition with a Secrets Manager or SSM Parameter Store ARN.

The two values in the task Dockerfile must be treated as leaked: rotate them, because they sit in image history anywhere that image was pushed.

### Recommended run flags

```sh
docker run -d --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 8080:8080 cloud-check-hardened:local
```

Docker applies its default seccomp profile unless you override it. Do not pass `--security-opt seccomp=unconfined`. If the app needs scratch space, add `--tmpfs /tmp`, not a writable root filesystem.

Equivalent Kubernetes `securityContext`:

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: <registry>/app@sha256:<digest>
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      readinessProbe:
        httpGet: { path: /healthz, port: 8080 }
```

Kubernetes ignores the Dockerfile `HEALTHCHECK`, so the probe is set in the manifest. This manifest was not applied to a cluster here.

## 5. Prevention

See `PREVENTION.md`. It is organised by layer: developer machine, pull request, pipeline, artifact, cloud guardrails, runtime, and detection and response.

## What was verified

All results below come from commands run while building this part, on macOS with Docker through colima.

Live runs:

| Check | Result |
| --- | --- |
| `cfn-lint cloudformation/hardened.yaml` | exit 0, no findings |
| `checkov` on `hardened.yaml` (cloudformation framework) | Passed 31, Failed 0, Skipped 1 (`CKV_AWS_18` on the log bucket) |
| `trivy config` on `hardened.yaml` | 0 misconfigurations |
| `hadolint Dockerfile.hardened` | exit 0, no findings |
| `checkov` on `Dockerfile.hardened` | Passed 9, Failed 0 |
| `trivy config --severity HIGH,CRITICAL Dockerfile.hardened` | 0 misconfigurations |
| `checkov` on `original.yaml` | Passed 3, Failed 13 |
| `trivy config` on `original.yaml` | 9 failures (HIGH 5, MEDIUM 1, LOW 3) |
| `checkov` on `Dockerfile.original` | Passed 7, Failed 2 (CKV_DOCKER_8, CKV_DOCKER_2) |
| `trivy config` on `Dockerfile.original` | 5 failures (CRITICAL 2, HIGH 2, LOW 1) |
| `hadolint Dockerfile.original` | 8 findings, exit non-zero |
| `tests/assert-originals-fail.sh` | 11 assertions, all held |
| `docker build` of `Dockerfile.hardened` | built, image size 208MB |
| `docker run --read-only --cap-drop=ALL --security-opt no-new-privileges` | health status went `starting` to `healthy` in 20 seconds. `/healthz` returned 200. `/proc/1/status` showed `CapEff` and `CapPrm` all zero and `NoNewPrivs: 1`. Writing to `/app` failed with "Read-only file system". The process ran as uid 10001. |
| Secret file mount | With `DB_PASSWORD_FILE` pointing at a mounted file, `/healthz` reported `db_secret_present: true`. Without it, `false`. |
| `docker history` of the hardened image | no match for password or API key |
| `trivy image` on the hardened image | Python packages: 0 findings. OS packages: 44 HIGH, 0 CRITICAL. None of the 44 has a fixed version available. With `--ignore-unfixed --severity HIGH,CRITICAL` the scan is clean. |

Notes on these results:

- **cfn-lint passes the original template.** It validates syntax and resource schema, and the original is a valid template. It is not a security scanner, so `assert-originals-fail.sh` asserts cfn-lint only on the hardened file. Checkov and trivy are the tools that reject the original.
- **The 44 OS findings are in the Debian base image** (util-linux, ncurses, systemd and similar libraries). The Debian tracker lists no fix at scan time. The image digest is pinned, so a rebuild on a newer digest is how they get fixed. This is the reason CI scans with `--ignore-unfixed`. The results will change as the vulnerability database changes.
- **Python findings were real and removed.** The first image scan found 4 HIGH findings in `msgpack`, `setuptools` and `urllib3`. They came from pip's vendored libraries and setuptools in the base image. The app does not need pip, so the Dockerfile removes pip, setuptools and wheel.

Verified only by static analysis or not run:

- The CloudFormation template was never deployed. No AWS account or credentials were used.
- The AWS CLI detection commands were not executed against an account. Only `--generate-cli-skeleton` and `help` ran, to confirm the commands and parameters exist in CLI 2.37.13.
- Prowler, `cfn-guard` and Conftest are not installed here and were not run.
- The Kubernetes `securityContext` was not applied to a cluster.
- The image was built and run locally and was not pushed anywhere.
- The legacy Docker builder was used (no buildx plugin here). The Dockerfile avoids BuildKit-only flags so it builds either way.

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
| `PREVENTION.md` | How to stop these mistakes from being introduced, by phase |
| `policies/` | Example AWS SCP and RCP (valid JSON, not tested in an account) |
| `scripts/find_risky_iam_users.py` | Offline finder for risky IAM users from the credential report and authorization details, with tests in `tests/` |
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

1. **The IAM user has `Action: "*"` on `Resource: "*"`.** That is full administrator access to the whole account, through an inline policy. Checkov fails 7 IAM checks on it (CKV_AWS_62, 63, 107, 108, 109, 110 and 111).
2. **A long-lived IAM user instead of a role.** A user means access keys or a password that do not expire and must be rotated by hand. A role gives short-lived credentials from STS. The policy is also attached to the user directly (trivy AWS-0143).
3. **The bucket does not declare any protection from public exposure.** There is no `PublicAccessBlockConfiguration` (trivy AWS-0086, 0087, 0091, 0093, 0094, all HIGH except 0094). In my sandbox test a bucket created from the original template did have all four block settings on, because S3 now turns them on for new buckets, and it refused a public bucket policy. The template still states nothing, so a bucket from an older account, another creation path or a later change is not covered.
4. **No encryption configuration.** S3 applies SSE-S3 by default, but nothing uses a customer-managed key, so there is no key policy, no key-level audit trail and no way to revoke access by disabling the key (trivy AWS-0132).
5. **No versioning.** An overwrite or delete cannot be undone (CKV_AWS_21, AWS-0090).
6. **No access logging.** Nothing records who read or wrote objects (CKV_AWS_18, AWS-0089).
7. **No TLS-only bucket policy.** Requests over plain HTTP are accepted. AWS Config rule `S3_BUCKET_SSL_REQUESTS_ONLY` marked the original bucket non-compliant.
8. **No ownership controls.** The template does not set `BucketOwnerEnforced`. In my sandbox test a new bucket from the original template already rejected ACLs, because S3 now defaults to that. Setting it in the template keeps the behaviour explicit.
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
- **What the trust conditions enforce, tested in a sandbox account.** The results are in "Trust policy test" below. In short: `ExternalId` and MFA work for a direct call by the trusted user. MFA does not carry through every role chain, so `RequireMfa` is the wrong setting for a role that a workload or another role assumes. `ExternalId` is a guard against a confused deputy. It is not a secret and it does not prove who the caller is.
- **The key policy only delegates to IAM** for this account. Access is then granted by the role policy. A stricter setup would name key administrators and key users in the key policy.

Verification of this template is in "What was verified".

## 3. Assuming the user exists: find it and fix it

### Finding it

Each item names the primitive. The commands are AWS CLI v2 commands. The status column says what I ran in a sandbox account and what I did not.

| Step | Primitive | Command | Status |
| --- | --- | --- | --- |
| 1 | IAM credential report: users, key age, last use | `aws iam generate-credential-report` then `aws iam get-credential-report --query Content --output text \| base64 -d` | Run in a sandbox account. The report listed the original user with `mfa_active` false and an active key with no last use recorded. The key had been used a few minutes earlier, so the last-use columns lag. Do not read "never used" from a report generated just after the key was used. |
| 2 | Who has an all-actions policy | `aws iam get-account-authorization-details --filter User Group LocalManagedPolicy --output json > authz.json`, then `jq -r '.UserDetailList[] \| select(.UserPolicyList[]?.PolicyDocument.Statement \| (if type=="array" then . else [.] end)[] \| select(.Action=="*" and .Resource=="*")) \| .UserName' authz.json` | Run in a sandbox account. The filter printed `UnrestrictedUser` and nothing else. It sees inline user policies only. `scripts/find_risky_iam_users.py` also covers group and managed policies. |
| 3 | Access Advisor: which services the user really used | `aws iam generate-service-last-accessed-details --arn <user-arn> --granularity ACTION_LEVEL` then `aws iam get-service-last-accessed-details --job-id <id>` | Run in a sandbox account. The job completed and listed 200 services with no last-access time for the original user, although the user had called S3 and STS a few minutes earlier, so this data lags too. The job takes a few seconds, so poll `JobStatus` before reading it. |
| 4 | IAM Access Analyzer unused access: finds unused users, roles, keys and permissions | `aws accessanalyzer create-analyzer --analyzer-name unused --type ACCOUNT_UNUSED_ACCESS --configuration '{"unusedAccess":{"unusedAccessAge":90}}'` then `aws accessanalyzer list-findings-v2 --analyzer-arn <arn>` | Analyzer created and queried in a sandbox account with an age of 1 day. It returned no findings, because the test identities were minutes old. The finding itself is not demonstrated. |
| 5 | Access Analyzer policy validation, run on the policy before deploy | `aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policy.json` | Run in a sandbox account. On the original policy it returned three findings: WARNING `MISSING_VERSION`, WARNING `CREATE_SLR_WITH_STAR_IN_ACTION_AND_RESOURCE` and SECURITY_WARNING `PASS_ROLE_WITH_STAR_IN_ACTION_AND_RESOURCE`. None is an ERROR, so a pipeline must fail on warnings to stop it. The hardened policy returned no findings. |
| 6 | AWS Config managed rules | `IAM_NO_INLINE_POLICY_CHECK` and `IAM_USER_NO_POLICIES_CHECK` flag the original user. `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` and `IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS` check customer-managed policies only. Also `IAM_USER_UNUSED_CREDENTIALS_CHECK`, `S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED`, `S3_BUCKET_SSL_REQUESTS_ONLY`, `S3_BUCKET_VERSIONING_ENABLED`, `S3_BUCKET_LOGGING_ENABLED`. Read results with `aws configservice get-compliance-details-by-config-rule`. | Run in a sandbox account. The inline-policy and no-user-policies rules marked the user non-compliant. The admin-access and full-access rules did not flag it: they reported only the customer-managed policies, as compliant. The S3 rules marked the original bucket non-compliant for TLS, versioning and logging, and the hardened data bucket compliant for all four. The hardened log bucket is non-compliant for logging only, which is the checkov skip. |
| 7 | Security Hub CSPM controls (AWS Foundational Security Best Practices and CIS) | Controls such as IAM.1 (no `*:*` policies), IAM.2 (no user policies), S3.1 to S3.5 and S3.9 | Not executed. |
| 8 | CloudTrail: what has the user done | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=UnrestrictedUser` (90 days of management events). For longer history, query the trail in Athena or CloudTrail Lake. | Run in a sandbox account. It listed the user's `GetCallerIdentity` and `ListBuckets` calls. Its IAM call (`ListUsers`) was not in this region's history, so check the region where IAM events are recorded. |
| 9 | Ad hoc sweep with an open-source scanner | Prowler, for example `prowler aws --services iam s3` | Prowler was not installed or run. |

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

See `PREVENTION.md`. It is organised by phase: development, pull request, deployment (pipeline and cloud policies), and runtime. It says which controls this repository implements and which it only describes.

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
- **The 44 OS findings are in the Debian base image** (util-linux, ncurses, systemd and similar libraries). The Debian tracker lists no fix at scan time. The image digest is pinned, so a rebuild on a newer digest is how they get fixed. This is the reason the CI image gate uses `--ignore-unfixed`. A separate CI step prints all 44 so they stay visible. The results will change as the vulnerability database changes.
- **Python findings were real and removed.** The first image scan found 4 HIGH findings in `msgpack`, `setuptools` and `urllib3`. They came from pip's vendored libraries and setuptools in the base image. The app does not need pip, so the Dockerfile removes pip, setuptools and wheel.

### Trust policy test

Run on 2026-10-14 in a sandbox AWS account (eu-north-1, not part of an AWS Organization). I deployed `hardened.yaml` as one stack and changed `TrustedPrincipalArn` and `RequireMfa` between runs. Callers were an IAM user with long-term keys and a virtual MFA device, a second user that is not trusted, and two roles used as chained callers (one reachable only with MFA, one reachable without). The account was empty before the test, and everything created for it was test-only.

| Trusted principal | `RequireMfa` | Caller | Result |
| --- | --- | --- | --- |
| The user | true | Long-term keys, no MFA | Refused |
| The user | true | Keys plus an MFA code on `assume-role` | Accepted |
| The user | true | Credentials from `get-session-token` with MFA | Accepted |
| The user | true | Right MFA but wrong or missing `ExternalId` | Refused |
| The user | true | A different user | Refused |
| The user | false | Long-term keys, right `ExternalId` | Accepted |
| The user | false | Long-term keys, no `ExternalId` | Refused |
| A role | true | Role reached with `get-session-token` MFA credentials | Accepted |
| A role | true | Role reached with `assume-role` plus an MFA code | Refused (reproduced three times) |
| A role | true | Role reached without MFA | Refused |
| A role | false | Role reached without MFA | Accepted |

What follows from this:

- **MFA carries through a role chain only in one case.** The MFA flag survives when the first hop used credentials from `get-session-token` with MFA. It does not survive when the MFA code was passed to `assume-role` itself. CloudTrail shows `mfaAuthenticated` true for the caller in the first case.
- **Workloads cannot meet an MFA condition.** A role session that nobody authenticated with MFA is refused when `RequireMfa` is `"true"`. Deploy a separate stack with `RequireMfa` set to `"false"` for workload callers, and rely on the `ExternalId`, the narrow principal and the session limit.
- **Service principals are not covered.** `TrustedPrincipalArn` accepts only user and role ARNs, so a service cannot be the trusted principal of this template. A role that a service runs as behaves like the role cases above.
- **Not tested:** IAM Identity Center sessions, EC2 or Lambda roles as callers, and the SCP and RCP examples in `policies/`. The account is not in an organization, so those policies cannot be attached.

The same run deployed the stack with each setting without error, including the log bucket that uses SSE-S3 and the bucket policy that lets the log service write to it. The data role could put and get an object, which S3 stored with SSE-KMS and the bucket key, and was refused when it tried to list the log bucket. Log files were not checked: S3 delivers them with a delay and the test was shorter than that.

### Detection and prevention test

Run on 2026-10-14 in the same sandbox account. I deployed the task's original template as its own stack, gave the user an access key, and ran the detection commands from section 3 on it. I also ran the prevention checks against the hardened stack.

| Check | Result |
| --- | --- |
| `scripts/find_risky_iam_users.py` on the real credential report and authorization details | Reported `UnrestrictedUser` as critical (inline policy `FullAccess` allows `Action *` on `Resource *`) and medium (key with no recorded use, which is the credential report lag described in section 3, step 1). Exit code 1. The other two test users, which have no wildcard policy, were not reported. |
| Original bucket, as created | All four public access block settings on, SSE-S3, no versioning. S3 applied the block settings by default. |
| TLS-only policy on the hardened data bucket | A `head-bucket` call over plain HTTP returned `403 Forbidden`. The same call over HTTPS worked. |
| Public bucket policy on the hardened data bucket | Refused with `AccessDenied`. |
| Public-read ACL on the hardened data bucket | Refused with `AccessDenied`. |
| Same two attempts on the original bucket | Policy refused with `AccessDenied`. ACL refused with "The bucket does not allow ACLs". S3's defaults did the blocking, not the template. |
| Account-level S3 Block Public Access | Turned on and the policy attempt repeated. It failed the same way as before, so the test cannot show what the account-level setting adds on top of the defaults. |
| Permission boundary | A role with `AdministratorAccess` attached and a boundary that allows only `s3:ListAllMyBuckets` was refused `iam:ListUsers` and could list buckets. The same role without a boundary could list users. |
| Requiring a boundary on role creation | An identity policy that allows `iam:CreateRole` only with the boundary in `iam:PermissionsBoundary`. Creating a role without the boundary was refused. Creating it with the boundary worked. |
| `validate-policy` on `policies/rcp-s3-tls-only.json` | No findings. |
| `validate-policy` on `policies/scp-deny-iam-users-and-admin.json` | The first version failed with `INVALID_ACTION`: `s3:DeleteBucketPublicAccessBlock` is not an AWS action. I removed it. The corrected file has no findings. |

Not tested: attaching the SCP or RCP (the account is not in an organization), CloudFormation Hooks, Security Hub, and the remediation sequence in section 3.

Verified only by static analysis or not run:

- The `cloud-check` and `cloud-check-image` CI jobs ran on GitHub and passed. The repository's gitleaks job failed on that run because of a download-checksum bug in the shared scaffold, which is fixed in another branch.
- The template was deployed only in a sandbox account for the trust policy test. It has not been deployed in an organization with SCPs or in any production-like setup.
- Security Hub and Prowler (detection steps 7 and 9) were not run.
- Prowler, `cfn-guard` and Conftest are not installed here and were not run.
- The Kubernetes `securityContext` was not applied to a cluster.
- The image was built and run locally and was not pushed anywhere.
- The legacy Docker builder was used (no buildx plugin here). The Dockerfile avoids BuildKit-only flags so it builds either way.

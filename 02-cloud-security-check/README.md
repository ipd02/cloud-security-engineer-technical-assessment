# Part 2: Cloud security check

This part reviews the task's CloudFormation template and Dockerfile. It answers the task questions in the task's order: what is wrong, an improved version, how to find and fix the existing user, and how to prevent the problems. The two original files are kept unchanged.

## What is in this folder

| Path | What it is |
| --- | --- |
| `cloudformation/original.yaml` | The task template, unchanged |
| `cloudformation/hardened.yaml` | The improved template |
| `docker/Dockerfile.original` | The task Dockerfile, unchanged |
| `docker/Dockerfile.hardened` | The improved Dockerfile |
| `docker/app.py`, `docker/.dockerignore` | A small demo web service for the image to run (the task gives no app code), and a file that keeps everything else out of the build |
| `tests/assert-originals-fail.sh` | Checks that the scanners reject the original files and accept the improved ones |
| `scripts/find_risky_iam_users.py` | Reads two AWS exports and lists risky users, roles and root account settings |
| `tests/test_find_risky_iam_users.py` and `tests/fixtures/` | Unit tests for that script, with made-up data |
| `scripts/ci-install-tools.sh` | Installs the pinned scanner versions in CI |
| `policies/` | Two example AWS policies that block the problems at account level |
| `PREVENTION.md` | How to stop these problems from being introduced |
| `part.mk` | Make targets for this part |

## How to run

From the repository root:

```sh
make cloud-check-lint    # cfn-lint and hadolint on the improved files
make cloud-check-scan    # checkov and trivy on the improved files
make cloud-check-test    # originals must fail, improved files must pass
make cloud-check-build   # build the improved image (needs docker)
```

Versions used: cfn-lint 1.57.2, checkov 3.3.20, hadolint 2.15.1, trivy 0.75.0, Docker 29.9.0, AWS CLI 2.37.13.

The two secret-looking values in `docker/Dockerfile.original` are the task's own sample values.

## 1. CloudFormation: what is wrong

The issues are listed in the order they appear in the template: the bucket first, then the IAM user. Each has a severity: **Critical** (full control of the account or data), **High** (a serious exposure), **Medium** (a weakness that makes a mistake or attack harder to stop or to detect), **Low** (good practice).

| # | Where | Issue | Why it matters | Severity |
| --- | --- | --- | --- | --- |
| 1 | Bucket | No public access block | Nothing in the template stops a policy or ACL from making the bucket public. S3 now turns this protection on for new buckets, and I confirmed that on a bucket made from this template. But the template does not say so, so an older account or a later change is not covered. | High |
| 2 | Bucket | No encryption setting | S3 encrypts new objects with its own keys by default, which I also confirmed. Without your own key there is no key-level audit log and no way to cut access by disabling the key. | Medium |
| 3 | Bucket | No versioning | An overwritten or deleted object cannot be recovered. | Medium |
| 4 | Bucket | No access logging | Nothing records who read or wrote objects. | Medium |
| 5 | Bucket | No rule that requires HTTPS | Requests over plain HTTP are accepted. | Medium |
| 6 | Bucket | No ownership setting | The template does not turn object ACLs off. S3 does this by default for new buckets, but the template does not say so. | Low |
| 7 | Bucket | No `DeletionPolicy` and no lifecycle rule | Deleting the stack deletes the bucket and its data. Old versions are never cleaned up. | Medium |
| 8 | IAM user | `Action: "*"` on `Resource: "*"` | The user can do anything in the whole account. | Critical |
| 9 | IAM user | A user instead of a role | A user has access keys that do not expire and must be rotated by hand. A role gives short-lived credentials. | High |
| 10 | IAM user | Fixed user name, no policy `Version`, no `Sid` | The template cannot be deployed twice and needs the extra `CAPABILITY_NAMED_IAM`. The policy uses the old policy language. | Low |

## 2. CloudFormation: the improved template

`cloudformation/hardened.yaml` replaces the user with a role and sets every bucket protection explicitly.

| Problem | What the improved template does |
| --- | --- |
| User with full access (8, 9) | A role, `DataAccessRole`, that people or other roles assume. A separate policy lists the allowed actions: read and write objects in this bucket, and use this one key. |
| Who may use the role | One principal, set with the `TrustedPrincipalArn` parameter. The caller must also give the `ExternalId` value, and by default must have signed in with MFA (`RequireMfa`). A session lasts at most one hour. |
| Public access (1) | All four public access block settings are on. |
| Encryption (2) | Objects are encrypted with your own KMS key, which rotates itself. |
| Versioning (3) | On. |
| Logging (4) | Access logs go to a separate log bucket. Only S3's logging service, acting for this bucket, may write there. |
| HTTPS (5) | A bucket policy refuses every request that does not use HTTPS. |
| Ownership (6) | `BucketOwnerEnforced`, so ACLs are off. |
| Deletion and cleanup (7) | The buckets and the key use `DeletionPolicy: Retain`, so deleting the stack does not delete the data. Old versions are removed after 90 days, logs after 365 days (both can be changed), and unfinished uploads after 7 days. |
| Parameters | Each parameter has a type, a description and limits on what it accepts. |

A few choices need an explanation:

- **The log bucket uses S3-managed encryption, not the KMS key.** AWS documents that the bucket receiving S3 access logs must use S3-managed encryption.
- **One scanner rule is skipped, on the log bucket only.** The rule asks for access logging on every bucket. Logging the log bucket would need another log bucket, and so on. The skip and its reason are written in the template.
- **The key policy only hands control to IAM in this account.** The role's policy then grants the access.
- **There is no fixed bucket name.** CloudFormation picks a unique one, so the template can be used in many stacks.

### What the trust settings do

`ExternalId` is a shared value, not a secret. It makes the caller prove it was given the value, which protects against a third party tricking a service into using the role.

MFA works for a person who calls the role directly. It does not work for workloads, because nobody signs a workload in with MFA. I tested this with real callers in a test AWS account (see "Trust policy test" below). The result: use the default (`RequireMfa` true) for the role that people use, and deploy a second stack with `RequireMfa` set to `"false"` for workloads.

## 3. The user already exists: find it and fix it

### Finding it

Each row is one way to find a user like this. The result column says what happened when I ran it in a test AWS account against the task's original template.

| Step | What it does | Command | Result |
| --- | --- | --- | --- |
| 1 | Credential report: every user, whether it has MFA, and its keys | `aws iam generate-credential-report` then `aws iam get-credential-report --query Content --output text \| base64 -d` | Listed the user with no MFA and an active key. The "last used" columns lag by minutes, so a key used a moment ago can show as never used. |
| 2 | Find users that have a policy allowing everything | `aws iam get-account-authorization-details --filter User Group LocalManagedPolicy --output json > authz.json`, then `jq -r '.UserDetailList[] \| select(.UserPolicyList[]?.PolicyDocument.Statement \| (if type=="array" then . else [.] end)[] \| select(.Action=="*" and .Resource=="*")) \| .UserName' authz.json` | Printed `UnrestrictedUser` and nothing else. This filter reads inline user policies only. |
| 3 | Access Advisor: which services a user actually used | `aws iam generate-service-last-accessed-details --arn <user-arn> --granularity ACTION_LEVEL` then `aws iam get-service-last-accessed-details --job-id <id>` | The job finished after a few seconds. Its data also lags, so it showed no use for a user that had just called S3 and STS. |
| 4 | Access Analyzer unused access: users, roles and keys nobody uses | `aws accessanalyzer create-analyzer --analyzer-name unused --type ACCOUNT_UNUSED_ACCESS --configuration '{"unusedAccess":{"unusedAccessAge":90}}'` then `aws accessanalyzer list-findings-v2 --analyzer-arn <arn>` | Created and queried. It reports identities that have been unused for the set number of days, so it has nothing to report for identities that are minutes old. |
| 5 | Access Analyzer policy check, before deploying a policy | `aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policy.json` | The original policy got three warnings (no policy `Version`, a wildcard that allows creating service-linked roles, a wildcard on `iam:PassRole`) and no errors. The improved policy got none. A pipeline has to fail on warnings to stop the original. |
| 6 | AWS Config rules: continuous checks | `IAM_NO_INLINE_POLICY_CHECK` and `IAM_USER_NO_POLICIES_CHECK` find the user. `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` only looks at customer-managed policies, so it does not. Bucket rules: `S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED`, `S3_BUCKET_SSL_REQUESTS_ONLY`, `S3_BUCKET_VERSIONING_ENABLED`, `S3_BUCKET_LOGGING_ENABLED`. Read results with `aws configservice get-compliance-details-by-config-rule`. | The two user rules marked the user non-compliant. The bucket rules marked the original bucket non-compliant for HTTPS, versioning and logging, and the improved data bucket compliant for all four. |
| 7 | CloudTrail: what the user did | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=UnrestrictedUser` | Listed the user's S3 and STS calls. The user's IAM call did not show up in this region's history. |

At larger scale, AWS Security Hub (controls IAM.1 and IAM.2) and the open-source scanner Prowler do the same checks across many accounts.

For this template the fastest route is steps 2 and 7: list who has a policy that allows everything, then see what that user actually did.

### The finder script

`scripts/find_risky_iam_users.py` reads the exports from steps 1 and 2 and lists risky users, roles and root account settings, worst first. Add `Role` to the `--filter` of step 2 to include roles. It reports:

- **Critical:** a policy that allows every action on every resource, the `AdministratorAccess` policy, or an active root access key.
- **High:** `iam:*` on every resource, the `IAMFullAccess` policy, a console password without MFA, or a root account without MFA.
- **Medium:** another `service:*` wildcard on every resource, and access keys that are old or unused.

It exits with code 1 when it finds something at or above `--fail-on`, and with code 2 and a one-line message when an input file cannot be read or is the wrong kind of file. On the test account it reported `UnrestrictedUser` as critical.

### What the checks look at

The jq filter, the finder and the Config rules read policies as they are written. They do not combine them with the things that change what a user can really do:

- a `Deny` statement or a condition in a policy,
- a permission boundary, which caps what a user or role can be given (I showed this in the test below: a role with `AdministratorAccess` could not list IAM users once a boundary was set),
- a service control policy (SCP), which caps every user and role in an AWS Organizations account.

To see the real permissions of one user or role, use the IAM policy simulator (`aws iam simulate-principal-policy`) or IAM Access Analyzer. Treat the finder's list as a list of leads to check.

### Fixing it safely

1. **Inventory.** Use steps 1, 3 and 7 to find which keys exist, what the user used, and which systems hold its keys.
2. **Create the replacement.** Deploy `hardened.yaml`. The role now exists beside the user, and nothing breaks.
3. **Switch the users of the keys, one at a time.** Each one assumes the role instead of using the user's keys. Workloads use roles with OIDC or instance profiles.
4. **Give only what is needed.** If something needs more than the role allows, add the specific actions that Access Advisor shows. Do not copy the old wildcard. Access Analyzer can write a policy from CloudTrail activity (`aws accessanalyzer start-policy-generation`).
5. **Retire the user.** Set its keys to inactive (`aws iam update-access-key --status Inactive`). Wait one release cycle and watch CloudTrail for failures. Then delete the keys, the policy and the user. In the test account, a call with the inactive key failed, and deleting the key, the policy and the user worked.
6. **Block it from coming back.** Add a service control policy that denies creating IAM users and access keys, and attaching `AdministratorAccess`, outside an approved admin role. `policies/scp-deny-iam-users-and-admin.json` is an example.

## 4. Dockerfile

### 4.1 What is wrong

The issues are listed in the order they appear in the Dockerfile. Severity uses the same scale as section 1.

| # | In `Dockerfile.original` | Why it matters | Severity |
| --- | --- | --- | --- |
| 1 | `FROM ubuntu:18.04` | Ubuntu 18.04 no longer gets standard security updates. The tag can also change, so two builds can differ. | High |
| 2 | `USER root` | A bug in the app gives root inside the container. | High |
| 3 | Installs `curl`, `vim`, `dnsutils`, `python3-pip` | Each extra program adds vulnerabilities and gives an attacker more tools. | Medium |
| 4 | `apt-get install` with no `--no-install-recommends`, no cleanup and no pinned versions | A larger image that keeps the package lists. | Low |
| 5 | `ENV DB_PASSWORD=...` and `ENV API_KEY=...` | Anyone who can pull the image can read these values with `docker inspect` or `docker history`. They stay in the image even if a later step removes them. | Critical |
| 6 | `COPY . /app` with no `.dockerignore` | Copies everything in the folder into the image, including `.git`, `.env` files and keys. | High |
| 7 | `chmod -R 777 /app` | Every user and process can change the code. | Medium |
| 8 | `EXPOSE 80` | A port below 1024 needs root or an extra permission to open. | Low |
| 9 | `CMD python3 app.py` | The shell form starts the app through a shell, so a stop signal may not reach it. | Low |
| 10 | No `HEALTHCHECK` | Docker cannot tell a stuck container from a healthy one. | Low |

### 4.2 How each issue is fixed

The fixes are in `docker/Dockerfile.hardened`. The numbers match the table above.

**1. Base image.** Use `python:3.13-slim-trixie`, pinned by digest. From the Dockerfile, the app only needs Python (`CMD python3 app.py`), and this image already has it, so no `apt` step is needed. The digest makes every build use the same image. Someone has to update it on purpose to get new fixes.

The task does not include the app, so the improved Dockerfile runs a small demo app. If the real app needs something different, change the base like this:

- **An older Python version** (an old library or tool needs it, or any other reason). Use the official image for that version, pinned by digest. The risk is that old versions get no security fixes, so known vulnerabilities stay open. Keep every other fix, run it with the flags in issue 2, allow only the network connections it needs, scan with `trivy image` on a schedule, and plan the upgrade with an owner and a date.
- **Ubuntu** (the app needs an Ubuntu package or tool). Use a release that is still supported, such as `ubuntu:24.04`, pinned by digest. Install `python3` and only what the app needs in one `apt` step (see issue 4). The risk is a bigger base with more packages to patch, so rebuild and scan often. If 18.04 itself has to stay, Ubuntu Pro sells security updates for the system packages. They do not cover the app's own libraries.
- **In every case,** run the real app's tests and the same scanner checks on the new image. Code written for Python 3.6 can break on 3.13. If the app has a `requirements.txt`, install it in a first build stage, pin the versions, and copy only the result into the final image.

**2. Root user.** Create a user with a number (`10001`), no shell and no home folder, and switch to it with `USER`. Also start the container with settings that limit what it can do:

```sh
docker run -d --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 8080:8080 cloud-check-hardened:local
```

- `--cap-drop=ALL` removes the extra Linux privileges a container has by default.
- `--security-opt no-new-privileges` stops a process from gaining more privileges later.
- `--read-only` makes the container's filesystem read-only (see issue 7).
- Docker applies its default seccomp profile, which blocks risky system calls. Do not pass `--security-opt seccomp=unconfined`.

In Kubernetes the same settings are `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]` and `seccompProfile.type: RuntimeDefault`.

**3. Extra tools.** The demo app needs none of them, so nothing is installed, and pip is removed because nothing in the running container needs it. The health check uses Python instead of `curl`. If the real app does need a tool, such as `curl` or `dig`, add back only that package. Do not add back `vim`. The demo app has no build step, so the Dockerfile has one stage. With packages to install, use a first stage as described in issue 1.

**4. `apt` options.** The improved Dockerfile has no `apt` step, so there is nothing to fix. If one is needed, install with `--no-install-recommends`, pin versions where practical, and remove the package lists (`rm -rf /var/lib/apt/lists/*`) in the same `RUN` step.

**5. Secrets.** The image holds no secret. Give the secret to the running container instead:

- **Docker or Compose:** mount a file, for example `-v ./secret:/run/secrets/db_password:ro -e DB_PASSWORD_FILE=/run/secrets/db_password`.
- **Kubernetes:** use a Secret volume, or the Secrets Store CSI driver with AWS Secrets Manager, GCP Secret Manager or HashiCorp Vault.
- **ECS:** use the `secrets` field of the task definition with a Secrets Manager or SSM Parameter Store ARN.

A file is better than an environment variable, because it does not show up in `docker inspect`. The demo app reads the path from `DB_PASSWORD_FILE`, logs that it read the file, and never logs or returns the value. Treat the two values in the task's Dockerfile as leaked and change them. They are in the image history wherever that image was pushed.

**6. Copying everything.** `.dockerignore` excludes everything except `app.py`, and `COPY` names that one file.

**7. World-writable files.** `app.py` belongs to root and is read-only (mode `0444`), so the app user cannot change it. The `--read-only` flag in issue 2 protects the rest of the filesystem. If the app needs scratch space, add `--tmpfs /tmp` instead of making the whole filesystem writable.

**8. Port 80.** The app listens on port 8080, which any user can open.

**9. Shell form.** Use the list form: `CMD ["python", "/app/app.py"]`. The app then receives stop signals directly.

**10. Health check.** A `HEALTHCHECK` calls `/healthz` with Python. Kubernetes ignores the Dockerfile `HEALTHCHECK`, so set a `readinessProbe` on `/healthz` there.

## 5. Preventing both problems

See `PREVENTION.md`. It follows a change through four phases (development, pull request, deployment, runtime) and names a concrete control for each, including policies that make the problem impossible in AWS.

## What was checked

Everything below was run while building this part. The image checks apply to the demo app, not to the task's real app. The scanners and Docker ran on a Mac. The AWS tests ran in a test AWS account on 2026-10-14, and everything created for them was deleted afterwards.

### Scanners and image

| Check | Result |
| --- | --- |
| `cfn-lint` on `hardened.yaml` | No findings |
| `checkov` on `hardened.yaml` | 31 passed, 0 failed, 1 skipped (the log bucket rule explained in section 2) |
| `trivy config` on `hardened.yaml` | 0 findings |
| `hadolint` on `Dockerfile.hardened` | No findings |
| `checkov` and `trivy config` on `Dockerfile.hardened` | 9 passed, 0 failed. 0 findings. |
| `checkov` on the originals | `original.yaml`: 3 passed, 13 failed. `Dockerfile.original`: 7 passed, 2 failed. |
| `trivy config` on the originals | `original.yaml`: 9 findings (5 high). `Dockerfile.original`: 5 findings (2 critical, 2 high). |
| `hadolint` on `Dockerfile.original` | 8 findings |
| `tests/assert-originals-fail.sh` | 11 checks, all held. Each "must fail" check also looks for a named rule, so a crash does not count. |
| Image build and run with the flags in issue 2 | Healthy within seconds, `/healthz` returns 200, runs as user 10001 with no capabilities, and writing to `/app` fails (read-only). |
| Secret file | With `DB_PASSWORD_FILE` pointing at a mounted file, the app logs that it read the file. The value is never in the logs or in a response. |
| `docker history` of the image | No password or key in it |
| `trivy image` | No Python findings. 44 high findings in the Debian base image, and none of them has a fix yet. With `--ignore-unfixed` the scan is clean. |
| CI | The `cloud-check` and `cloud-check-image` jobs pass on GitHub. |

Two notes on these results:

- **cfn-lint accepts the original template.** It checks that a template is valid, and the original is valid. It is not a security scanner, so the test script runs it only on the improved template. Checkov and trivy are the tools that reject the original.
- **The 44 high findings are in the Debian base image** (system libraries such as util-linux and systemd). Debian has not published fixes for them. The image is pinned by digest, so building on a newer digest picks up fixes when they appear. CI fails only on findings that have a fix, and a separate CI step prints all 44.

### Trust policy test

I deployed `hardened.yaml` in a test AWS account and changed `TrustedPrincipalArn` and `RequireMfa` between runs. The callers were an IAM user with a virtual MFA device, a second user that is not trusted, and two roles used as middle steps in a chain (one reachable only with MFA, one reachable without it).

| Trusted principal | `RequireMfa` | Caller | Result |
| --- | --- | --- | --- |
| The user | true | Access keys, no MFA | Refused |
| The user | true | Access keys plus an MFA code on `assume-role` | Accepted |
| The user | true | Credentials from `get-session-token` with MFA | Accepted |
| The user | true | MFA, but the wrong or no `ExternalId` | Refused |
| The user | true | A different user | Refused |
| The user | false | Access keys, right `ExternalId` | Accepted |
| The user | false | Access keys, no `ExternalId` | Refused |
| A role | true | Role reached with `get-session-token` MFA credentials | Accepted |
| A role | true | Role reached with `assume-role` plus an MFA code | Refused |
| A role | true | Role reached without MFA | Refused |
| A role | false | Role reached without MFA | Accepted |

What this shows:

- **MFA passes through a chain of roles in only one case.** It does when the first step used credentials from `get-session-token` with MFA. It does not when the MFA code was given to `assume-role` itself.
- **A workload cannot meet an MFA condition.** Use a second stack with `RequireMfa` set to `"false"` for workloads.
- **`TrustedPrincipalArn` takes a user or role ARN.** An AWS service runs as a role, so it behaves like the role rows.

The data role could put and get an object (S3 stored it encrypted with the KMS key) and was refused when it tried to list the log bucket. The stack deployed with every setting, including the log bucket and the policy that lets S3's logging service write to it.

### Detection and prevention test

I deployed the task's original template as its own stack in the same account and ran the commands from section 3. I ran the prevention checks against the improved stack.

| Check | Result |
| --- | --- |
| Finder script on the real exports | Reported `UnrestrictedUser` as critical (a policy allowing every action on every resource) and listed its key as never used (the report lags, see step 1). The other two test users, which have no wildcard policy, were not reported. |
| The original bucket as created | All four public access block settings on, S3-managed encryption, no versioning. |
| HTTPS rule on the improved bucket | A request over plain HTTP returned `403 Forbidden`. The same request over HTTPS worked. |
| Public bucket policy on the improved bucket | Refused |
| Public ACL on the improved bucket | Refused |
| The same two attempts on the original bucket | Both refused. S3's defaults did the blocking, not the template. |
| Permission boundary | A role with `AdministratorAccess` and a boundary that allows only `s3:ListAllMyBuckets` could not list IAM users, but could list buckets. Without the boundary it could list users. |
| Requiring a boundary when roles are created | An identity policy that allows `iam:CreateRole` only with the boundary set. Creating a role without it was refused. With it, the role was created. |
| Retiring the user | Setting the key inactive made a call with it fail. Deleting the key, the policy and the user worked. |
| Access Analyzer on `policies/rcp-s3-tls-only.json` | No findings |
| Access Analyzer on `policies/scp-deny-iam-users-and-admin.json` | One error at first: `s3:DeleteBucketPublicAccessBlock` is not an AWS action. I removed it, and the file now has no findings. |

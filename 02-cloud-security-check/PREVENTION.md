# Prevention: stopping these misconfigurations from being introduced

The two inputs have the same root causes: a wildcard admin identity, a long-lived credential, a public-capable unencrypted bucket, a root container and secrets in the image. Each layer below names the primitive that blocks one or more of them. A mistake that slips past one layer should hit the next.

This repository demonstrates the developer machine, pull request and pipeline layers through its own pre-commit config and CI. The other layers are described here. They are not implemented in this repository.

## 1. Developer machine

| Primitive | Catches |
| --- | --- |
| `pre-commit` with `gitleaks` | Hardcoded secrets such as the `ENV` values, before they enter history |
| `hadolint` hook | Root user, missing `--no-install-recommends`, shell-form `CMD`, secrets in `ENV` |
| `cfn-lint` hook | Invalid or deprecated CloudFormation |
| `tflint` and `terraform fmt` hooks | Same for Terraform (Part 1) |
| `detect-private-key`, `check-added-large-files` | Keys and stray artifacts |
| `.dockerignore` and `.gitignore` | `.env`, keys and `.git` copied into an image |

This repo's `.pre-commit-config.yaml` carries these hooks. Local checks are advisory, since a developer can skip them, so every one is repeated in the next layer.

## 2. Pull request

| Primitive | Catches |
| --- | --- |
| Required status checks: cfn-lint, hadolint, `checkov`, `trivy config`, gitleaks | The same issues, enforced and not skippable |
| Policy as code: Open Policy Agent with Conftest, or AWS CloudFormation Guard (`cfn-guard`) | Custom rules such as "no IAM statement with `Action: *`", "every bucket has a public access block", "image must not run as root" |
| `CODEOWNERS` on `**/iam*`, `cloudformation/`, `Dockerfile*`, `.github/workflows/` plus required reviews | A second person reads every security-sensitive change |
| Signed commits and protected branches | Attribution, and no direct push to the main branch |
| `iam:` policy checks in CI with IAM Access Analyzer `validate-policy` and `check-no-new-access` | New access that a change would grant |

A `cfn-guard` rule for this template would look like this:

```
rule no_wildcard_iam_actions {
  Resources.*[ Type in ["AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy"] ]
    .Properties.*.PolicyDocument.Statement[ Effect == "Allow" ] {
      Action != "*"
    }
}
```

It is shown as an example of the primitive. It was not run here, because `cfn-guard` is not installed.

## 3. Pipeline

| Primitive | Catches |
| --- | --- |
| Workflow `permissions: {}` at the top, `contents: read` per job | A compromised step cannot write to the repository |
| OIDC federation: the pipeline assumes an IAM role (`aws-actions/configure-aws-credentials` with `role-to-assume`) or a GCP workload identity pool | No stored long-lived cloud keys, which removes the "IAM user" pattern from CI |
| Separate build and deploy identities, and trust policy conditions on repository, branch and environment (`token.actions.githubusercontent.com:sub`) | A pull request build cannot deploy |
| Protected deployment environments with required reviewers | A human approves production changes |
| Actions pinned to a full commit SHA | Tag hijack of a third-party action |
| Dependabot or Renovate for actions, base images and packages | Stale base images and tools |
| `docker build` followed by `trivy image` and a failing threshold | Known CVEs in the image before it ships |

## 4. Artifact

| Primitive | Catches |
| --- | --- |
| Pin base images by digest | Silent base image changes |
| Sign images with Sigstore Cosign (keyless, OIDC identity) and attach provenance (SLSA attestation, SBOM from `trivy` or `syft`) | Images that did not come from the pipeline |
| Admission control in the cluster: Kyverno, OPA Gatekeeper or the Sigstore policy-controller | Rejects unsigned images, root users, privileged pods, `latest` tags |
| Private registry with immutable tags and scanning on push (ECR, Artifact Registry) | Tag overwrite and unscanned images |
| Pod Security Admission at the `restricted` level | Pods without a non-root user, dropped capabilities or seccomp |

## 5. Cloud guardrails

| Primitive | Catches |
| --- | --- |
| AWS Organizations Service Control Policies. Examples: deny `iam:CreateUser` and `iam:CreateAccessKey` outside a break-glass role, deny `s3:PutBucketPublicAccessBlock` changes that disable it, deny leaving the approved regions | Makes the original template impossible to deploy even with admin rights in a member account |
| GCP Organization Policy constraints (for example `iam.disableServiceAccountKeyCreation`, `storage.publicAccessPrevention`) | The GCP equivalent of the same classes of mistake |
| S3 account-level Block Public Access (`aws s3control put-public-access-block`) | Public buckets regardless of bucket settings |
| AWS Config rules and conformance packs, with auto-remediation through SSM Automation | Drift from the baseline after deploy |
| Security Hub CSPM (AWS Foundational Security Best Practices, CIS) | Aggregated findings across accounts |
| CloudFormation Hooks (for example a Guard hook) and Service Catalog | Rejects a non-compliant stack at deploy time |
| Separate accounts or projects for dev, staging and production, with their own roles | A mistake in one environment does not reach another |
| IAM permission boundaries on roles that teams can create | Developers cannot grant themselves more than the boundary allows |

## 6. Runtime

Run containers with a read-only root filesystem, all capabilities dropped, `no-new-privileges` and the default seccomp profile. Add an AppArmor or SELinux profile where the host supports it. In Kubernetes, enforce this through the `securityContext` and Pod Security Admission. For detection, use a runtime sensor such as Falco rules (shell in a container, write below `/etc`, unexpected outbound connection) or an EDR agent on the nodes. This repository does not implement runtime detection. `README.md` shows only the flags and a manifest.

## 7. Detection and response

| Primitive | Purpose |
| --- | --- |
| CloudTrail organisation trail in a dedicated log archive account, with log file validation and S3 Object Lock | Immutable audit record |
| GCP Cloud Audit Logs with a locked log bucket sink | Same on GCP |
| EventBridge rules or CloudWatch metric filters on `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `DeleteTrail`, `StopLogging` | Alert on privilege changes within minutes |
| GuardDuty (credential and anomaly findings) and Access Analyzer external-access findings | Compromise and exposure detection |
| IAM Access Analyzer unused access findings on a schedule | Retires stale users and permissions |
| Runbooks: disable the key (`aws iam update-access-key --status Inactive`), attach a deny-all policy, review CloudTrail, rotate | A tested response when a key leaks |

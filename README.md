# yakkai-policies

OPA / [Conftest](https://www.conftest.dev) policy library evaluated by the
`policy-check` stage of a [YakkAI](https://github.com/GuhaTek/yakkai)-managed
GitHub Actions pipeline. Public on purpose: the Rego here contains logic only.
**Which** rules apply to a repository, their severity and their parameters are
edited in the YakkAI UI and stored in that repository as
`.yakkai/policies/<stage>.json`:

```json
{
  "stage": "deploy-helm",
  "policies": [
    {"id": "no-privileged", "type": "k8s.no_privileged", "severity": "block", "params": {}},
    {"id": "registry", "type": "image.allowed_registries", "severity": "block",
     "params": {"allow": ["ghcr.io/guhatek/"]}}
  ]
}
```

`severity: block` fails the pipeline job; `warn` only reports.

| File | Package | Input | Policy file |
|------|---------|-------|-------------|
| `rego/k8s.rego` | `yakkai.k8s` | rendered Helm output / Kubernetes YAML | `.yakkai/policies/deploy-helm.json` |
| `rego/dockerfile.rego` | `yakkai.dockerfile` | Dockerfile (`--parser dockerfile`) | `.yakkai/policies/container-build.json` |

## Rule types

| Type | Params |
|------|--------|
| `k8s.no_privileged` | – |
| `k8s.run_as_non_root` | – |
| `k8s.resource_limits_required` | `kinds` |
| `k8s.no_latest_tag` | – |
| `k8s.required_labels` | `labels` |
| `image.allowed_registries` | `allow` |
| `dockerfile.no_latest_base` | – |
| `dockerfile.allowed_base_registries` | `allow` |

The rule-type catalog the YakkAI UI offers (`POLICY_TYPES` in
`backend/app/services/iac/gha_pipeline.py` of the YakkAI repo) must match the
`p.type` strings in these files. Adding a rule type means a change in both repos
and a new tag here.

## Versioning

Pipelines fetch this repository at a **tag** (`POLICY_REF`, e.g. `v1.0.0`) and
verify the checked-out commit against a **SHA** (`POLICY_SHA`) recorded in the
workflow, so a moved tag fails the job instead of silently changing behaviour.
Behaviour changes ship under a new tag; old tags keep evaluating exactly as before.

## Run locally

```bash
conftest verify -p rego
conftest test rendered.yaml -p rego -n yakkai.k8s -d .yakkai/policies/deploy-helm.json
conftest test Dockerfile --parser dockerfile -p rego -n yakkai.dockerfile -d .yakkai/policies/container-build.json
```

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

### Kubernetes (`deploy-helm`)

Pod Security Standards *baseline* and *restricted* checks, plus operational hygiene.

| Type | Checks | Params |
|------|--------|--------|
| `k8s.no_privileged` | no `privileged: true` container | – |
| `k8s.no_privilege_escalation` | every container sets `allowPrivilegeEscalation: false` | – |
| `k8s.run_as_non_root` | `runAsNonRoot: true` on the container or pod | – |
| `k8s.drop_all_capabilities` | capabilities drop `ALL`; only listed capabilities may be added | `allowed_add` |
| `k8s.read_only_root_fs` | `readOnlyRootFilesystem: true` | – |
| `k8s.seccomp_required` | `seccompProfile.type` is `RuntimeDefault` or `Localhost` | – |
| `k8s.no_host_namespaces` | no `hostNetwork` / `hostPID` / `hostIPC` | – |
| `k8s.no_host_path` | no `hostPath` volumes | – |
| `k8s.no_host_ports` | no `hostPort` on containers | – |
| `k8s.no_automount_sa_token` | `automountServiceAccountToken: false` on workloads | – |
| `k8s.resource_limits_required` | cpu and memory limits on the listed kinds | `kinds` |
| `k8s.resource_requests_required` | cpu and memory requests on the listed kinds | `kinds` |
| `k8s.probes_required` | liveness and readiness probes on the listed kinds | `kinds` |
| `k8s.no_latest_tag` | images pinned to a tag other than `latest`, or a digest | – |
| `image.allowed_registries` | images start with one of the listed prefixes | `allow` |
| `k8s.required_labels` | every object carries the listed labels | `labels` |
| `k8s.no_default_namespace` | nothing deployed into `default` | – |
| `k8s.no_secrets_in_env` | no literal env value whose name matches a pattern | `patterns` |
| `k8s.service_types` | Service `type` is in the allowed list | `allow` |
| `k8s.ingress_tls_required` | every Ingress has a `tls` section | – |
| `k8s.deny_wildcard_rbac` | no `*` in Role/ClusterRole verbs, resources or apiGroups | – |

### Dockerfile (`container-build`)

| Type | Checks | Params |
|------|--------|--------|
| `dockerfile.no_latest_base` | `FROM` images pinned (scratch and stage aliases ignored) | – |
| `dockerfile.allowed_base_registries` | `FROM` images start with one of the listed prefixes | `allow` |
| `dockerfile.user_required` | final stage sets a non-root `USER` | – |
| `dockerfile.no_add` | `COPY` instead of `ADD` | – |
| `dockerfile.no_sudo` | no `sudo` in `RUN` | – |
| `dockerfile.no_curl_pipe_sh` | no `curl \| sh` / `wget \| bash` in `RUN` | – |
| `dockerfile.apt_get_hygiene` | `apt-get install` uses `--no-install-recommends` and cleans `/var/lib/apt/lists` | – |
| `dockerfile.no_secrets_in_env` | no `ENV` / defaulted `ARG` whose name matches a pattern | `patterns` |
| `dockerfile.healthcheck_required` | a `HEALTHCHECK` instruction exists | – |
| `dockerfile.forbidden_ports` | none of the listed ports is `EXPOSE`d | `ports` |

The rule-type catalog the YakkAI UI offers (`POLICY_TYPES` in
`backend/app/services/iac/gha_pipeline.py` of the YakkAI repo) must match the
`p.type` strings in these files. Adding a rule type means a change in both repos
and a new tag here.

## Versioning

Pipelines fetch this repository at a **tag** (`POLICY_REF`, e.g. `v1.1.0`) and
verify the checked-out commit against a **SHA** (`POLICY_SHA`) recorded in the
workflow, so a moved tag fails the job instead of silently changing behaviour.
Behaviour changes ship under a new tag; old tags keep evaluating exactly as before.

| Tag | Contents |
|-----|----------|
| `v1.0.0` | 8 rule types (privileged, non-root, limits, latest tag, labels, registries, base image pinning/registries) |
| `v1.1.0` | 31 rule types: full PSS baseline/restricted set, hygiene checks, Dockerfile hardening |

## Run locally

```bash
conftest verify -p rego
conftest test rendered.yaml -p rego -n yakkai.k8s -d .yakkai/policies/deploy-helm.json
conftest test Dockerfile --parser dockerfile -p rego -n yakkai.dockerfile -d .yakkai/policies/container-build.json
```

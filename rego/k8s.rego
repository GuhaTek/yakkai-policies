# YakkAI policy library: Kubernetes manifests (rendered Helm output or plain YAML).
#
# Logic lives here; the rules that are switched on, their severity and their
# parameters come from the repo's `.yakkai/policies/deploy-helm.json`, passed to
# conftest with `--data`. Each entry there is {id, type, severity, params}.
package yakkai.k8s

policies := data.policies

# ---- pod spec extraction -------------------------------------------------

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains c if some c in pod_spec.containers

containers contains c if some c in pod_spec.initContainers

subject := sprintf("%s/%s", [input.kind, input.metadata.name])

# ---- findings: one rule body per policy type ----------------------------

finding contains f if {
	some p in policies
	p.type == "k8s.no_privileged"
	some c in containers
	c.securityContext.privileged == true
	f := {"id": p.id, "msg": sprintf("%s: container %q runs privileged", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.run_as_non_root"
	some c in containers
	not runs_as_non_root(c)
	f := {"id": p.id, "msg": sprintf("%s: container %q does not set runAsNonRoot", [subject, c.name])}
}

runs_as_non_root(c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(_) if pod_spec.securityContext.runAsNonRoot == true

finding contains f if {
	some p in policies
	p.type == "k8s.resource_limits_required"
	input.kind in p.params.kinds
	some c in containers
	not c.resources.limits.cpu
	f := {"id": p.id, "msg": sprintf("%s: container %q has no cpu limit", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.resource_limits_required"
	input.kind in p.params.kinds
	some c in containers
	not c.resources.limits.memory
	f := {"id": p.id, "msg": sprintf("%s: container %q has no memory limit", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.no_latest_tag"
	some c in containers
	unpinned(c.image)
	f := {"id": p.id, "msg": sprintf("%s: image %q is not pinned to a tag or digest", [subject, c.image])}
}

unpinned(img) if endswith(img, ":latest")

unpinned(img) if {
	not contains(img, "@")
	parts := split(img, "/")
	not contains(parts[count(parts) - 1], ":")
}

finding contains f if {
	some p in policies
	p.type == "k8s.required_labels"
	input.kind
	some l in p.params.labels
	not input.metadata.labels[l]
	f := {"id": p.id, "msg": sprintf("%s: missing label %q", [subject, l])}
}

finding contains f if {
	some p in policies
	p.type == "image.allowed_registries"
	some c in containers
	not registry_allowed(c.image, p.params.allow)
	f := {"id": p.id, "msg": sprintf("%s: image %q is not from an allowed registry", [subject, c.image])}
}

registry_allowed(img, allow) if {
	some a in allow
	startswith(img, a)
}

# ---- severity routing ----------------------------------------------------

deny contains msg if {
	some p in policies
	p.severity == "block"
	some f in finding
	f.id == p.id
	msg := sprintf("[%s] %s", [p.id, f.msg])
}

warn contains msg if {
	some p in policies
	p.severity == "warn"
	some f in finding
	f.id == p.id
	msg := sprintf("[%s] %s", [p.id, f.msg])
}

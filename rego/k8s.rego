# YakkAI policy library: Kubernetes manifests (rendered Helm output or plain YAML).
#
# Logic lives here; the rules that are switched on, their severity and their
# parameters come from the repo's `.yakkai/policies/deploy-helm.json`, passed to
# conftest with `--data`. Each entry there is {id, type, severity, params}.
# Rule types mirror the Pod Security Standards (baseline / restricted) plus
# common operational hygiene checks.
package yakkai.k8s

policies := data.policies

# ---- pod spec extraction -------------------------------------------------

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains c if some c in pod_spec.containers

containers contains c if some c in pod_spec.initContainers

# main containers only (probes make no sense on init containers)
app_containers contains c if some c in pod_spec.containers

subject := sprintf("%s/%s", [input.kind, input.metadata.name])

seccomp_types := {"RuntimeDefault", "Localhost"}

# ---- findings: one rule body per policy type ----------------------------

# -- privilege --

finding contains f if {
	some p in policies
	p.type == "k8s.no_privileged"
	some c in containers
	c.securityContext.privileged == true
	f := {"id": p.id, "msg": sprintf("%s: container %q runs privileged", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.no_privilege_escalation"
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	f := {"id": p.id, "msg": sprintf("%s: container %q does not set allowPrivilegeEscalation: false", [subject, c.name])}
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
	p.type == "k8s.drop_all_capabilities"
	some c in containers
	not drops_all(c)
	f := {"id": p.id, "msg": sprintf("%s: container %q does not drop ALL capabilities", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.drop_all_capabilities"
	some c in containers
	some a in c.securityContext.capabilities.add
	not a in p.params.allowed_add
	f := {"id": p.id, "msg": sprintf("%s: container %q adds capability %q", [subject, c.name, a])}
}

drops_all(c) if {
	some d in c.securityContext.capabilities.drop
	upper(d) == "ALL"
}

finding contains f if {
	some p in policies
	p.type == "k8s.read_only_root_fs"
	some c in containers
	not c.securityContext.readOnlyRootFilesystem == true
	f := {"id": p.id, "msg": sprintf("%s: container %q does not set readOnlyRootFilesystem: true", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.seccomp_required"
	some c in containers
	not seccomp_ok(c)
	f := {"id": p.id, "msg": sprintf("%s: container %q has no RuntimeDefault/Localhost seccomp profile", [subject, c.name])}
}

seccomp_ok(c) if c.securityContext.seccompProfile.type in seccomp_types

seccomp_ok(_) if pod_spec.securityContext.seccompProfile.type in seccomp_types

# -- host isolation --

finding contains f if {
	some p in policies
	p.type == "k8s.no_host_namespaces"
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	pod_spec[field] == true
	f := {"id": p.id, "msg": sprintf("%s: uses %s", [subject, field])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.no_host_path"
	some v in pod_spec.volumes
	v.hostPath
	f := {"id": p.id, "msg": sprintf("%s: volume %q mounts a hostPath", [subject, v.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.no_host_ports"
	some c in containers
	some port in c.ports
	port.hostPort > 0
	f := {"id": p.id, "msg": sprintf("%s: container %q binds hostPort %d", [subject, c.name, port.hostPort])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.no_automount_sa_token"
	pod_spec
	not pod_spec.automountServiceAccountToken == false
	f := {"id": p.id, "msg": sprintf("%s: does not set automountServiceAccountToken: false", [subject])}
}

# -- resources & reliability --

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
	p.type == "k8s.resource_requests_required"
	input.kind in p.params.kinds
	some c in containers
	not c.resources.requests.cpu
	f := {"id": p.id, "msg": sprintf("%s: container %q has no cpu request", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.resource_requests_required"
	input.kind in p.params.kinds
	some c in containers
	not c.resources.requests.memory
	f := {"id": p.id, "msg": sprintf("%s: container %q has no memory request", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.probes_required"
	input.kind in p.params.kinds
	some c in app_containers
	not c.livenessProbe
	f := {"id": p.id, "msg": sprintf("%s: container %q has no livenessProbe", [subject, c.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.probes_required"
	input.kind in p.params.kinds
	some c in app_containers
	not c.readinessProbe
	f := {"id": p.id, "msg": sprintf("%s: container %q has no readinessProbe", [subject, c.name])}
}

# -- images --

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
	p.type == "image.allowed_registries"
	some c in containers
	not registry_allowed(c.image, p.params.allow)
	f := {"id": p.id, "msg": sprintf("%s: image %q is not from an allowed registry", [subject, c.image])}
}

registry_allowed(img, allow) if {
	some a in allow
	startswith(img, a)
}

# -- configuration hygiene --

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
	p.type == "k8s.no_default_namespace"
	input.metadata.namespace == "default"
	f := {"id": p.id, "msg": sprintf("%s: deployed into the default namespace", [subject])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.no_secrets_in_env"
	some c in containers
	some e in c.env
	e.value
	some pat in p.params.patterns
	contains(upper(e.name), upper(pat))
	f := {"id": p.id, "msg": sprintf("%s: container %q sets %q as a literal env value (use a Secret)", [subject, c.name, e.name])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.service_types"
	input.kind == "Service"
	t := object.get(input.spec, "type", "ClusterIP")
	not t in p.params.allow
	f := {"id": p.id, "msg": sprintf("%s: service type %q is not allowed", [subject, t])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.ingress_tls_required"
	input.kind == "Ingress"
	count(object.get(input.spec, "tls", [])) == 0
	f := {"id": p.id, "msg": sprintf("%s: ingress has no tls section", [subject])}
}

finding contains f if {
	some p in policies
	p.type == "k8s.deny_wildcard_rbac"
	input.kind in {"Role", "ClusterRole"}
	some r in input.rules
	some field in ["verbs", "resources", "apiGroups"]
	"*" in r[field]
	f := {"id": p.id, "msg": sprintf("%s: rule uses wildcard %s", [subject, field])}
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

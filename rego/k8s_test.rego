package yakkai.k8s_test

import data.yakkai.k8s

# one block policy per type, id = type suffix
pol(t) := {"id": t, "type": sprintf("k8s.%s", [t]), "severity": "block", "params": params(t)}

params("resource_limits_required") := {"kinds": ["Deployment"]}

params("resource_requests_required") := {"kinds": ["Deployment"]}

params("probes_required") := {"kinds": ["Deployment"]}

params("required_labels") := {"labels": ["app.kubernetes.io/name"]}

params("drop_all_capabilities") := {"allowed_add": ["NET_BIND_SERVICE"]}

params("no_secrets_in_env") := {"patterns": ["PASSWORD", "SECRET", "TOKEN"]}

params("service_types") := {"allow": ["ClusterIP"]}

params(t) := {} if not t in {"resource_limits_required", "resource_requests_required", "probes_required", "required_labels", "drop_all_capabilities", "no_secrets_in_env", "service_types"}

all_policies := array.concat([pol(t) | some t in ["no_privileged", "no_privilege_escalation", "run_as_non_root", "drop_all_capabilities", "read_only_root_fs", "seccomp_required", "no_host_namespaces", "no_host_path", "no_host_ports", "no_automount_sa_token", "resource_limits_required", "resource_requests_required", "probes_required", "no_latest_tag", "required_labels", "no_default_namespace", "no_secrets_in_env", "service_types", "ingress_tls_required", "deny_wildcard_rbac"]], [{"id": "registry", "type": "image.allowed_registries", "severity": "block", "params": {"allow": ["ghcr.io/guhatek/"]}}])

ids(set) := {id | some m in set; id := regex.find_n(`^\[([a-z_]+)\]`, m, 1)[0]}

bad_deployment := {
	"kind": "Deployment",
	"metadata": {"name": "web", "namespace": "default", "labels": {}},
	"spec": {"template": {"spec": {
		"hostNetwork": true,
		"volumes": [{"name": "host", "hostPath": {"path": "/"}}],
		"containers": [{
			"name": "app",
			"image": "docker.io/library/nginx:latest",
			"securityContext": {"privileged": true, "capabilities": {"add": ["SYS_ADMIN"]}},
			"ports": [{"containerPort": 80, "hostPort": 8080}],
			"env": [{"name": "DB_PASSWORD", "value": "x"}, {"name": "SAFE", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}],
		}],
	}}},
}

good_deployment := {
	"kind": "Deployment",
	"metadata": {"name": "web", "namespace": "apps", "labels": {"app.kubernetes.io/name": "web"}},
	"spec": {"template": {"spec": {
		"automountServiceAccountToken": false,
		"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
		"containers": [{
			"name": "app",
			"image": "ghcr.io/guhatek/web:1.4.2",
			"securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}},
			"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}},
			"livenessProbe": {"httpGet": {"path": "/", "port": 80}},
			"readinessProbe": {"httpGet": {"path": "/", "port": 80}},
			"env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}],
		}],
	}}},
}

test_bad_deployment_trips_every_workload_policy if {
	d := k8s.deny with input as bad_deployment with data.policies as all_policies
	ids(d) == {"[no_privileged]", "[no_privilege_escalation]", "[run_as_non_root]", "[drop_all_capabilities]", "[read_only_root_fs]", "[seccomp_required]", "[no_host_namespaces]", "[no_host_path]", "[no_host_ports]", "[no_automount_sa_token]", "[resource_limits_required]", "[resource_requests_required]", "[probes_required]", "[no_latest_tag]", "[required_labels]", "[no_default_namespace]", "[no_secrets_in_env]", "[registry]"}
}

test_good_deployment_is_clean if {
	count(k8s.deny) == 0 with input as good_deployment with data.policies as all_policies
	count(k8s.warn) == 0 with input as good_deployment with data.policies as all_policies
}

test_warn_policy_goes_to_warn_not_deny if {
	pols := [{"id": "nonroot", "type": "k8s.run_as_non_root", "severity": "warn", "params": {}}]
	w := k8s.warn with input as bad_deployment with data.policies as pols
	count(w) == 1
	count(k8s.deny) == 0 with input as bad_deployment with data.policies as pols
}

test_policy_not_enabled_is_silent if {
	count(k8s.deny) == 0 with input as bad_deployment with data.policies as []
}

test_capability_add_outside_allow_list if {
	dep := object.union(good_deployment, {"spec": {"template": {"spec": {"containers": [{"name": "a", "image": "ghcr.io/guhatek/a:1", "securityContext": {"capabilities": {"drop": ["ALL"], "add": ["SYS_PTRACE"]}}}]}}}})
	d := k8s.deny with input as dep with data.policies as [pol("drop_all_capabilities")]
	d == {"[drop_all_capabilities] Deployment/web: container \"a\" adds capability \"SYS_PTRACE\""}
}

test_limits_and_probes_only_for_listed_kinds if {
	job := object.union(bad_deployment, {"kind": "Job"})
	count(k8s.deny) == 0 with input as job with data.policies as [pol("resource_limits_required"), pol("probes_required")]
}

test_cronjob_containers_are_found if {
	cj := {
		"kind": "CronJob", "metadata": {"name": "nightly"},
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "busybox"}]}}}}},
	}
	count(k8s.deny) == 1 with input as cj with data.policies as [pol("no_latest_tag")]
}

test_digest_pinned_image_is_ok if {
	dep := object.union(good_deployment, {"spec": {"template": {"spec": {"containers": [{"name": "a", "image": "ghcr.io/guhatek/web@sha256:abc"}]}}}})
	count(k8s.deny) == 0 with input as dep with data.policies as [pol("no_latest_tag")]
}

test_service_ingress_rbac_rules if {
	svc := {"kind": "Service", "metadata": {"name": "s"}, "spec": {"type": "NodePort"}}
	count(k8s.deny) == 1 with input as svc with data.policies as [pol("service_types")]
	svc_ok := {"kind": "Service", "metadata": {"name": "s"}, "spec": {}}
	count(k8s.deny) == 0 with input as svc_ok with data.policies as [pol("service_types")]
	ing := {"kind": "Ingress", "metadata": {"name": "i"}, "spec": {"rules": []}}
	count(k8s.deny) == 1 with input as ing with data.policies as [pol("ingress_tls_required")]
	ing_ok := {"kind": "Ingress", "metadata": {"name": "i"}, "spec": {"tls": [{"hosts": ["a"]}]}}
	count(k8s.deny) == 0 with input as ing_ok with data.policies as [pol("ingress_tls_required")]
	role := {"kind": "ClusterRole", "metadata": {"name": "r"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}]}
	count(k8s.deny) == 1 with input as role with data.policies as [pol("deny_wildcard_rbac")]
}

test_non_workload_document_ignored_by_workload_rules if {
	cm := {"kind": "ConfigMap", "metadata": {"name": "cfg", "namespace": "apps", "labels": {"app.kubernetes.io/name": "x"}}, "data": {}}
	count(k8s.deny) == 0 with input as cm with data.policies as all_policies
}

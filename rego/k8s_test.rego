package yakkai.k8s_test

import data.yakkai.k8s

all_policies := [
	{"id": "priv", "type": "k8s.no_privileged", "severity": "block", "params": {}},
	{"id": "nonroot", "type": "k8s.run_as_non_root", "severity": "warn", "params": {}},
	{"id": "limits", "type": "k8s.resource_limits_required", "severity": "block", "params": {"kinds": ["Deployment"]}},
	{"id": "latest", "type": "k8s.no_latest_tag", "severity": "block", "params": {}},
	{"id": "labels", "type": "k8s.required_labels", "severity": "block", "params": {"labels": ["app.kubernetes.io/name"]}},
	{"id": "registry", "type": "image.allowed_registries", "severity": "block", "params": {"allow": ["ghcr.io/guhatek/"]}},
]

bad_deployment := {
	"kind": "Deployment",
	"metadata": {"name": "web", "labels": {}},
	"spec": {"template": {"spec": {"containers": [{
		"name": "app",
		"image": "docker.io/library/nginx:latest",
		"securityContext": {"privileged": true},
	}]}}},
}

good_deployment := {
	"kind": "Deployment",
	"metadata": {"name": "web", "labels": {"app.kubernetes.io/name": "web"}},
	"spec": {"template": {"spec": {
		"securityContext": {"runAsNonRoot": true},
		"containers": [{
			"name": "app",
			"image": "ghcr.io/guhatek/web:1.4.2",
			"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
		}],
	}}},
}

test_bad_deployment_blocks_every_block_policy if {
	d := k8s.deny with input as bad_deployment with data.policies as all_policies
	ids := {id | some m in d; id := regex.find_n(`^\[([a-z]+)\]`, m, 1)[0]}
	ids == {"[priv]", "[limits]", "[latest]", "[labels]", "[registry]"}
}

test_warn_policy_goes_to_warn_not_deny if {
	w := k8s.warn with input as bad_deployment with data.policies as all_policies
	count(w) == 1
	startswith([m | some m in w][0], "[nonroot]")
}

test_good_deployment_is_clean if {
	count(k8s.deny) == 0 with input as good_deployment with data.policies as all_policies
	count(k8s.warn) == 0 with input as good_deployment with data.policies as all_policies
}

test_policy_not_enabled_is_silent if {
	count(k8s.deny) == 0 with input as bad_deployment with data.policies as []
}

test_limits_only_for_listed_kinds if {
	job := object.union(bad_deployment, {"kind": "Job"})
	d := k8s.deny with input as job with data.policies as [all_policies[2]]
	count(d) == 0
}

test_cronjob_containers_are_found if {
	cj := {
		"kind": "CronJob", "metadata": {"name": "nightly"},
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "busybox"}]}}}}},
	}
	d := k8s.deny with input as cj with data.policies as [all_policies[3]]
	count(d) == 1
}

test_digest_pinned_image_is_ok if {
	dep := object.union(good_deployment, {"spec": {"template": {"spec": {"containers": [{"name": "a", "image": "ghcr.io/guhatek/web@sha256:abc"}]}}}})
	count(k8s.deny) == 0 with input as dep with data.policies as [all_policies[3]]
}

test_non_workload_document_ignored if {
	cm := {"kind": "ConfigMap", "metadata": {"name": "cfg", "labels": {"app.kubernetes.io/name": "x"}}, "data": {}}
	count(k8s.deny) == 0 with input as cm with data.policies as all_policies
}

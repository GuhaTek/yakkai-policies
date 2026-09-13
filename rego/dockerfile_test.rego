package yakkai.dockerfile_test

import data.yakkai.dockerfile

all_policies := [
	{"id": "latest", "type": "dockerfile.no_latest_base", "severity": "block", "params": {}},
	{"id": "registry", "type": "dockerfile.allowed_base_registries", "severity": "warn", "params": {"allow": ["ghcr.io/guhatek/"]}},
]

# FROM ghcr.io/guhatek/base:1.2 AS build / FROM ubuntu:latest / FROM scratch / FROM build
multi_stage := [
	{"Cmd": "from", "Stage": 0, "Value": ["ghcr.io/guhatek/base:1.2", "AS", "build"]},
	{"Cmd": "run", "Stage": 0, "Value": ["echo"]},
	{"Cmd": "from", "Stage": 1, "Value": ["ubuntu:latest"]},
	{"Cmd": "from", "Stage": 2, "Value": ["scratch"]},
	{"Cmd": "from", "Stage": 3, "Value": ["build"]},
]

test_base_images_skip_scratch_and_aliases if {
	dockerfile.base_images == {"ghcr.io/guhatek/base:1.2", "ubuntu:latest"} with input as multi_stage
}

test_latest_base_is_denied_once if {
	d := dockerfile.deny with input as multi_stage with data.policies as all_policies
	d == {"[latest] base image \"ubuntu:latest\" is not pinned to a tag or digest"}
}

test_registry_policy_warns_for_ubuntu_only if {
	w := dockerfile.warn with input as multi_stage with data.policies as all_policies
	w == {"[registry] base image \"ubuntu:latest\" is not from an allowed registry"}
}

test_untagged_base_is_unpinned if {
	d := dockerfile.deny with input as [{"Cmd": "from", "Value": ["python"]}] with data.policies as [all_policies[0]]
	count(d) == 1
}

test_pinned_allowed_base_is_clean if {
	inp := [{"Cmd": "from", "Value": ["ghcr.io/guhatek/base@sha256:abc"]}]
	count(dockerfile.deny) == 0 with input as inp with data.policies as all_policies
	count(dockerfile.warn) == 0 with input as inp with data.policies as all_policies
}

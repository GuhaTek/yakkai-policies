package yakkai.dockerfile_test

import data.yakkai.dockerfile

pol(t) := {"id": t, "type": sprintf("dockerfile.%s", [t]), "severity": "block", "params": params(t)}

params("allowed_base_registries") := {"allow": ["ghcr.io/guhatek/"]}

params("no_secrets_in_env") := {"patterns": ["PASSWORD", "SECRET", "TOKEN", "API_KEY"]}

params("forbidden_ports") := {"ports": ["22"]}

params(t) := {} if not t in {"allowed_base_registries", "no_secrets_in_env", "forbidden_ports"}

all_policies := [pol(t) | some t in ["no_latest_base", "allowed_base_registries", "user_required", "no_add", "no_sudo", "no_curl_pipe_sh", "apt_get_hygiene", "no_secrets_in_env", "healthcheck_required", "forbidden_ports"]]

ids(set) := {id | some m in set; id := regex.find_n(`^\[([a-z_]+)\]`, m, 1)[0]}

# Shapes as produced by `conftest test --parser dockerfile` (flat instruction list).
bad := [
	{"Cmd": "from", "Stage": 0, "Value": ["ubuntu:latest"]},
	{"Cmd": "arg", "Stage": 0, "Value": ["API_TOKEN=abc"]},
	{"Cmd": "env", "Stage": 0, "Value": ["DB_PASSWORD", "x", "=", "OTHER", "1", "="]},
	{"Cmd": "run", "Stage": 0, "Value": ["apt-get update && apt-get install -y curl"]},
	{"Cmd": "run", "Stage": 0, "Value": ["curl -sSL https://x/install.sh | sh"]},
	{"Cmd": "run", "Stage": 0, "Value": ["sudo", "make"]},
	{"Cmd": "add", "Stage": 0, "Value": ["https://x/file.tgz", "/opt"]},
	{"Cmd": "expose", "Stage": 0, "Value": ["22", "8080/tcp"]},
	{"Cmd": "user", "Stage": 0, "Value": ["root"]},
]

good := [
	{"Cmd": "from", "Stage": 0, "Value": ["ghcr.io/guhatek/base:1.2", "AS", "build"]},
	{"Cmd": "run", "Stage": 0, "Value": ["apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*"]},
	{"Cmd": "from", "Stage": 1, "Value": ["ghcr.io/guhatek/runtime@sha256:abc"]},
	{"Cmd": "copy", "Stage": 1, "Flags": ["--from=build"], "Value": ["/a", "/b"]},
	{"Cmd": "env", "Stage": 1, "Value": ["APP_ENV", "prod", "="]},
	{"Cmd": "arg", "Stage": 1, "Value": ["API_TOKEN"]},
	{"Cmd": "expose", "Stage": 1, "Value": ["8080/tcp"]},
	{"Cmd": "healthcheck", "Stage": 1, "Value": ["CMD", "curl -f http://localhost/"]},
	{"Cmd": "user", "Stage": 1, "Value": ["app:app"]},
]

test_bad_dockerfile_trips_every_policy if {
	d := dockerfile.deny with input as bad with data.policies as all_policies
	ids(d) == {"[no_latest_base]", "[allowed_base_registries]", "[user_required]", "[no_add]", "[no_sudo]", "[no_curl_pipe_sh]", "[apt_get_hygiene]", "[no_secrets_in_env]", "[healthcheck_required]", "[forbidden_ports]"}
}

test_good_dockerfile_is_clean if {
	count(dockerfile.deny) == 0 with input as good with data.policies as all_policies
	count(dockerfile.warn) == 0 with input as good with data.policies as all_policies
}

test_base_images_skip_scratch_and_aliases if {
	inp := array.concat(good, [{"Cmd": "from", "Stage": 2, "Value": ["scratch"]}, {"Cmd": "from", "Stage": 3, "Value": ["build"]}])
	dockerfile.base_images == {"ghcr.io/guhatek/base:1.2", "ghcr.io/guhatek/runtime@sha256:abc"} with input as inp
}

test_user_required_looks_at_final_stage_only if {
	# builder stage runs as root, final stage switches to app -> ok
	inp := [
		{"Cmd": "from", "Stage": 0, "Value": ["a:1", "AS", "b"]}, {"Cmd": "user", "Stage": 0, "Value": ["root"]},
		{"Cmd": "from", "Stage": 1, "Value": ["a:1"]}, {"Cmd": "user", "Stage": 1, "Value": ["1000:1000"]},
	]
	count(dockerfile.deny) == 0 with input as inp with data.policies as [pol("user_required")]

	# final stage ends as root after switching back
	inp2 := [{"Cmd": "from", "Stage": 0, "Value": ["a:1"]}, {"Cmd": "user", "Stage": 0, "Value": ["app"]}, {"Cmd": "user", "Stage": 0, "Value": ["0"]}]
	count(dockerfile.deny) == 1 with input as inp2 with data.policies as [pol("user_required")]
}

test_secret_env_messages if {
	d := dockerfile.deny with input as bad with data.policies as [pol("no_secrets_in_env")]
	d == {
		"[no_secrets_in_env] ENV \"DB_PASSWORD\" looks like a secret baked into the image",
		"[no_secrets_in_env] ARG \"API_TOKEN\" has a default value that looks like a secret (kept in image history)",
	}
}

test_warn_routing if {
	w := dockerfile.warn with input as bad with data.policies as [{"id": "hc", "type": "dockerfile.healthcheck_required", "severity": "warn", "params": {}}]
	w == {"[hc] no HEALTHCHECK instruction"}
}

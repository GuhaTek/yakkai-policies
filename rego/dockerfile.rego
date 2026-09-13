# YakkAI policy library: Dockerfiles (conftest `--parser dockerfile`).
#
# In `conftest test` the input is a flat array of instructions {Cmd, Value, Stage, ...}
# (note: `conftest parse` prints them grouped per stage, `test` does not).
# Rules come from `.yakkai/policies/container-build.json`.
package yakkai.dockerfile

policies := data.policies

from_values contains v if {
	some ins in input
	ins.Cmd == "from"
	v := ins.Value
}

# Names introduced by `FROM x AS name`; later `FROM name` is a stage ref, not an image.
aliases contains lower(v[2]) if {
	some v in from_values
	count(v) >= 3
	lower(v[1]) == "as"
}

base_images contains img if {
	some v in from_values
	img := v[0]
	img != "scratch"
	not aliases[lower(img)]
}

run_commands contains cmd if {
	some ins in input
	ins.Cmd == "run"
	cmd := concat(" ", ins.Value)
}

last_stage := max({ins.Stage | some ins in input})

# USER instructions of the final stage, in order
final_users := [ins.Value[0] | some ins in input; ins.Stage == last_stage; ins.Cmd == "user"]

root_user(u) if u == "root"

root_user(u) if u == "0"

root_user(u) if startswith(u, "root:")

root_user(u) if startswith(u, "0:")

# -- base images --

finding contains f if {
	some p in policies
	p.type == "dockerfile.no_latest_base"
	some img in base_images
	unpinned(img)
	f := {"id": p.id, "msg": sprintf("base image %q is not pinned to a tag or digest", [img])}
}

unpinned(img) if endswith(img, ":latest")

unpinned(img) if {
	not contains(img, "@")
	parts := split(img, "/")
	not contains(parts[count(parts) - 1], ":")
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.allowed_base_registries"
	some img in base_images
	not registry_allowed(img, p.params.allow)
	f := {"id": p.id, "msg": sprintf("base image %q is not from an allowed registry", [img])}
}

registry_allowed(img, allow) if {
	some a in allow
	startswith(img, a)
}

# -- user --

finding contains f if {
	some p in policies
	p.type == "dockerfile.user_required"
	count(final_users) == 0
	f := {"id": p.id, "msg": "final stage has no USER instruction (container runs as root)"}
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.user_required"
	count(final_users) > 0
	u := final_users[count(final_users) - 1]
	root_user(u)
	f := {"id": p.id, "msg": sprintf("final stage ends as USER %q", [u])}
}

# -- instructions --

finding contains f if {
	some p in policies
	p.type == "dockerfile.no_add"
	some ins in input
	ins.Cmd == "add"
	f := {"id": p.id, "msg": sprintf("ADD %q used - prefer COPY (ADD fetches URLs and unpacks archives implicitly)", [ins.Value[0]])}
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.no_sudo"
	some cmd in run_commands
	regex.match(`(^|[\s;&|])sudo\s`, cmd)
	f := {"id": p.id, "msg": sprintf("RUN uses sudo: %q", [trim_cmd(cmd)])}
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.no_curl_pipe_sh"
	some cmd in run_commands
	regex.match(`(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh(\s|$)`, cmd)
	f := {"id": p.id, "msg": sprintf("RUN pipes a download straight into a shell: %q", [trim_cmd(cmd)])}
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.apt_get_hygiene"
	some cmd in run_commands
	contains(cmd, "apt-get install")
	not contains(cmd, "--no-install-recommends")
	f := {"id": p.id, "msg": sprintf("apt-get install without --no-install-recommends: %q", [trim_cmd(cmd)])}
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.apt_get_hygiene"
	some cmd in run_commands
	contains(cmd, "apt-get install")
	not contains(cmd, "/var/lib/apt/lists")
	f := {"id": p.id, "msg": sprintf("apt-get install without cleaning /var/lib/apt/lists in the same RUN: %q", [trim_cmd(cmd)])}
}

trim_cmd(cmd) := cmd if count(cmd) <= 60

trim_cmd(cmd) := sprintf("%s...", [substring(cmd, 0, 57)]) if count(cmd) > 60

# -- secrets --

# ENV values arrive as [key, value, "=", key, value, "=", ...]; ARG as ["KEY=default"] or ["KEY"].
env_keys contains k if {
	some ins in input
	ins.Cmd == "env"
	some i
	i % 3 == 0
	k := ins.Value[i]
}

arg_keys_with_default contains k if {
	some ins in input
	ins.Cmd == "arg"
	some v in ins.Value
	contains(v, "=")
	k := split(v, "=")[0]
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.no_secrets_in_env"
	some k in env_keys
	some pat in p.params.patterns
	contains(upper(k), upper(pat))
	f := {"id": p.id, "msg": sprintf("ENV %q looks like a secret baked into the image", [k])}
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.no_secrets_in_env"
	some k in arg_keys_with_default
	some pat in p.params.patterns
	contains(upper(k), upper(pat))
	f := {"id": p.id, "msg": sprintf("ARG %q has a default value that looks like a secret (kept in image history)", [k])}
}

# -- runtime --

finding contains f if {
	some p in policies
	p.type == "dockerfile.healthcheck_required"
	not has_healthcheck
	f := {"id": p.id, "msg": "no HEALTHCHECK instruction"}
}

has_healthcheck if {
	some ins in input
	ins.Cmd == "healthcheck"
}

finding contains f if {
	some p in policies
	p.type == "dockerfile.forbidden_ports"
	some ins in input
	ins.Cmd == "expose"
	some v in ins.Value
	port := split(v, "/")[0]
	port in p.params.ports
	f := {"id": p.id, "msg": sprintf("EXPOSE %s is not allowed", [v])}
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

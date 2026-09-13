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

package concourse

import rego.v1

# METADATA
# description: default rule allows everything that is not explicitly denied
# entrypoint: true
default decision := {"allowed": true}

decision := {"allowed": false, "reasons": reasons} if {
	count(deny) > 0
	reasons := deny
}

# METADATA
# title: ExposePipeline
# description: Pipeline cannot be public/exposed
# scope: rule
deny contains msg if {
	msg := rego.metadata.rule().description
	input.action == "ExposePipeline"
}

# METADATA
# title: SaveConfig or SetPipeline
# description: "Git resource must have webhook_token or check_every: 24h configured"
# scope: rule
deny contains msg if {
	msg := rego.metadata.rule().description
	input.action in {"SaveConfig", "SetPipeline"}
	not valid_git_resources
}

git_resources contains r if {
	r := input.data.resources[_]
	r.type == "git"
}

git_resources_with_webhooks contains r if {
	r := input.data.resources[_]
	r.type == "git"
	r.webhook_token != null
}

git_resources_with_check contains r if {
	r := input.data.resources[_]
	r.type == "git"
	r.check_every != null
	time.parse_duration_ns(r.check_every) >= time.parse_duration_ns("24h")
}

valid_git_resources if {
	count(git_resources_with_webhooks & git_resources_with_check) == 0
	count(git_resources_with_webhooks | git_resources_with_check) == count(git_resources)
}

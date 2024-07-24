package concourse

import rego.v1

# METADATA
# description: default rule allows everything that is not explicitly denied
# entrypoint: true
default decision := {"allowed": true}

decision := {"allowed": false, "reasons": deny | soft_deny} if {
	count(deny) > 0
}

# Soft-policy enforcement
# Note that documentation: https://concourse-ci.org/opa.html#writing-opa-rules about soft policy enforcement
# is not correct. See the actual implemenation for more details:
# https://github.com/concourse/concourse/blob/master/atc/api/policychecker/handler.go#L44
decision := {"allowed": false, "block": false, "reasons": soft_deny} if {
	count(deny) == 0
	count(soft_deny) > 0
}

craft_message(metadata) := sprintf("Violation: %s. Documentation: %s", [
	metadata.description,
	concat(",", [ref | ref := metadata.related_resources[_].ref]),
])

# METADATA
# title: ExposePipeline
# description: Pipeline cannot be public/exposed
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/L4CaJgE
# scope: rule
deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action == "ExposePipeline"
}

# METADATA
# title: Public job
# description: Job cannot be public
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/N4ChJgE
# scope: rule
deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action in {"SaveConfig", "SetPipeline"}
	some job in input.data.jobs
	job.public
}

# METADATA
# title: Public resource
# description: Resource cannot be public
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/N4ChJgE
# scope: rule
deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action in {"SaveConfig", "SetPipeline"}
	some resource in input.data.resources
	resource.public
}

# METADATA
# title: SaveConfig or SetPipeline
# description: "Git resource must have webhook_token or check_every: 24h configured"
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/PoCfJgE
# scope: rule
deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action in {"SaveConfig", "SetPipeline"}
	not valid_git_resources
}

# METADATA
# title: Deprecated docker-image
# description: Cannot use docker-image resource type
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/CADDJgE
# scope: rule
deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action == "UseImage"
	input.data.image_type == "docker-image"
}

# METADATA
# title: Deprecated docker-image in pipeline resource configuration
# description: Cannot use docker-image resource type
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/CADDJgE
# scope: rule
deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action in {"SaveConfig", "SetPipeline"}
	some r in input.data.resources
	r.type == "docker-image"
}

# METADATA
# title: Deprecated docker-image in pipeline resource type configuration
# description: Cannot use docker-image resource type
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/CADDJgE
# scope: rule
deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action in {"SaveConfig", "SetPipeline"}
	some r in input.data.resource_types
	r.type == "docker-image"
}

git_resources contains r if {
	some r in input.data.resources
	r.type == "git"
}

git_resources_with_webhooks contains r if {
	some r in input.data.resources
	r.type == "git"
	r.webhook_token != null
}

git_resources_with_check contains r if {
	some r in input.data.resources
	r.type == "git"
	r.check_every != null
	time.parse_duration_ns(r.check_every) >= time.parse_duration_ns("24h")
}

valid_git_resources if {
	count(git_resources_with_webhooks & git_resources_with_check) == 0
	count(git_resources_with_webhooks | git_resources_with_check) == count(git_resources)
}

jobs_with_max_in_flight contains job if {
	some job in input.data.jobs
	job.max_in_flight != null
}

# METADATA
# title: Serial job
# description: Each job must have max_in_flight key configured
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/RwCYJgE
# scope: rule
soft_deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action in {"SaveConfig", "SetPipeline"}
	count(input.data.jobs) != count(jobs_with_max_in_flight)
}

# METADATA
# title: Serial job
# description: Each job must have max_in_flight key set to 1
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/RwCYJgE
# scope: rule
soft_deny contains msg if {
	msg := craft_message(rego.metadata.rule())
	input.action in {"SaveConfig", "SetPipeline"}
	some job in input.data.jobs
	job.max_in_flight != 1
}

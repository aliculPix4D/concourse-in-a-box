package concourse

import rego.v1

# METADATA
# description: default rule allows everything that is not explicitly denied
# entrypoint: true
default decision := {"allowed": true}

# Hard-policy enforcement
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

# METADATA
# title: Exposed pipeline
# description: Pipeline cannot be public/exposed
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/L4CaJgE
# scope: rule
deny contains msg if {
	input.action == "ExposePipeline"
	msg := sprintf("Violation: %s. Pipeline: %s/%s. Documentation: %s", [
		rego.metadata.rule().description,
		input.team,
		input.pipeline,
		rego.metadata.rule().related_resources[0].ref,
	])
}

# METADATA
# title: Public job
# description: Job cannot be public
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/N4ChJgE
# scope: rule
deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}
	some job in input.data.jobs
	job.public
	msg := sprintf("Violation: %s. Misconfigured job: %s. Documentation: %s", [
		rego.metadata.rule().description,
		job.name,
		rego.metadata.rule().related_resources[0].ref,
	])
}

# METADATA
# title: Public resource
# description: Resource cannot be public
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/N4ChJgE
# scope: rule
deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}
	some resource in input.data.resources
	resource.public
	msg := sprintf("Violation: %s. Misconfigured resource: %s. Documentation: %s", [
		rego.metadata.rule().description,
		resource.name,
		rego.metadata.rule().related_resources[0].ref,
	])
}

# METADATA
# title: Deprecated docker-image at runtime
# description: Cannot use docker-image resource type
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/CADDJgE
# scope: rule
deny contains msg if {
	input.action == "UseImage"
	input.data.image_type == "docker-image"
	msg := sprintf("Violation: %s. Documentation: %s", [
		rego.metadata.rule().description,
		rego.metadata.rule().related_resources[0].ref,
	])
}

# METADATA
# title: Deprecated docker-image in pipeline resource configuration
# description: Cannot use docker-image resource type
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/CADDJgE
# scope: rule
deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}
	some r in input.data.resources
	r.type == "docker-image"
	msg := sprintf("Violation: %s. Misconfigured resource: %s. Documentation: %s", [
		rego.metadata.rule().description,
		r.name,
		rego.metadata.rule().related_resources[0].ref,
	])
}

# METADATA
# title: Deprecated docker-image in pipeline resource type configuration
# description: Cannot use docker-image resource type
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/CADDJgE
# scope: rule
deny contains msg if {
	some r in input.data.resource_types
	r.type == "docker-image"
	msg := sprintf("Violation: %s. Misconfigured resource type: %s. Documentation: %s", [
		rego.metadata.rule().description,
		r.name,
		rego.metadata.rule().related_resources[0].ref,
	])
}

# METADATA
# title: Misconfigured git resource
# description: "Git resource must have webhook_token or check_every: 24h configured"
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/PoCfJgE
# scope: rule
deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}
	not valid_git_resources
	msg := sprintf("Violation: %s. Found misconfigured git resources: %s. Documentation: %s", [
		rego.metadata.rule().description,
		concat(",", [r | r := misconfigured_git_resources[_]]),
		rego.metadata.rule().related_resources[0].ref,
	])
}

git_resources contains r.name if {
	some r in input.data.resources
	r.type == "git"
}

git_resources_with_webhooks contains r.name if {
	some r in input.data.resources
	r.type == "git"
	r.webhook_token != null
}

git_resources_with_check contains r.name if {
	some r in input.data.resources
	r.type == "git"
	r.check_every != null
	time.parse_duration_ns(r.check_every) >= time.parse_duration_ns("24h")
}

misconfigured_git_resources contains r.name if {
	some r in input.data.resources
	r.type == "git"
	both_polling_and_check := git_resources_with_webhooks & git_resources_with_check
	r.name in ((git_resources - (git_resources_with_webhooks | git_resources_with_check)) | both_polling_and_check)
}

valid_git_resources if {
	count(git_resources_with_webhooks & git_resources_with_check) == 0
	count(git_resources_with_webhooks | git_resources_with_check) == count(git_resources)
}

# METADATA
# title: Parallel builds
# description: Each job must have max_in_flight key configured
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/RwCYJgE
# scope: rule
soft_deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}

	some job in input.data.jobs
	not "max_in_flight" in object.keys(job)
	msg := sprintf("Violation: %s. Found misconfigured job: %s. Documentation: %s", [
		rego.metadata.rule().description,
		job.name,
		rego.metadata.rule().related_resources[0].ref,
	])
}

# METADATA
# title: Parallel builds
# description: Each job must have max_in_flight key set to 1
# related_resources:
# - https://pix4dbug.atlassian.net/wiki/x/RwCYJgE
# scope: rule
soft_deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}

	some job in input.data.jobs
	job.max_in_flight != 1
	msg := sprintf("Violation: %s. Found misconfigured job: %s. Documentation: %s", [
		rego.metadata.rule().description,
		job.name,
		rego.metadata.rule().related_resources[0].ref,
	])
}

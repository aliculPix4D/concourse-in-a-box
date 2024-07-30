package concourse

import rego.v1

# METADATA
# description: default rule allows everything that is not explicitly denied
# entrypoint: true
default decision := {"allowed": true}

decision := {"allowed": false, "reasons": deny} if {
	count(deny) > 0
}

deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}

	some job in input.data.jobs
	not "max_in_flight" in object.keys(job)
	msg := sprintf("Violation: max_in_flight not configured for job: %s.", [job.name])
}

deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}
	some job in input.data.jobs
	job.max_in_flight != 1
	msg := sprintf("Violation: each job must have max_in_flight key set to 1 for job: %s.", [job.name])
}

deny contains msg if {
	input.action in {"SaveConfig", "SetPipeline"}

	not valid_git_resources
	msg := sprintf("Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: %s.", [concat(",", [r | r := misconfigured_git_resources[_]])])
}

misconfigured_git_resources contains r.name if {
	some r in input.data.resources
	r.type == "git"
	r.name in (git_resources - (git_resources_with_webhooks | git_resources_with_check) | (git_resources_with_webhooks & git_resources_with_check))
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

valid_git_resources if {
	count(git_resources_with_webhooks & git_resources_with_check) == 0
	count(git_resources_with_webhooks | git_resources_with_check) == count(git_resources)
}

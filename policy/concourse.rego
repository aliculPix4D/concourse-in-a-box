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

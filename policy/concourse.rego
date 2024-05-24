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

deny contains "pipeline cannot be exposed" if {
	input.action == "ExposePipeline"
}

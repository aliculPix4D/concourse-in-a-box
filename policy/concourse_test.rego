package concourse_test

import rego.v1

import data.concourse

test_expose_denied if {
	concourse.decision.allowed == false with input as {"action": "ExposePipeline"}
}

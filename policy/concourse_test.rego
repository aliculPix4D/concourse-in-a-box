package concourse_test

import rego.v1

import data.concourse

test_saveconfig_denied_if_max_in_flight_not_set if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"jobs": [{"name": "job-1"}]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Violation: max_in_flight not configured for job: job-1."},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_max_in_flight_set_wrongly if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"jobs": [{"name": "job-1", "max_in_flight": 2}]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Violation: each job must have max_in_flight key set to 1 for job: job-1."},
	}
	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_max_in_flight_set_wrongly_multiple_jobs if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"jobs": [
			{"name": "job-1", "max_in_flight": 2},
			{"name": "job-2"},
			{"name": "job-3", "max_in_flight": 1},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {
			"Violation: each job must have max_in_flight key set to 1 for job: job-1.",
			"Violation: max_in_flight not configured for job: job-2.",
		},
	}
	concourse.decision == expected with input as input_fixture
}

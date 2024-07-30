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

test_setpipeline_allowed if {
	input_fixture := {
		"action": "SetPipeline",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "repo-1.git", "type": "git", "check_every": "24h"},
			{"name": "repo-2.git", "type": "git", "webhook_token": "((concourse_gh_webhook))"},
		]},
	}
	expected := {"allowed": true}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_neither if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "polling-only.git", "type": "git"},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: polling-only.git."},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_both if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "both-check-and-webhook.git", "type": "git", "check_every": "24h", "webhook_token": "((concourse_gh_webhook))"},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: both-check-and-webhook.git."},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_low if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "too-frequent-check.git", "type": "git", "check_every": "1m"},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: too-frequent-check.git."},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_multiple_misconfigured_git if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "too-frequent-check.git", "type": "git", "check_every": "7m"},
			{"name": "polling-only.git", "type": "git"},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: polling-only.git,too-frequent-check.git."},
	}

	concourse.decision == expected with input as input_fixture
}

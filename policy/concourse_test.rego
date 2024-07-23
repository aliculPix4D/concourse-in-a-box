package concourse_test

import rego.v1

import data.concourse

test_expose_denied if {
	input_fixture := {"action": "ExposePipeline"}
	expected := {"allowed": false, "reasons": {"Pipeline cannot be public/exposed"}}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_allowed if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "repo.git", "type": "git", "check_every": "24h"},
			{"name": "repo.git", "type": "git", "webhook_token": "((concourse_gh_webhook))"},
		]},
	}
	expected := {"allowed": true}

	concourse.decision == expected with input as input_fixture
}

test_setpipeline_allowed if {
	input_fixture := {
		"action": "SetPipeline",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "repo.git", "type": "git", "check_every": "24h"},
			{"name": "repo.git", "type": "git", "webhook_token": "((concourse_gh_webhook))"},
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
			{"name": "repo.git", "type": "git"},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Git resource must have webhook_token or check_every: 24h configured"},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_both if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "repo.git", "type": "git", "check_every": "24h", "webhook_token": "((concourse_gh_webhook))"},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Git resource must have webhook_token or check_every: 24h configured"},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_low if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [
			{"name": "image.docker", "type": "registry-image"},
			{"name": "repo.git", "type": "git", "check_every": "1m"},
		]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Git resource must have webhook_token or check_every: 24h configured"},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_soft_denied_if_public_job if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"jobs": [{"name": "job-1", "public": true, "max_in_flight": 1}]},
	}
	expected := {
		"allowed": false,
		"block": false,
		"reasons": {"Job cannot be public"},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_soft_denied_if_max_in_flight_not_set if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"jobs": [{"name": "job-1"}]},
	}
	expected := {
		"allowed": false,
		"block": false,
		"reasons": {"Each job must have max_in_flight key configured"},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_soft_denied_if_max_in_flight_set_wrongly if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"jobs": [{"name": "job-1", "max_in_flight": 2}]},
	}
	expected := {
		"allowed": false,
		"block": false,
		"reasons": {"Each job must have max_in_flight key set to 1"},
	}

	concourse.decision == expected with input as input_fixture
}

package concourse_test

import rego.v1

import data.concourse

test_expose_denied if {
	input_fixture := {"action": "ExposePipeline"}
	expected := {
		"allowed": false,
		"reasons": {"Violation: Pipeline cannot be public/exposed. Documentation: https://pix4dbug.atlassian.net/wiki/x/L4CaJgE"},
	}

	concourse.decision == expected with input as input_fixture
}

test_saveconfig_allowed if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {
			"resources": [
				{"name": "image.docker", "type": "registry-image"},
				{"name": "repo.git", "type": "git", "check_every": "24h"},
				{"name": "repo.git", "type": "git", "webhook_token": "((concourse_gh_webhook))"},
			],
			"jobs": [{"name": "job-1", "max_in_flight": 1}],
		},
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
		"reasons": {"Violation: Git resource must have webhook_token or check_every: 24h configured. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE"},
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
		"reasons": {"Violation: Git resource must have webhook_token or check_every: 24h configured. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE"},
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
		"reasons": {"Violation: Git resource must have webhook_token or check_every: 24h configured. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE"},
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
		"reasons": {"Violation: Each job must have max_in_flight key configured. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE"},
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
		"reasons": {"Violation: Each job must have max_in_flight key set to 1. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE"},
	}
	concourse.decision == expected with input as input_fixture
}

test_saveconfig_hard_denied_if_mixed_with_soft if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {
			"resources": [
				{"name": "image.docker", "type": "registry-image"},
				{"name": "repo.git", "type": "git", "check_every": "1m"},
			],
			"jobs": [
				{"name": "job-1"},
				{"name": "job-2", "max_in_flight": 2},
			],
		},
	}
	expected := {
		"allowed": false,
		"reasons": {
			"Violation: Git resource must have webhook_token or check_every: 24h configured. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE",
			"Violation: Each job must have max_in_flight key configured. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE",
			"Violation: Each job must have max_in_flight key set to 1. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE",
		},
	}
	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_public_job if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"jobs": [{"name": "job-1", "public": true, "max_in_flight": 1}]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Violation: Job cannot be public. Documentation: https://pix4dbug.atlassian.net/wiki/x/N4ChJgE"},
	}
	concourse.decision == expected with input as input_fixture
}

test_saveconfig_denied_if_public_resource if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [{"name": "resource-1", "public": true}]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Violation: Resource cannot be public. Documentation: https://pix4dbug.atlassian.net/wiki/x/N4ChJgE"},
	}
	concourse.decision == expected with input as input_fixture
}

test_use_image_denied if {
	input_fixture := {
		"action": "UseImage",
		"data": {"image_type": "docker-image"},
	}
	expected := {
		"allowed": false,
		"reasons": {"Violation: Cannot use docker-image resource type. Documentation: https://pix4dbug.atlassian.net/wiki/x/CADDJgE"},
	}

	concourse.decision == expected with input as input_fixture
}

test_use_image_resource_denied if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resources": [{"name": "resource-1", "type": "docker-image"}]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Violation: Cannot use docker-image resource type. Documentation: https://pix4dbug.atlassian.net/wiki/x/CADDJgE"},
	}

	concourse.decision == expected with input as input_fixture
}

test_use_image_resource_types_denied if {
	input_fixture := {
		"action": "SaveConfig",
		"data": {"resource_types": [{"name": "resource-1", "type": "docker-image"}]},
	}
	expected := {
		"allowed": false,
		"reasons": {"Violation: Cannot use docker-image resource type. Documentation: https://pix4dbug.atlassian.net/wiki/x/CADDJgE"},
	}

	concourse.decision == expected with input as input_fixture
}

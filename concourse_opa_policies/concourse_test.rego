package concourse_test

import rego.v1

import data.concourse

test_valid_pipeline_allowed if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		expected := {"allowed": true}

		input_fixture := {
			"action": action,
			"data": {"resources": [
				{"name": "image.docker", "type": "registry-image"},
				{"name": "repo-1.git", "type": "git", "check_every": "24h"},
				{"name": "repo-2.git", "type": "git", "webhook_token": "((concourse_gh_webhook))"},
			]},
		}
		concourse.decision == expected with input as input_fixture
	}
}

test_expose_pipeline_denied if {
	input_fixture := {"action": "ExposePipeline", "team": "foo", "pipeline": "bar"}
	expected := {
		"allowed": false,
		"reasons": {"Violation: Pipeline cannot be public/exposed. Pipeline: foo/bar. Documentation: https://pix4dbug.atlassian.net/wiki/x/L4CaJgE"},
	}

	concourse.decision == expected with input as input_fixture
}

test_misconfigured_polling_git_resource_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"resources": [
				{"name": "image.docker", "type": "registry-image"},
				{"name": "polling-only.git", "type": "git"},
			]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: polling-only.git. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE"},
		}

		concourse.decision == expected with input as input_fixture
	}
}

test_misconfigured_git_resource_with_both_webhook_and_check_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"resources": [
				{"name": "image.docker", "type": "registry-image"},
				{"name": "check-and-webhook.git", "type": "git", "check_every": "24h", "webhook_token": "((concourse_gh_webhook))"},
			]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: check-and-webhook.git. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE"},
		}

		concourse.decision == expected with input as input_fixture
	}
}

test_misconfigured_git_resource_with_too_frequent_polling_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"resources": [
				{"name": "image.docker", "type": "registry-image"},
				{"name": "too-frequent-check.git", "type": "git", "check_every": "1m"},
			]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: too-frequent-check.git. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE"},
		}

		concourse.decision == expected with input as input_fixture
	}
}

test_multiple_misconfigured_git_resources_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"resources": [
				{"name": "image.docker", "type": "registry-image"},
				{"name": "too-frequent-check.git", "type": "git", "check_every": "7m"},
				{"name": "polling-only.git", "type": "git"},
			]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Git resource must have webhook_token or check_every: 24h configured. Found misconfigured git resources: polling-only.git,too-frequent-check.git. Documentation: https://pix4dbug.atlassian.net/wiki/x/PoCfJgE"},
		}

		concourse.decision == expected with input as input_fixture
	}
}

test_misconfigured_job_without_max_in_flight_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"jobs": [{"name": "job-1"}]},
		}
		expected := {
			"allowed": false,
			"block": false,
			"reasons": {"Violation: Each job must have max_in_flight key configured. Found misconfigured job: job-1. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE"},
		}

		concourse.decision == expected with input as input_fixture
	}
}

test_misconfigured_job_wrong_max_in_flight_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"jobs": [{"name": "job-1", "max_in_flight": 2}]},
		}
		expected := {
			"allowed": false,
			"block": false,
			"reasons": {"Violation: Each job must have max_in_flight key set to 1. Found misconfigured job: job-1. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE"},
		}
		concourse.decision == expected with input as input_fixture
	}
}

test_multiple_misconfigured_jobs_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"jobs": [
				{"name": "job-1", "max_in_flight": 2},
				{"name": "job-2"},
				{"name": "job-3", "max_in_flight": 1},
			]},
		}
		expected := {
			"allowed": false,
			"block": false,
			"reasons": {
				"Violation: Each job must have max_in_flight key set to 1. Found misconfigured job: job-1. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE",
				"Violation: Each job must have max_in_flight key configured. Found misconfigured job: job-2. Documentation: https://pix4dbug.atlassian.net/wiki/x/RwCYJgE",
			},
		}
		concourse.decision == expected with input as input_fixture
	}
}

test_config_with_public_job_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"jobs": [{"name": "public-job", "public": true, "max_in_flight": 1}]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Job cannot be public. Misconfigured job: public-job. Documentation: https://pix4dbug.atlassian.net/wiki/x/N4ChJgE"},
		}
		concourse.decision == expected with input as input_fixture
	}
}

test_config_with_public_resource_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"resources": [{"name": "public-resource", "public": true}]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Resource cannot be public. Misconfigured resource: public-resource. Documentation: https://pix4dbug.atlassian.net/wiki/x/N4ChJgE"},
		}
		concourse.decision == expected with input as input_fixture
	}
}

test_use_image_deprecated_image_type_denied if {
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

test_config_deprecated_image_type_resource_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"resources": [{"name": "resource-1", "type": "docker-image"}]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Cannot use docker-image resource type. Misconfigured resource: resource-1. Documentation: https://pix4dbug.atlassian.net/wiki/x/CADDJgE"},
		}

		concourse.decision == expected with input as input_fixture
	}
}

test_config_deprecated_image_type_resource_type_denied if {
	actions := {"SaveConfig", "SetPipeline"}

	every action in actions {
		input_fixture := {
			"action": action,
			"data": {"resource_types": [{"name": "resource-1", "type": "docker-image"}]},
		}
		expected := {
			"allowed": false,
			"reasons": {"Violation: Cannot use docker-image resource type. Misconfigured resource type: resource-1. Documentation: https://pix4dbug.atlassian.net/wiki/x/CADDJgE"},
		}

		concourse.decision == expected with input as input_fixture
	}
}

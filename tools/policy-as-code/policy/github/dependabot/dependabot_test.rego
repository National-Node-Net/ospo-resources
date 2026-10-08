# SPDX-License-Identifier: Apache-2.0
# © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
package github.dependabot_test

import data.github.dependabot

github_actions_omit_msg := "Dependabot update configuration for 'github-actions' must omit 'target-branch' so updates target the repository default branch"
valid_groups := {"versions": {}}

# Mock repository metadata for Git Flow
git_flow_repo := {
	"defaultBranch": "main",
	"hasDevelopBranch": true,
}

# Helper to check if deny is empty
no_violations if {
	count(dependabot.deny) == 0
}

test_denies_github_actions_with_target_branch_develop if {
	mock_input := {"updates": [{
		"package-ecosystem": "github-actions",
		"target-branch": "develop",
		"groups": valid_groups,
	}]}
	dependabot.deny == {github_actions_omit_msg} with input as mock_input with data.repository as git_flow_repo
}

test_denies_github_actions_with_target_branch_main if {
	mock_input := {"updates": [{
		"package-ecosystem": "github-actions",
		"target-branch": "main",
		"groups": valid_groups,
	}]}
	dependabot.deny == {github_actions_omit_msg} with input as mock_input with data.repository as git_flow_repo
}

test_allows_github_actions_without_target_branch if {
	mock_input := {"updates": [{"package-ecosystem": "github-actions", "groups": valid_groups}]}
	no_violations with input as mock_input with data.repository as git_flow_repo
}

test_denies_when_non_github_actions_target_branch_is_not_develop if {
	msg := "Dependabot update configuration for 'npm' must target 'develop'"
	mock_input := {"updates": [{
		"package-ecosystem": "npm",
		"target-branch": "main",
		"groups": valid_groups,
	}]}
	dependabot.deny[msg] with input as mock_input with data.repository as git_flow_repo
}

test_denies_when_non_github_actions_target_branch_is_missing if {
	msg := "Dependabot update configuration for 'pip' is missing 'target-branch'"
	mock_input := {"updates": [{"package-ecosystem": "pip", "groups": valid_groups}]}
	dependabot.deny[msg] with input as mock_input with data.repository as git_flow_repo
}

test_allows_non_github_actions_when_target_branch_is_develop if {
	mock_input := {"updates": [{
		"package-ecosystem": "pip",
		"target-branch": "develop",
		"groups": valid_groups,
	}]}
	no_violations with input as mock_input with data.repository as git_flow_repo
}

test_multiple_updates_with_mixed_compliance if {
	mock_input := {"updates": [
		{"package-ecosystem": "github-actions", "groups": valid_groups},
		{
			"package-ecosystem": "npm",
			"target-branch": "develop",
			"groups": valid_groups,
		},
		{
			"package-ecosystem": "pip",
			"target-branch": "main",
			"groups": valid_groups,
		},
	]}
	msg := "Dependabot update configuration for 'pip' must target 'develop'"
	dependabot.deny == {msg} with input as mock_input with data.repository as git_flow_repo
}

test_multiple_updates_all_missing_target_branch if {
	mock_input := {"updates": [
		{"package-ecosystem": "npm", "groups": valid_groups},
		{"package-ecosystem": "pip", "groups": valid_groups},
	]}
	count(dependabot.deny) == 2 with input as mock_input with data.repository as git_flow_repo
}

test_ignores_non_github_actions_rules_when_not_git_flow if {
	# Repository with no develop branch gets ignored, but github-actions rule still applies
	non_git_flow_repo := {
		"defaultBranch": "main",
		"hasDevelopBranch": false,
	}

	mock_input := {"updates": [{
		"package-ecosystem": "npm",
		"target-branch": "main",
		"groups": valid_groups,
	}]}
	no_violations with input as mock_input with data.repository as non_git_flow_repo
}

test_ignores_non_github_actions_rules_when_repository_data_is_missing if {
	mock_input := {"updates": [{
		"package-ecosystem": "npm",
		"target-branch": "main",
		"groups": valid_groups,
	}]}
	no_violations with input as mock_input
}

test_denies_github_actions_regardless_of_repository_data if {
	mock_input := {"updates": [{
		"package-ecosystem": "github-actions",
		"target-branch": "main",
		"groups": valid_groups,
	}]}
	dependabot.deny == {github_actions_omit_msg} with input as mock_input
}

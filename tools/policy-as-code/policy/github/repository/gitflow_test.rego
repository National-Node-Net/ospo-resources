# SPDX-License-Identifier: Apache-2.0
# © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
package github.repository_test

import data.github.repository

missing_develop_msg := "GitFlow repository must have a 'develop' branch"

test_allows_main_repository_with_develop_branch if {
	repo := {
		"defaultBranch": "main",
		"hasDevelopBranch": true,
		"repositoryName": "example",
	}
	count(repository.deny) == 0 with data.repository as repo
}

test_denies_main_repository_without_develop_branch if {
	repo := {
		"defaultBranch": "main",
		"hasDevelopBranch": false,
		"repositoryName": "example",
	}
	repository.deny == {missing_develop_msg} with data.repository as repo
}

test_allows_repository_with_another_default_branch if {
	repo := {
		"defaultBranch": "process",
		"hasDevelopBranch": false,
		"repositoryName": "example",
	}
	count(repository.deny) == 0 with data.repository as repo
}

test_allows_centrally_exempt_repository_without_develop_branch if {
	repo := {
		"defaultBranch": "main",
		"hasDevelopBranch": false,
		"repositoryName": "example",
	}
	count(repository.deny) == 0 with data.repository as repo with data.github.repository.gitflow_exceptions.repositories as ["example"]
}

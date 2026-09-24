# SPDX-License-Identifier: Apache-2.0
# © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.

# METADATA
# organizations:
# - National Digital Twin Programme
# title: Dependabot Git Flow Target Branch Policy
# description: Require GitHub Actions updates to omit target-branch, and all other ecosystem updates to target 'develop' in Git Flow repositories
package github.dependabot

import data.repository

# METADATA
# title: Determine if repository uses Git Flow
is_git_flow if {
	repository.defaultBranch == "main"
	repository.hasDevelopBranch == true
}

# METADATA
# entrypoint: true
# description: Deny GitHub Actions updates with an explicit target-branch field
deny contains msg if {
	some update in input.updates
	update["package-ecosystem"] == "github-actions"
	"target-branch" in object.keys(update)
	msg := "Dependabot update configuration for 'github-actions' must omit 'target-branch' so updates target the repository default branch"
}

# METADATA
# description: Deny non-GitHub-Actions updates that do not target 'develop' in Git Flow repositories
deny contains msg if {
	is_git_flow
	some i
	package_ecosystem := input.updates[i]["package-ecosystem"]
	package_ecosystem != "github-actions"
	input.updates[i]["target-branch"] != "develop"
	msg := sprintf("Dependabot update configuration for '%v' must target 'develop'", [package_ecosystem])
}

# METADATA
# description: Deny non-GitHub-Actions updates that are missing the 'target-branch' field in Git Flow repositories
deny contains msg if {
	is_git_flow
	some i
	package_ecosystem := input.updates[i]["package-ecosystem"]
	package_ecosystem != "github-actions"
	not input.updates[i]["target-branch"]
	msg := sprintf("Dependabot update configuration for '%v' is missing 'target-branch'", [package_ecosystem])
}

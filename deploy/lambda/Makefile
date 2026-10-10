# Copyright (c) 2026 quantum-box
# SPDX-License-Identifier: MIT

.PHONY: build-GatewayFunction

# SAM can invoke a Makefile from an isolated build directory. Prefer the
# manifest directory when the CLI provides it, while retaining a direct
# `make` fallback for local artifact checks.
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SOURCE_DIR := $(MAKEFILE_DIR)
ifneq ($(strip $(SAM_CLI_MANIFEST)),)
MANIFEST_DIR := $(dir $(abspath $(SAM_CLI_MANIFEST)))
ifneq ($(wildcard $(MANIFEST_DIR)handler.mjs),)
SOURCE_DIR := $(MANIFEST_DIR)
endif
endif

# SAM invokes this target with ARTIFACTS_DIR pointing at the isolated Lambda
# build directory. Keep provider development dependencies, test fixtures,
# tunnel credentials, and the Rust workspace out of the deployment package.
build-GatewayFunction:
	mkdir -p "$(ARTIFACTS_DIR)/lambda" "$(ARTIFACTS_DIR)/gateway"
	cp "$(SOURCE_DIR)handler.mjs" "$(ARTIFACTS_DIR)/lambda/handler.mjs"
	cp "$(SOURCE_DIR)../gateway/index.mjs" "$(ARTIFACTS_DIR)/gateway/index.mjs"

#!/usr/bin/env bash
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0


set -e

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python3 -m pip install black==21.12b0 isort==5.10.1 click==8.0.4
black --config .github/linters/.python-black .
isort --sp .github/linters/.isort.cfg .
deactivate

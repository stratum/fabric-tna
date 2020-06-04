# Copyright 2019-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

# Docker image to run PTF-based data plane tests for ONOS fabric.p4

FROM bitnami/minideb:stretch as builder

ENV BUILD_DEPS \
    python-pip \
    python-setuptools \
    git
RUN install_packages $BUILD_DEPS

RUN mkdir -p /ouput

ENV PIP_DEPS \
    git+https://github.com/p4lang/scapy-vxlan \
    git+https://github.com/p4lang/ptf.git
RUN pip install --no-cache-dir --root /output $PIP_DEPS

FROM opennetworking/p4mn:stable as runtime

LABEL maintainer="onos-dev@onosproject.org"
LABEL description="Docker image to run PTF-based data plane tests for ONOS fabric.p4"
LABEL url="https://github.com/opennetworkinglab/fabric-p4test"

ENV RUNTIME_DEPS \
    make
RUN install_packages $RUNTIME_DEPS

COPY --from=builder /output /

ENV DOCKER_RUN true

ENTRYPOINT []
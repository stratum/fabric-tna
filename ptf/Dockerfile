# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
ARG TREX_VER=2.85
ARG BASE_IMAGE=stratumproject/testvectors:ptf-py3

FROM $BASE_IMAGE as builder

ARG TREX_VER
RUN apt-get update && apt-get install -y wget
WORKDIR /tmp
RUN wget https://github.com/cisco-system-traffic-generator/trex-core/archive/v${TREX_VER}.tar.gz
RUN tar xf v${TREX_VER}.tar.gz && \
    mkdir -p /output/trex/lib && \
    mkdir -p /output/trex/external && \
    cp -r trex-core-${TREX_VER}/scripts/automation/trex_control_plane/interactive/* /output/trex/lib && \
    cp -r trex-core-${TREX_VER}/scripts/automation/trex_control_plane/stf/trex_stf_lib /output/trex/lib && \
    cp -r trex-core-${TREX_VER}/scripts/external_libs/* /output/trex/external

FROM $BASE_IMAGE as runtime


COPY --from=builder /output/trex/lib /usr/local/lib/python3.5/dist-packages/
RUN mkdir -p /trex-external
COPY --from=builder /output/trex/external /trex-external
ENV PYTHONPATH=/trex-external:${PYTHONPATH}

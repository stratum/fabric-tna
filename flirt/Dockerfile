# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
ARG TREX_VER=2.85
ARG TREX_EXT_LIBS=/external_libs
ARG TREX_LIBS=/trex_python

FROM alpine:3.12.1 as builder
ARG TREX_VER
ARG TREX_EXT_LIBS
ARG TREX_LIBS
# Install Trex library
ENV TREX_SCRIPT_DIR=/trex-core-${TREX_VER}/scripts
# RUN apt update && apt install -y wget
RUN wget https://github.com/cisco-system-traffic-generator/trex-core/archive/v${TREX_VER}.tar.gz
RUN tar xf v${TREX_VER}.tar.gz && \
    mkdir -p /output/${TREX_EXT_LIBS} && \
    mkdir -p /output/${TREX_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/automation/trex_control_plane/interactive/* /output/${TREX_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/external_libs/* /output/${TREX_EXT_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/automation/trex_control_plane/stf/trex_stf_lib /output/${TREX_LIBS}

FROM ubuntu:20.04 as runtime
ARG TREX_EXT_LIBS
ARG TREX_LIBS
RUN apt update && apt install -y python3-dev build-essential python3-pip git
ADD requirements.txt /
RUN pip3 install -r requirements.txt
ENV TREX_EXT_LIBS=${TREX_EXT_LIBS}
ENV PYTHONPATH=/workspace/trex-scripts:${TREX_EXT_LIBS}:${TREX_LIBS}:/ptf
COPY --from=builder /output /
COPY --from=stratumproject/testvectors:ptf-py3 /usr/lib/python3.5/dist-packages/testvector /usr/lib/python3.8/dist-packages/testvector
COPY --from=stratumproject/testvectors:ptf-py3 /usr/lib/python3.5/dist-packages/target /usr/lib/python3.8/dist-packages/target
COPY --from=stratumproject/testvectors:ptf-py3 /usr/lib/python3.5/dist-packages/portmap /usr/lib/python3.8/dist-packages/portmap
COPY --from=stratumproject/testvectors:ptf-py3 /usr/lib/python3.5/dist-packages/gnmi_ext /usr/lib/python3.8/dist-packages/gnmi_ext
COPY --from=stratumproject/testvectors:ptf-py3 /usr/lib/python3.5/dist-packages/gnmi /usr/lib/python3.8/dist-packages/gnmi
WORKDIR /workspace
ENTRYPOINT [ "python3", "-m", "control" ]

# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
#
# Docker image to run PTF-based tests

ARG GRPC_VER=1.26
ARG PROTOBUF_VER=3.12
ARG SCAPY_VER=2.4.5
ARG PTF_VER=c5299ea2e27386653209af458757b3b15e5dec5d
ARG P4RUNTIME_SHELL_VER=0.0.1
ARG TREX_VER=3b19ddcf67e33934f268b09d3364cd87275d48db
ARG TREX_EXT_LIBS=/external_libs
ARG TREX_LIBS=/trex_python
ARG UNITTEST_XML_REPORTING_VER=3.0.4

FROM python:3.8 as proto-deps

ARG GRPC_VER

ENV BUILD_DEPS \
    autoconf \
    automake \
    ca-certificates \
    curl \
    g++ \
    net-tools
RUN apt-get update
RUN apt-get install -y $BUILD_DEPS
RUN pip install grpcio-tools==$GRPC_VER

RUN mkdir -p /output
RUN echo "Building gnmi proto"
RUN git clone https://github.com/openconfig/gnmi.git /tmp/github.com/openconfig/gnmi
WORKDIR /tmp/github.com/openconfig/gnmi/proto
RUN sed -i "s|github.com/openconfig/gnmi/proto/gnmi_ext|gnmi_ext|g" /tmp/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto

RUN python -m grpc_tools.protoc -I=/tmp/github.com/openconfig/gnmi/proto --python_out=/output gnmi_ext/gnmi_ext.proto
RUN python -m grpc_tools.protoc -I=/tmp/github.com/openconfig/gnmi/proto --python_out=/output --grpc_python_out=/output gnmi/gnmi.proto

RUN echo "Building p4runtime proto"
RUN git clone https://github.com/p4lang/p4runtime.git /tmp/github.com/p4lang/p4runtime
RUN git clone https://github.com/googleapis/googleapis /tmp/github.com/googleapis/googleapis
WORKDIR /tmp/github.com/p4lang/p4runtime/proto
ENV PROTOS="\
/tmp/github.com/p4lang/p4runtime/proto/p4/v1/p4data.proto \
/tmp/github.com/p4lang/p4runtime/proto/p4/v1/p4runtime.proto \
/tmp/github.com/p4lang/p4runtime/proto/p4/config/v1/p4info.proto \
/tmp/github.com/p4lang/p4runtime/proto/p4/config/v1/p4types.proto \
/tmp/github.com/googleapis/googleapis/google/rpc/status.proto \
/tmp/github.com/googleapis/googleapis/google/rpc/code.proto"
RUN python -m grpc_tools.protoc -I=/tmp/github.com/p4lang/p4runtime/proto:/tmp/github.com/googleapis/googleapis --python_out=/output --grpc_python_out=/output $PROTOS

RUN echo "Building testvector proto"
RUN git clone https://github.com/stratum/testvectors /tmp/github.com/stratum/testvectors
WORKDIR /tmp/github.com/stratum/testvectors/proto
RUN python -m grpc_tools.protoc -I=.:/tmp/github.com/openconfig/gnmi/proto:/tmp/github.com/p4lang/p4runtime/proto:/tmp/github.com/googleapis/googleapis --python_out=/output testvector/tv.proto
RUN python -m grpc_tools.protoc -I=. --python_out=/output target/target.proto
RUN python -m grpc_tools.protoc -I=. --python_out=/output portmap/portmap.proto
RUN cp /tmp/github.com/stratum/testvectors/utils/python/tvutils.py /output/testvector/tvutils.py
RUN cp /tmp/github.com/stratum/testvectors/utils/python/pmutils.py /output/portmap/pmutils.py
RUN cp /tmp/github.com/stratum/testvectors/utils/python/targetutils.py /output/target/targetutils.py

RUN touch /output/gnmi_ext/__init__.py
RUN touch /output/gnmi/__init__.py
RUN touch /output/google/__init__.py
RUN touch /output/google/rpc/__init__.py
RUN touch /output/__init__.py
RUN touch /output/p4/__init__.py
RUN touch /output/p4/config/__init__.py
RUN touch /output/p4/config/v1/__init__.py
RUN touch /output/p4/v1/__init__.py
RUN touch /output/testvector/__init__.py
RUN touch /output/target/__init__.py
RUN touch /output/portmap/__init__.py

FROM ubuntu:20.04 as ptf-deps

ARG GRPC_VER
ARG PROTOBUF_VER
ARG SCAPY_VER
ARG PTF_VER
ARG P4RUNTIME_SHELL_VER
ARG UNITTEST_XML_REPORTING_VER

ENV RUNTIME_DEPS \
    python3 \
    python3-pip \
    python3-setuptools \
    git

ENV PIP_DEPS \
    git+https://github.com/p4lang/ptf@$PTF_VER \
    protobuf==$PROTOBUF_VER \
    grpcio==$GRPC_VER \
    p4runtime-shell==$P4RUNTIME_SHELL_VER \
    unittest-xml-reporting==$UNITTEST_XML_REPORTING_VER

RUN apt update && apt install -y $RUNTIME_DEPS
RUN pip3 install --no-cache-dir --root /python_output $PIP_DEPS

# Install TRex deps
FROM alpine:3.12.1 as trex-builder
ARG TREX_VER
ARG TREX_EXT_LIBS
ARG TREX_LIBS
# Install Trex library
ENV TREX_SCRIPT_DIR=/trex-core-${TREX_VER}/scripts
# RUN apt update && apt install -y wget
RUN wget https://github.com/stratum/trex-core/archive/${TREX_VER}.zip
RUN unzip -qq ${TREX_VER}.zip && \
    mkdir -p /output/${TREX_EXT_LIBS} && \
    mkdir -p /output/${TREX_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/automation/trex_control_plane/interactive/* /output/${TREX_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/external_libs/* /output/${TREX_EXT_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/automation/trex_control_plane/stf/trex_stf_lib /output/${TREX_LIBS}

FROM ubuntu:20.04

ARG TREX_EXT_LIBS
ARG TREX_LIBS
ARG SCAPY_VER

#FIXME: Remove tcpdump, netbase after removing ptf
ENV RUNTIME_DEPS \
    make \
    net-tools \
    python3 \
    python3-setuptools \
    iproute2 \
    tcpdump \
    dumb-init \
    python3-dev \
    build-essential \
    python3-pip \
    wget \
    netbase \
    # below packages are necessary dependencies for installing scipy in PyPy
    libatlas-base-dev \
    gfortran

RUN apt update && apt install -y $RUNTIME_DEPS
RUN pip3 install --no-cache-dir scipy==1.5.4 numpy==1.19.4 matplotlib==3.3.3 pyyaml==5.4.1 tenacity==8.0.1

ENV TREX_EXT_LIBS=${TREX_EXT_LIBS}
ENV PYTHONPATH=${TREX_EXT_LIBS}:${TREX_LIBS}
COPY --from=trex-builder /output /
COPY --from=proto-deps /output /usr/lib/python3.8/dist-packages
COPY --from=ptf-deps /python_output /
# Install custom scapy version from TRex
RUN cd ${TREX_EXT_LIBS}/scapy-${SCAPY_VER}/ && python3 setup.py install
# Build pypy from source for traffic trace tests
RUN cd /opt/ && \
    wget -nv https://downloads.python.org/pypy/pypy3.7-v7.3.5-linux64.tar.bz2 && \
    tar xf pypy3.7-v7.3.5-linux64.tar.bz2 && \
    ln -s /opt/pypy3.7-v7.3.5-linux64/bin/pypy /usr/local/bin/pypy
RUN pypy -m ensurepip && \
    pypy -mpip install -U pip wheel
RUN pypy -mpip install --no-cache-dir six scipy==1.5.4 numpy==1.19.4 matplotlib==3.3.3 pyyaml==5.4.1 scapy==2.4.5
RUN ldconfig

ENTRYPOINT []

#!/bin/bash



python3 -u ptf_runner.py --port-map port_map.veth.json \
		--ptf-dir fabric.ptf --cpu-port 320 --device-id 1 \
		--grpc-addr "127.0.0.1:28000" \
		--p4info /p4c-out/p4info.txt \
		--tofino-pipeline-config /p4c-out/pipeline_config.pb.bin \
    --trex-config $TREX_CONFIG \
    # ....... other params
		--profile ${1} \
		${2}


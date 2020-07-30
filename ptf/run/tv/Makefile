define run_tests
$(if $(filter $(DEVICE),tofino),
python -u ptf_runner.py --device $(DEVICE) --port-map $(PORTMAP) \
	--ptf-dir fabric.ptf --cpu-port $(CPUPORT) --device-id 1 \
	--grpc-addr $(GRPCADDR) \
	--p4info /tofino_p4c_out/p4info.txt \
	--tofino-bin /tofino_p4c_out/pipe/tofino.bin \
	--tofino-ctx-json /tofino_p4c_out/pipe/context.json \
	--generate-tv \
	$(2),
python -u ptf_runner.py --device $(DEVICE) --port-map $(PORTMAP) \
	--ptf-dir fabric.ptf --cpu-port $(CPUPORT) --device-id 1 \
	--grpc-addr $(GRPCADDR) \
	--p4info /bmv2_p4c_out/p4info.txt \
	--bmv2-json /bmv2_p4c_out/bmv2.json \
	--generate-tv \
	$(2)
)
endef

.DEFAULT_GOAL := all

_checkenv:
ifndef DEVICE
	$(eval DEVICE = tofino)
endif
ifndef PORTMAP
	$(eval PORTMAP = port_map.veth.json)
endif
ifndef GRPCADDR
	$(eval GRPCADDR = 127.0.0.1:28000)
endif
ifndef CPUPORT
ifeq ($(DEVICE),tofino)
$(eval CPUPORT = 192)
#$(eval CPUPORT = 320)
else
$(eval CPUPORT = 255)
endif
endif
include ../../tests/ptf/Makefile.profiles


all: clean
	@mkdir -p p4build
	docker run -v $(PWD):/fabric-tna --workdir /fabric-tna --rm opennetworking/bf-sde:9.2.0 \
		p4c --target tofino --arch tna \
			-I /fabric-tna/p4src \
			--p4runtime-files /fabric-tna/p4build/p4info.txt \
			-g --verbose 2 \
			-DCPU_PORT=192 \
			-o p4build/ \
			p4src/fabric.p4

clean:
	@rm -rf p4build

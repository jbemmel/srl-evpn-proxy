NAME        := srl/static-vxlan-agent
LAST_COMMIT := $(shell sh -c "git log -1 --pretty=%h")
TODAY       := $(shell sh -c "date +%Y%m%d_%H%M")
TAG         := ${TODAY}.${LAST_COMMIT}
IMG         := ${NAME}:${TAG}
LATEST      := ${NAME}:latest
# HTTP_PROXY  := "http://proxy.lbs.alcatel-lucent.com:8000"

ifndef SR_LINUX_RELEASE
override SR_LINUX_RELEASE="latest"
endif

build:
	sudo docker build --build-arg SRL_EVPN_PROXY_RELEASE=${TAG} \
	                  --build-arg http_proxy=${HTTP_PROXY} \
										--build-arg https_proxy=${HTTP_PROXY} \
	                  --build-arg SR_LINUX_RELEASE="${SR_LINUX_RELEASE}" \
	                  -f ./Dockerfile -t ${IMG} .
	sudo docker tag ${IMG} ${LATEST}

build-submodules:
	make -C srl-baseimage

all: build-submodules build

grpc_eventlet:
	sudo docker build -f ./Dockerfile.grpc_with_eventlet -t srl/grpc-with-eventlet:latest .

auto_agent: build
	sudo docker build -f ./Dockerfile.auto_agent -t srl/evpn_proxy_with_auto_agent_v2:latest .

CREATE_CONTAINER := $(shell docker create ${LATEST})
SET_CONTAINER_ID = $(eval CONTAINER_ID=$(CREATE_CONTAINER))

# Include only essential grpc files? .so file is 139M, this doesn't help much
# mv rpmbuild/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc /tmp
# mkdir -p rpmbuild/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_cython
# mkdir -p rpmbuild/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/experimental/__pycache__
# cp /tmp/grpc/_cython/cygrpc.cpython-36m-x86_64-linux-gnu.so rpmbuild/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_cython/
# cp /tmp/grpc/experimental/__pycache__/eventlet.cpython-36.pyc rpmbuild/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/experimental/__pycache__/
# cp /tmp/grpc/experimental/eventlet.py rpmbuild/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/experimental/

rpm: pipenv
	mkdir -p rpmbuild
	$(SET_CONTAINER_ID)
	docker cp --follow-link ${CONTAINER_ID}:/opt/static-vxlan-agent/ rpmbuild/
	docker rm ${CONTAINER_ID}
	find rpmbuild/ -xtype l -delete # Purge broken symlinks
	# strip rpmbuild/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_cython/cygrpc.cpython-36m-x86_64-linux-gnu.so
	find rpmbuild/ -name *.so | xargs strip
	docker run --rm -v ${PWD}:/tmp -w /tmp goreleaser/nfpm package \
    --config /tmp/fpmConfig.yml \
    --target /tmp \
    --packager rpm
	# rm -rf rpmbuild

# Docker-in-Docker variant - not working yet
# rpm_did: all
#	docker run --privileged --rm -v /var/run/docker.sock:/var/run/docker.sock -v ${PWD}:/tmp -w /tmp ${LATEST} /build_rpm.sh

pipenv:
	sudo docker build --build-arg SRL_EVPN_PROXY_RELEASE=${TAG} \
	                  --build-arg http_proxy=${HTTP_PROXY} \
										--build-arg https_proxy=${HTTP_PROXY} \
	                  --build-arg SR_LINUX_RELEASE="${SR_LINUX_RELEASE}" \
	                  -f ./Dockerfile.pipenv -t ${IMG} .
	sudo docker tag ${IMG} ${LATEST}

ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE AS target-image

# Install BGP library and eBPF packages
RUN sudo pip3 install ryu netns
RUN sudo yum install -y python3-bcc kmod xz

# Install eBPF perf tools?
# RUN sudo yum install -y perf bpftool

# Build gRPC with eventlet support
# Use separate build image and copy only resulting binaries, else 3.4GB
FROM centos:8 AS build-grpc-with-eventlet

# Install build tools
RUN yum install -y python3-pip gcc-c++ git python3-devel openssl-devel

# Need to upgrade pip and setuptools
RUN pip3 install --upgrade pip setuptools

RUN cd /tmp && yum install -y git python3-devel && \
  pip3 install --upgrade pip && \
  git clone https://github.com/jbemmel/grpc.git && \
  cd grpc && \
  git submodule update --init && \
  python3 -m pip install -r requirements.txt && \
  GRPC_PYTHON_BUILD_WITH_CYTHON=1 python3 -m pip install .
# CC=/opt/rh/gcc-toolset-10/root/usr/bin/gcc GRPC_PYTHON_BUILD_WITH_CYTHON=1 GRPC_BUILD_WITH_BORING_SSL_ASM=False pip3 install .
# GRPC_BUILD_WITH_BORING_SSL_ASM="" GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=true GRPC_PYTHON_BUILD_SYSTEM_ZLIB=true
# GRPC_PYTHON_BUILD_EXT_COMPILER_JOBS=1 to see errors

FROM target-image AS final

# Allow provisioning of link-local IPs on interfaces, exclude gateway subnet?
# Issue is that these addresses do not get installed as next hop in the RT
# RUN sudo sed -i.orig "s/'169.254.'/'169.254.1.'/g" /opt/srlinux/models/srl_nokia/models/interfaces/srl_nokia-if-ip.yang

# Add custom grpc, keep default one /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/grpc too
COPY --from=build-grpc-with-eventlet /usr/local/lib64/python3.6/site-packages/grpc /usr/local/lib64/python3.6/site-packages/grpc

# Patch Ryu to support multiple VTEP endpoints per BGP speaker
COPY ryu_enhancements/vrf.py /usr/local/lib/python3.6/site-packages/ryu/services/protocols/bgp/info_base/
COPY ryu_enhancements/bgpspeaker.py /usr/local/lib/python3.6/site-packages/ryu/services/protocols/bgp/

RUN sudo mkdir -p /etc/opt/srlinux/appmgr/ /opt/srlinux/agents/evpn-proxy-agent
COPY --chown=srlinux:srlinux ./srl-evpn-proxy-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/srlinux/agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/srlinux/agents/evpn-proxy-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_EVPN_PROXY_RELEASE="[custom build]"
ENV SRL_EVPN_PROXY_RELEASE=$SRL_EVPN_PROXY_RELEASE

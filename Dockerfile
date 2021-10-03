ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE AS target-image

# Install BGP library and eBPF packages
RUN sudo pip3 install ryu netns # dask tornado distributed
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

# Also build Etherate tool? Too old, not working well
# RUN cd /tmp && git clone https://github.com/jwbensley/Etherate.git && \
#  yum install -y libtool autoconf automake diffutils file make && \
#  cd Etherate && ./configure.sh && make && make install

FROM target-image AS final

# Allow provisioning of link-local IPs on interfaces, exclude gateway subnet?
# Issue is that these addresses do not get installed as next hop in the RT
# RUN sudo sed -i.orig "s/'169.254.'/'169.254.1.'/g" /opt/srlinux/models/srl_nokia/models/interfaces/srl_nokia-if-ip.yang

# Add custom grpc, keep default one /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/grpc too
COPY --from=build-grpc-with-eventlet /usr/local/lib64/python3.6/site-packages/grpc /usr/local/lib64/python3.6/site-packages/grpc

# Add custom built etherate tool
# COPY --from=build-grpc-with-eventlet /usr/local/bin/etherate /usr/local/bin/

# Patch Ryu to support multiple VTEP endpoints per BGP speaker
COPY ryu_enhancements/ /usr/local/lib/python3.6/site-packages/ryu/services/protocols/bgp/

# Integrate vxlan service ping CLI command
COPY src/evpn-proxy-agent/vxlan_service_ping.py /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/srlinux/mgmt/cli/plugins/
RUN sudo sh -c ' echo "vxlan_ping = srlinux.mgmt.cli.plugins.vxlan_service_ping:Plugin" >> /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/srlinux-0.1-py3.6.egg-info/entry_points.txt'

RUN sudo mkdir --mode=0755 -p /etc/opt/srlinux/appmgr/ /opt/demo-agents/evpn-proxy-agent
COPY --chown=srlinux:srlinux ./srl-evpn-proxy-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/demo-agents/

# Add in auto-config agent sources too
# COPY --from=srl/auto-config-v2:latest /opt/demo-agents/ /opt/demo-agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/demo-agents/evpn-proxy-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_EVPN_PROXY_RELEASE="[custom build]"
ENV SRL_EVPN_PROXY_RELEASE=$SRL_EVPN_PROXY_RELEASE

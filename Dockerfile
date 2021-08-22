ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE

# Install BGP library and eBPF packages
RUN sudo pip3 install ryu netns
RUN sudo yum install -y python3-bcc kmod xz

# Install eBPF perf tools?
# RUN sudo yum install -y perf bpftool

# Allow provisioning of link-local IPs on interfaces, exclude gateway subnet?
# Issue is that these addresses do not get installed as next hop in the RT
# RUN sudo sed -i.orig "s/'169.254.'/'169.254.1.'/g" /opt/srlinux/models/srl_nokia/models/interfaces/srl_nokia-if-ip.yang

# Patch Ryu to support multiple VTEP endpoints per BGP speaker
COPY ryu_enhancements/vrf.py /usr/local/lib/python3.6/site-packages/ryu/services/protocols/bgp/info_base/
COPY ryu_enhancements/bgpspeaker.py /usr/local/lib/python3.6/site-packages/ryu/services/protocols/bgp/

# Build gRPC with eventlet support
# TODO use separate build image and copy only resulting binaries
#  removed: sudo pip3 install -r requirements.bazel.txt && \
RUN cd /tmp && sudo yum install -y git python3-devel && \
  git clone https://github.com/jbemmel/grpc.git && \
  cd grpc && \
  git submodule update --init && \
  sudo pip3 install -r requirements.txt

# Split for now
COPY ./src /opt/srlinux/agents/
RUN cd /tmp/grpc && sudo GRPC_PYTHON_BUILD_WITH_CYTHON=1 pip3 install .

RUN sudo mkdir -p /etc/opt/srlinux/appmgr/ /opt/srlinux/agents/evpn-proxy-agent
COPY --chown=srlinux:srlinux ./srl-evpn-proxy-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/srlinux/agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/srlinux/agents/evpn-proxy-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_EVPN_PROXY_RELEASE="[custom build]"
ENV SRL_EVPN_PROXY_RELEASE=$SRL_EVPN_PROXY_RELEASE

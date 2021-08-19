ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE

# Install BGP library and eBPF packages
RUN sudo pip3 install ryu
RUN sudo yum install -y python3-bcc

# Install eBPF perf tools?
# RUN sudo yum install -y perf bpftool

# Allow provisioning of link-local IPs on interfaces, exclude gateway subnet?
# Issue is that these addresses do not get installed as next hop in the RT
# RUN sudo sed -i.orig "s/'169.254.'/'169.254.1.'/g" /opt/srlinux/models/srl_nokia/models/interfaces/srl_nokia-if-ip.yang

RUN sudo mkdir -p /etc/opt/srlinux/appmgr/ /opt/srlinux/agents/evpn-proxy-agent
COPY --chown=srlinux:srlinux ./srl-evpn-proxy-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/srlinux/agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/srlinux/agents/evpn-proxy-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_EVPN_PROXY_RELEASE="[custom build]"
ENV SRL_EVPN_PROXY_RELEASE=$SRL_EVPN_PROXY_RELEASE

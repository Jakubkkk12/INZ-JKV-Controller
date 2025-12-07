from pathlib import Path
from jinja2 import Environment, FileSystemLoader, Template
from pydantic import field_validator
from app.heplers.functions import check_dict_key
from app.network_drivers.base_configuration import BaseConfigBgpTemplatePeerPolicy, BaseConfigBgpTemplatePeerSession, \
    BaseBgpNeighborPeerTemplate, BaseBgpNeighbor, BaseConfigBgpVpnv4UnicastNeighbor, BaseBgpNeighborTimers, Interface, \
    BaseConfigBgpIpv4UnicastNeighbor, BaseBgpIpv4Network, BaseBgpIpv4AggregateAddress, BaseConfigBgpIpv4UnicastVrf

class BgpNeighborTimers(BaseBgpNeighborTimers):
    """Class holds attributes for configuring BGP (Border Gateway Protocol) timers for a neighbor session.

    These timers govern the periodic exchange of keepalive messages and the maximum
    time a BGP session can remain inactive before being declared down.

    Attributes:
        keepalive_interval (int): The interval (in seconds) at which the router sends
            **KEEPALIVE messages** to its BGP neighbor. This value is negotiated
            during session establishment.
        holdtime (int): The **Hold Time** (in seconds) advertised to the BGP neighbor.
            If the router does not receive a KEEPALIVE, UPDATE, or NOTIFICATION message
            from the neighbor within this time, the session is torn down. It is typically
            three times the `keepalive_interval`.
        minimum_neighbor_holdtime (int | None, optional): The **minimum Hold Time** (in seconds)
            that the router is willing to accept from a BGP neighbor. If the neighbor advertises
            a Hold Time lower than this value, the router will use this configured minimum
            instead to prevent quick session resets. Defaults to None.
    """
    pass


class BgpIpv4AggregateAddress(BaseBgpIpv4AggregateAddress):
    """Class holds attributes for configuring an **aggregate (summary) address** under the
    BGP IPv4 Unicast address family.

    BGP aggregation is used to summarize a range of more specific routes into a single,
    less specific route, which helps reduce the size of the global routing table.

    Attributes:
        ipv4_address (str): The **IPv4 network address** of the aggregate route (e.g., '10.0.0.0').
        ipv4_mask (str): The subnet **mask** (in dotted-decimal notation, e.g., '255.0.0.0')
            that defines the length of the aggregate prefix.
        summary_only (bool): A flag that, when **True**, suppresses the advertisement of
            the more specific routes that are covered by this aggregate address. If False,
            both the aggregate and the specific routes are advertised. Defaults to False.
    """
    pass


class BgpIpv4Network(BaseBgpIpv4Network):
    """Class holds attributes for configuring an IPv4 network to be **advertised**
    (injected) into the BGP routing table via the 'network' command.

    This configuration tells the BGP process to search the local router's routing table
    for the specified prefix. If the prefix is present, it is then advertised to BGP neighbors.

    Attributes:
        ipv4_address (str): The **IPv4 network address** of the route to be injected
            into BGP (e.g., '192.168.1.0').
        ipv4_mask (str): The subnet **mask** (in dotted-decimal notation, e.g., '255.255.255.0')
            that defines the length of the prefix.
    """
    pass


class BgpNeighborPeerTemplate(BaseBgpNeighborPeerTemplate):
    """Class holds references to the BGP Peer Session and Peer Policy templates
    that are applied to a specific BGP neighbor.

    Applying templates ensures consistency and simplifies the configuration of BGP
    neighbors by inheriting pre-defined session parameters and route policy rules.

    Attributes:
        session_name (str | None, optional): The name of the pre-configured
            **Peer Session Template** (e.g., 'IBGP-Session') to be inherited by this neighbor.
            This template typically defines session attributes like update source and remote ASN. Defaults to None.
        policy_name (str | None, optional): The name of the pre-configured
            **Peer Policy Template** (e.g., 'VPN-Policy') to be inherited by this neighbor.
            This template typically defines route policy attributes like community signaling and route reflection. Defaults to None.
    """
    @field_validator("policy_name")
    def check_policy_name(cls, v):
        if v is not None and not (1 <= len(v) <= 100):
            raise ValueError("template name can have at most 100 characters")
        return v

    @field_validator("session_name")
    def check_session_name(cls, v):
        if v is not None and not (1 <= len(v) <= 100):
            raise ValueError("template name can have at most 100 characters")
        return v


class BgpNeighbor(BaseBgpNeighbor):
    """Class holds attributes for configuring a BGP (Border Gateway Protocol) neighbor (peer).

    This comprehensive class combines the core neighbor parameters with common policy and
    session settings, typically used when the neighbor configuration **does not fully rely
    on separate BGP templates**. Attributes that are often part of a peer policy or session
    template are included here for direct configuration.

    Attributes:
        ipv4_address (str): The **IPv4 address** of the remote BGP neighbor. This is the
            address used to establish the TCP connection for the BGP session.
        peer_template (BgpNeighborPeerTemplate): An object containing references to
            pre-configured BGP **Peer Session** and **Peer Policy** templates that should
            be applied to this neighbor. Defaults to an empty instance of BgpNeighborPeerTemplate.
        remote_asn (int | None, optional): The **Autonomous System Number (ASN)** of the remote
            BGP neighbor. If this is the same as the local router's ASN, it indicates an iBGP session;
            otherwise, it indicates an eBGP session. Defaults to None.
        ebgp_multihop (int | None, optional): Specifies the **maximum number of hops** for an eBGP session.
            This is used when eBGP neighbors are not directly connected. Defaults to None (directly connected).
        update_source_interface (Interface | None, optional): The structured object representing the
            **interface** (e.g., Loopback0) whose IP address should be used as the source IP address
            for the BGP session. Defaults to None.
        timers (BgpNeighborTimers | None, optional): A structured object defining the
            **keepalive and hold timers** for the BGP session. Defaults to None.
        route_reflector_client (bool): A flag to designate the peer as a **Route Reflector Client (RR Client)**.
            Defaults to False.
        send_community_extended (bool): A flag to enable sending **Extended Community** BGP attributes
            to this peer. Defaults to False.
        send_community_both (bool): A flag to enable sending **both Standard and Extended Community**
            BGP attributes to this peer. Defaults to False.
        as_override (bool): A flag to enable the **AS-Override** feature for eBGP peering. Defaults to False.
        next_hop_self (bool): A flag to enable the **Next-Hop-Self** feature, changing the
            Next-Hop attribute of BGP routes sent to the neighbor to the local router's IP address.
            Defaults to False.
        remove_private_as (bool): A flag to enable the **Remove Private AS** feature from the AS_PATH
            attribute before advertising to an eBGP peer. Defaults to False.
        soft_reconfiguration_inbound (bool): A flag to enable **Soft Reconfiguration Inbound**,
            storing all received routes for policy reapplication. Defaults to False.
        maximum_prefix (int | None, optional): The maximum number of **prefixes** this BGP neighbor
            is allowed to advertise before the session may be reset. Defaults to None.
        soo (str | None, optional): The **Site-of-Origin (SOO)** extended community value
            to be applied to routes advertised to this neighbor. Defaults to None.
        allowas_in (int | None, optional): Configures the **Allow-AS-In** feature, specifying the
            maximum number of times the local ASN is allowed to appear in the AS_PATH received from
            this neighbor. Defaults to None.
    """
    peer_template: BgpNeighborPeerTemplate = BgpNeighborPeerTemplate()
    timers: BgpNeighborTimers | None = None

    @field_validator("maximum_prefix")
    def check_maximum_prefix(cls, v):
        if v is not None and not (1 <= v <= 2147483647):
            raise ValueError("maximum_prefix must be value from 1 to 2147483647")
        return v

    @field_validator("allowas_in")
    def check_allowas_in(cls, v):
        if v is not None and not (1 <= v <= 10):
            raise ValueError("allowas_in must be value from 1 to 10")
        return v


def running_to_BgpNeighborTimers(timers: dict | None) -> BgpNeighborTimers | None:
    """['neighbor']['timers']"""
    if timers is None:
        return None

    try:
        keepalive_interval: int = timers['keepalive-interval']
        holdtime: int = timers['holdtime']
    except KeyError:
        return None

    minimum_neighbor_holdtime: int | None = None
    if check_dict_key(timers, 'minimum-neighbor-hold'):
        minimum_neighbor_holdtime = timers['minimum-neighbor-hold']

    return BgpNeighborTimers(keepalive_interval=keepalive_interval, holdtime=holdtime, minimum_neighbor_holdtime=minimum_neighbor_holdtime)

def running_to_update_source_interface(update_source_interface: dict | None) -> Interface | None:
    """['update-source']['interface']"""
    if update_source_interface is None:
        return None

    try:
        interface_name: str = list(update_source_interface.keys())[0]
        interface_id: str = update_source_interface[interface_name]
        return Interface(name=interface_name, id=interface_id)
    except KeyError:
        return None

def running_to_BgpIpv4Network_list(nets: dict | list[dict] | None) -> list[BgpIpv4Network] | None:
    """['network']['with-mask']"""
    if nets is None:
        return None

    networks: list[BgpIpv4Network] | None = []
    if not isinstance(nets, list):
        nets = [nets]

    for net in nets:
        try:
            ipv4_address = net['number']
            ipv4_mask = net['mask']
        except KeyError:
            continue
        networks.append(BgpIpv4Network(ipv4_address=ipv4_address, ipv4_mask=ipv4_mask))

    if len(networks) == 0:
        networks = None

    return networks

def running_to_BgpIpv4AggregateAddress_list(agg_addresses: dict | list[dict] | None) -> list[BgpIpv4AggregateAddress] | None:
    """['aggregate-address']"""
    if agg_addresses is None:
        return None

    aggregate_addresses: list[BgpIpv4AggregateAddress] | None = []
    if not isinstance(agg_addresses, list):
        agg_addresses = [agg_addresses]
    for agg_address in agg_addresses:
        try:
            ipv4_address = agg_address['ipv4-address']
            ipv4_mask = agg_address['ipv4-mask']
        except KeyError:
            continue
        summary_only = False
        if check_dict_key(agg_address, 'summary-only'):
            summary_only = True
        aggregate_addresses.append(BgpIpv4AggregateAddress(ipv4_address=ipv4_address, ipv4_mask=ipv4_mask, summary_only=summary_only))

    if len(aggregate_addresses) == 0:
        aggregate_addresses = None

    return aggregate_addresses


class ConfigBgpTemplatePeerPolicy(BaseConfigBgpTemplatePeerPolicy):
    """Class holds attributes for configuring a BGP Peer Policy template on Cisco IOS-XE device.

    BGP Peer Policy templates allow for the reusable configuration of common attributes
    that are applied to multiple BGP neighbors (peers), simplifying management and ensuring consistency.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which this BGP template is defined.
        name (str): The unique name assigned to this BGP Peer Policy template.
        route_reflector_client (bool): A flag to designate the peer as a **Route Reflector Client (RR Client)**.
            Defaults to False.
        send_community_extended (bool): A flag to enable sending **Extended Community** BGP attributes
            to this peer. Extended communities are used extensively in MPLS VPN environments.
            Defaults to False.
        send_community_both (bool): A flag to enable sending **both Standard and Extended Community**
            BGP attributes to this peer. Defaults to False.
        as_override (bool): A flag to enable the **AS-Override** feature for eBGP peering.
            This replaces the local router's ASN in the AS_PATH attribute of outgoing routes
            with the peer's ASN. Defaults to False.
        next_hop_self (bool): A flag to enable the **Next-Hop-Self** feature. This changes the
            Next-Hop attribute of BGP routes sent to the neighbor to the local router's IP address.
            This is commonly used for iBGP peers. Defaults to False.
        remove_private_as (bool): A flag to enable the **Remove Private AS** feature. This automatically
            strips any private Autonomous System Numbers (ASNs) from the AS_PATH attribute of routes
            before advertising them to an eBGP peer. Defaults to False.
        soft_reconfiguration_inbound (bool): A flag to enable **Soft Reconfiguration Inbound**.
            This causes the router to store all received (pre-policy) routes in memory, allowing
            route policies to be reapplied without tearing down the BGP session. Defaults to False.
        maximum_prefix (int | None, optional): The maximum number of **prefixes** that this BGP neighbor
            is allowed to send to the local router. Exceeding this limit can result in the
            session being reset. Defaults to None.
        soo (str | None, optional): The **Site-of-Origin (SOO)** extended community value
            to be applied to routes advertised to this neighbor. This is used in MPLS VPNs
            to prevent routing loops among sites in the same customer VPN. Defaults to None.
        allowas_in (int | None, optional): Configures the **Allow-AS-In** feature, specifying the
            maximum number of times the local ASN is allowed to appear in the AS_PATH attribute
            received from this neighbor before the route is rejected. Defaults to None.
    """
    render_args: dict | None = None

    @field_validator("name")
    def check_name(cls, v):
        if not (1 <= len(v) <= 100):
            raise ValueError("template name can have at most 100 characters")
        return v

    @field_validator("maximum_prefix")
    def check_maximum_prefix(cls, v):
        if v is not None and not (1 <= v <= 2147483647):
            raise ValueError("maximum_prefix must be value from 1 to 2147483647")
        return v

    @field_validator("allowas_in")
    def check_allowas_in(cls, v):
        if v is not None and not (1 <= v <= 10):
            raise ValueError("allowas_in must be value from 1 to 10")
        return v

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'asn': self.asn,
            'name': self.name,
            'route_reflector_client': self.route_reflector_client,
            'send_community_extended': self.send_community_extended,
            'send_community_both': self.send_community_both,
            'as_override': self.as_override,
            'next_hop_self': self.next_hop_self,
            'remove_private_as': self.remove_private_as,
            'soft_reconfiguration_inbound': self.soft_reconfiguration_inbound,
            'maximum_prefix': self.maximum_prefix,
            'soo': self.soo,
            'allowas_in': self.allowas_in,
        }

    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_template_peer_policy_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_template_peer_policy_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigBgpTemplatePeerPolicy(asn: int, bgp_template_peer_policy: dict | None) -> ConfigBgpTemplatePeerPolicy | None:
    """Converts the raw configuration dictionary for a BGP Peer Policy template
    into a structured ConfigBgpTemplatePeerPolicy model.

    This function processes the peer policy template data, extracting its name and
    various BGP configuration attributes (like route reflector status and community
    send options).

    Args:
        asn (int): The local **Autonomous System Number (ASN)** under which this BGP template is defined.
            This value is required by the ConfigBgpTemplatePeerPolicy model.
        bgp_template_peer_policy (dict | None): A dictionary representing the BGP Peer Policy
            template configuration read from the device's running configuration, typically
            the content of ['data']['native']['router']['bgp']['template']['peer-policy'][<LIST_INDEX>].

    Returns:
        ConfigBgpTemplatePeerPolicy | None: A structured configuration object which maps the running
            configuration, or None if the input dictionary is None or the essential 'name' key is missing.
    """
    if bgp_template_peer_policy is None:
        return None

    try:
        name: str = bgp_template_peer_policy['name']
    except KeyError:
        return None

    route_reflector_client: bool = False
    send_community_extended: bool = False
    send_community_both: bool = False
    as_override: bool = False
    next_hop_self: bool = False
    remove_private_as: bool = False
    soft_reconfiguration_inbound: bool = False
    maximum_prefix: int | None = None
    soo: str | None = None
    allowas_in: int | None = None

    if check_dict_key(bgp_template_peer_policy, 'route-reflector-client'):
        route_reflector_client = True

    if check_dict_key(bgp_template_peer_policy, 'as-override'):
        as_override = True

    if check_dict_key(bgp_template_peer_policy, 'next-hop-self'):
        next_hop_self = True

    if check_dict_key(bgp_template_peer_policy, 'remove-private-as'):
        remove_private_as = True

    if check_dict_key(bgp_template_peer_policy, 'soft-reconfiguration'):
        if bgp_template_peer_policy['soft-reconfiguration'] == "inbound":
            soft_reconfiguration_inbound = True

    try:
        community = bgp_template_peer_policy['send-community']['send-community-where']
        if community == "both":
            send_community_both = True
        elif community == "extended":
            send_community_extended = True
    except KeyError:
        pass

    try:
        allowas_in = int(bgp_template_peer_policy['allowas-in']['as-number'])
    except KeyError:
        pass

    try:
        maximum_prefix = int(bgp_template_peer_policy['maximum-prefix']['max-prefix-no'])
    except KeyError:
        pass

    try:
        soo = bgp_template_peer_policy['soo']
    except KeyError:
        pass

    return ConfigBgpTemplatePeerPolicy(asn=asn, name=name, route_reflector_client=route_reflector_client, send_community_extended=send_community_extended, send_community_both=send_community_both, as_override=as_override, next_hop_self=next_hop_self, remove_private_as=remove_private_as, soft_reconfiguration_inbound=soft_reconfiguration_inbound, maximum_prefix=maximum_prefix, soo=soo, allowas_in=allowas_in)


class ConfigBgpTemplatePeerSession(BaseConfigBgpTemplatePeerSession):
    """Class holds attributes for configuring a BGP Peer Session template on Cisco IOS-XE device.

    BGP Peer Session templates allow for the reusable configuration of core session parameters
    (like remote ASN and update source interface) that are applied to multiple BGP neighbors,
    simplifying management and ensuring consistency across sessions.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which this BGP template is defined.
        name (str): The unique name assigned to this BGP Peer Session template.
        remote_asn (int | None, optional): The **Autonomous System Number (ASN)** of the remote BGP neighbor.
            This is used when configuring eBGP (external BGP) peers. Defaults to None.
        ebgp_multihop (int | None, optional): Specifies the **maximum number of hops** for an eBGP session.
            This is required when the eBGP neighbors are not directly connected (i.e., their TTL needs to be
            increased beyond the default of 1). Defaults to None.
        update_source_interface (Interface | None, optional): The structured object representing the
            **interface** (e.g., Loopback0) whose IP address should be used as the source IP address
            for the BGP session. This is common practice to ensure session stability. Defaults to None.
        timers (BgpNeighborTimers | None, optional): A structured object defining the
            **keepalive and hold timers** for the BGP session. Defaults to None.
    """
    timers: BgpNeighborTimers | None = None
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'asn': self.asn,
            'name': self.name,
            'remote_asn': self.remote_asn,
            'ebgp_multihop': self.ebgp_multihop,
            'timers': self.timers,
            'update_source_interface': self.update_source_interface,
        }

    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_template_peer_session_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_template_peer_session_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigBgpTemplatePeerSession(asn: int, bgp_template_peer_session: dict | None) -> ConfigBgpTemplatePeerSession | None:
    """Converts the raw configuration dictionary for a BGP Peer Session template
    into a structured ConfigBgpTemplatePeerSession model.

    This function processes the peer session template data, extracting its name and
    core session parameters (like remote ASN and update source interface).

    Args:
        asn (int): The local Autonomous System Number (ASN) under which this BGP template
            is defined. This value is required by the ConfigBgpTemplatePeerSession model.
        bgp_template_peer_session (dict | None): A dictionary representing the BGP Peer Session
            template configuration read from the device's running configuration, typically
            the content of ['data']['native']['router']['bgp']['template']['peer-session'][<LIST_INDEX>].

    Returns:
        ConfigBgpTemplatePeerSession | None: A structured configuration object which maps the running
            configuration, or None if the input dictionary is None or the essential 'name' key is missing.
    """
    if bgp_template_peer_session is None:
        return None

    try:
        name: str = bgp_template_peer_session['name']
    except KeyError:
        return None

    remote_asn: int | None = None
    ebgp_multihop: int | None = None
    update_source_interface: Interface | None = None
    timers: BgpNeighborTimers | None = None

    if check_dict_key(bgp_template_peer_session, 'remote-as'):
        remote_asn = int(bgp_template_peer_session['remote-as'])

    if check_dict_key(bgp_template_peer_session, 'ebgp-multihop') and check_dict_key(
            bgp_template_peer_session['ebgp-multihop'], 'max-hop'):
        ebgp_multihop = int(bgp_template_peer_session['ebgp-multihop'].get('max-hop'))

    if check_dict_key(bgp_template_peer_session, 'update-source') and check_dict_key(
            bgp_template_peer_session['update-source'], 'interface'):
        interface_name = list(bgp_template_peer_session['update-source']['interface'].keys())[0]
        interface_id = bgp_template_peer_session['update-source']['interface'][interface_name]
        update_source_interface = Interface(name=interface_name, id=interface_id)

    if check_dict_key(bgp_template_peer_session, 'timers'):
        keepalive_interval = bgp_template_peer_session['timers']['keepalive-interval']
        holdtime = bgp_template_peer_session['timers']['holdtime']
        minimum_neighbor_hold = None
        if check_dict_key(bgp_template_peer_session['timers'], 'minimum-neighbor-hold'):
            minimum_neighbor_hold = bgp_template_peer_session['timers']['minimum-neighbor-hold']
        timers = BgpNeighborTimers(keepalive_interval=keepalive_interval, holdtime=holdtime, minimum_neighbor_holdtime=minimum_neighbor_hold)

    return ConfigBgpTemplatePeerSession(asn=asn, name=name, remote_asn=remote_asn, update_source_interface=update_source_interface, timers=timers, ebgp_multihop=ebgp_multihop)


class ConfigBgpIpv4UnicastNeighbor(BaseConfigBgpIpv4UnicastNeighbor):
    """Class holds attributes to configure a specific BGP neighbor under the IPv4 Unicast address family.

    This configuration is used to activate the exchange of standard IPv4 Unicast routes
    with a specific neighbor. This is the foundational address family used for Internet
    and general-purpose routing in BGP.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which this BGP neighbor
            is defined. This provides the context for the BGP process on the device.
        neighbor (BgpNeighbor): A structured object containing the specific configuration
            details for the remote BGP neighbor, including its IPv4 address, template
            references, and various policy/session parameters.
    """
    neighbor: BgpNeighbor
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'asn': self.asn,
            'neighbor': self.neighbor,
        }

    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_ipv4_unicast_neighbor_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_ipv4_unicast_neighbor_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigBgpIpv4UnicastNeighbor(asn: int, bgp_neighbor: dict | None, bgp_ipv4_unicast_neighbor: dict | None) -> ConfigBgpIpv4UnicastNeighbor | None:
    """Converts raw configuration dictionaries for a BGP neighbor and its IPv4 Unicast
    address-family activation into a structured ConfigBgpIpv4UnicastNeighbor model.

    This function merges the base BGP neighbor parameters (defined globally) with the
    parameters specific to the IPv4 Unicast address family, which are typically used
    to activate the route exchange for a neighbor.

    Note: These two dictionaries must correspond to the same neighbor IP address.

    Args:
        asn (int): The local **Autonomous System Number (ASN)** of the BGP process.
            This value is required by the ConfigBgpIpv4UnicastNeighbor model.
        bgp_neighbor (dict | None): A dictionary representing the base BGP neighbor configuration
            (e.g., address, remote-as, peer-templates) from the global neighbor list, typically
            the content of ['data']['native']['router']['bgp']['neighbor'][<LIST_INDEX>].
        bgp_ipv4_unicast_neighbor (dict | None): A dictionary representing the IPv4 Unicast
            address-family specific configuration for the same neighbor (e.g., activation status,
            inbound/outbound policy overrides), typically the content of
            ['data']['native']['router']['bgp']['address-family']['no-vrf']['ipv4']['ipv4-unicast']['neighbor'][<LIST_INDEX>].

    Returns:
        ConfigBgpIpv4UnicastNeighbor | None: A structured configuration object that maps the running
            configuration for the BGP IPv4 Unicast neighbor, or None if the essential base
            neighbor configuration is missing.
    """
    if bgp_neighbor is None or bgp_ipv4_unicast_neighbor is None:
        return None

    try:
        ipv4_address: str = bgp_neighbor['id']
        _ipv4_address: str = bgp_ipv4_unicast_neighbor['id']
        if ipv4_address != _ipv4_address:
            return None
    except KeyError:
        return None

    remote_asn: int | None = None
    ebgp_multihop: int | None = None
    route_reflector_client: bool = False
    send_community_extended: bool = False
    send_community_both: bool = False
    as_override: bool = False
    next_hop_self: bool = False
    remove_private_as: bool = False
    soft_reconfiguration_inbound: bool = False
    maximum_prefix: int | None = None
    soo: str | None = None
    allowas_in: int | None = None

    if check_dict_key(bgp_neighbor, 'remote-as'):
        remote_asn = bgp_neighbor['remote-as']

    if check_dict_key(bgp_neighbor, 'ebgp-multihop') and check_dict_key(bgp_neighbor['ebgp-multihop'], 'max-hop'):
        ebgp_multihop = bgp_neighbor['ebgp-multihop']['max-hop']

    timers: BgpNeighborTimers | None = None
    if check_dict_key(bgp_neighbor, 'timers'):
        timers = running_to_BgpNeighborTimers(bgp_neighbor['timers'])

    update_source_interface: Interface | None = None
    if check_dict_key(bgp_neighbor, 'update-source') and check_dict_key(bgp_neighbor['update-source'], 'interface'):
        update_source_interface = running_to_update_source_interface(bgp_neighbor['update-source']['interface'])

    peer_template: BgpNeighborPeerTemplate = BgpNeighborPeerTemplate()
    if check_dict_key(bgp_neighbor, 'inherit'):
        if check_dict_key(bgp_neighbor['inherit'], 'peer-session'):
            peer_template.session_name = bgp_neighbor['inherit']['peer-session']

    if check_dict_key(bgp_ipv4_unicast_neighbor, 'inherit'):
        if check_dict_key(bgp_ipv4_unicast_neighbor['inherit'], 'peer-policy'):
            peer_template.policy_name = bgp_ipv4_unicast_neighbor['inherit']['peer-policy']

    if check_dict_key(bgp_ipv4_unicast_neighbor, 'route-reflector-client'):
        route_reflector_client = True
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'send-community') and check_dict_key(
            bgp_ipv4_unicast_neighbor['send-community'], 'send-community-where') and bgp_ipv4_unicast_neighbor['send-community']['send-community-where'] == 'extended':
        send_community_extended = True
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'send-community') and check_dict_key(
            bgp_ipv4_unicast_neighbor['send-community'], 'send-community-where') and bgp_ipv4_unicast_neighbor['send-community']['send-community-where'] == 'both':
        send_community_both = True
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'allowas-in') and check_dict_key(
            bgp_ipv4_unicast_neighbor['allowas-in'], 'as-number'):
        allowas_in = bgp_ipv4_unicast_neighbor['allowas-in']['as-number']
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'as-override'):
        as_override = True
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'maximum-prefix') and check_dict_key(
            bgp_ipv4_unicast_neighbor['maximum-prefix'], 'max-prefix-no'):
        maximum_prefix = bgp_ipv4_unicast_neighbor['maximum-prefix']['max-prefix-no']
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'next-hop-self'):
        next_hop_self = True
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'remove-private-as'):
        remove_private_as = True
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'soft-reconfiguration') and bgp_ipv4_unicast_neighbor['soft-reconfiguration'] == 'inbound':
        soft_reconfiguration_inbound = True
    if check_dict_key(bgp_ipv4_unicast_neighbor, 'soo'):
        soo = bgp_ipv4_unicast_neighbor['soo']


    neighbor = BgpNeighbor(ipv4_address=ipv4_address,
                           peer_template=peer_template,
                           remote_asn=remote_asn,
                           ebgp_multihop=ebgp_multihop,
                           update_source_interface=update_source_interface,
                           timers=timers,
                           route_reflector_client=route_reflector_client,
                           send_community_both=send_community_both,
                           send_community_extended=send_community_extended,
                           as_override=as_override, next_hop_self=next_hop_self,
                           remove_private_as=remove_private_as,
                           soft_reconfiguration_inbound=soft_reconfiguration_inbound,
                           maximum_prefix=maximum_prefix,
                           soo=soo,
                           allowas_in=allowas_in)

    return ConfigBgpIpv4UnicastNeighbor(asn=asn, neighbor=neighbor)


class ConfigBgpVpnv4UnicastNeighbor(BaseConfigBgpVpnv4UnicastNeighbor):
    """Class holds attributes to configure a specific BGP neighbor within the IPv4 VPN address family.

    This configuration is essential for establishing and managing the BGP peering relationship
    that carries VPNv4 routes, which are fundamental to MPLS VPN services. It combines the
    local BGP context (ASN) with the detailed neighbor configuration.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which BGP neighbor is defined.
        neighbor (BaseBgpNeighbor): A structured object containing the specific configuration
            details for the remote BGP neighbor, including its IPv4 address, remote ASN,
            and peer template references.
    """
    neighbor: BgpNeighbor
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'asn': self.asn,
            'neighbor': self.neighbor,
        }

    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_vpnv4_unicast_neighbor_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_vpnv4_unicast_neighbor_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigBgpVpnv4UnicastNeighbor(asn: int, bgp_vpnv4_unicast_neighbor: dict | None) -> ConfigBgpVpnv4UnicastNeighbor | None:
    """Converts the raw configuration dictionary for a BGP neighbor configured under the
    VPNv4 Unicast address family into a structured ConfigBgpVpnv4UnicastNeighbor model.

    This function processes the BGP neighbor data specific to the VPNv4 address family,
    which is essential for carrying MPLS VPN routes between Provider Edge (PE) routers
    and Route Reflectors (RRs). It combines the local BGP context (ASN) with the detailed
    neighbor configuration.

    Args:
        asn (int): The local **Autonomous System Number (ASN)** under which the BGP process
            is running. This value is included in the resulting model.
        bgp_vpnv4_unicast_neighbor (dict | None): A dictionary representing the BGP VPNv4
            Unicast neighbor configuration read from the device's running configuration,
            typically the content of ['data']['native']['router']['bgp']['address-family']['no-vrf']['vpnv4']['vpnv4-unicast']['neighbor'][<LIST_INDEX>].

    Returns:
        ConfigBgpVpnv4UnicastNeighbor | None: A structured configuration object which maps the running
            configuration, or None if the input dictionary is None or the essential neighbor
            IPv4 address key is missing.
    """
    if bgp_vpnv4_unicast_neighbor is None:
        return None

    try:
        ipv4_address: str = bgp_vpnv4_unicast_neighbor['id']
    except KeyError:
        return None

    route_reflector_client: bool = False
    send_community_extended: bool = False
    send_community_both: bool = False
    if check_dict_key(bgp_vpnv4_unicast_neighbor, 'route-reflector-client'):
        route_reflector_client = True
    if check_dict_key(bgp_vpnv4_unicast_neighbor, 'send-community') and check_dict_key(
            bgp_vpnv4_unicast_neighbor['send-community'], 'send-community-where') and bgp_vpnv4_unicast_neighbor['send-community']['send-community-where'] == 'extended':
        send_community_extended = True
    if check_dict_key(bgp_vpnv4_unicast_neighbor, 'send-community') and check_dict_key(
            bgp_vpnv4_unicast_neighbor['send-community'], 'send-community-where') and bgp_vpnv4_unicast_neighbor['send-community']['send-community-where'] == 'both':
        send_community_both = True

    peer_template: BgpNeighborPeerTemplate = BgpNeighborPeerTemplate()
    if check_dict_key(bgp_vpnv4_unicast_neighbor, 'inherit'):
        if check_dict_key(bgp_vpnv4_unicast_neighbor['inherit'], 'peer-policy'):
            peer_template.policy_name = bgp_vpnv4_unicast_neighbor['inherit']['peer-policy']

    return ConfigBgpVpnv4UnicastNeighbor(asn=asn, neighbor=BgpNeighbor(ipv4_address=ipv4_address, peer_template=peer_template, route_reflector_client=route_reflector_client, send_community_extended=send_community_extended, send_community_both=send_community_both))


class ConfigBgpIpv4UnicastVrf(BaseConfigBgpIpv4UnicastVrf):
    """Class holds attributes for configuring the BGP IPv4 Unicast address family specifically
    within the context of a VRF (Virtual Routing and Forwarding) instance.

    This configuration is crucial for enabling the exchange of **VPN-specific IPv4 routes**
    within the VRF's routing table, typically used for customer sites in an MPLS VPN environment.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which the BGP process is running.
            This defines the BGP instance that manages the VRF's routes.
        vrf_name (str): The **unique name** of the VRF instance (e.g., 'VPN_A') to which these
            BGP IPv4 Unicast configurations apply.
        neighbors (list[BgpNeighbor] | None, optional): A list of BGP neighbor configurations
            that are **activated** or specifically configured within this VRF's IPv4 Unicast
            address family. Defaults to None.
        aggregate_addresses (list[BgpIpv4AggregateAddress] | None, optional): A list of
            **aggregate (summary) route** configurations to be generated and advertised
            within the context of this VRF's routing domain. Defaults to None.
        networks (list[BgpIpv4Network] | None, optional): A list of **network** statements
            defining specific IPv4 prefixes that should be injected (advertised) into the
            BGP routing table of this VRF, provided the routes exist in the VRF's routing table.
            Defaults to None.
    """
    neighbors: list[BgpNeighbor] | None = None
    aggregate_addresses: list[BgpIpv4AggregateAddress] | None = None
    networks: list[BgpIpv4Network] | None = None
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'asn': self.asn,
            'vrf_name': self.vrf_name,
            'neighbors': self.neighbors,
            'aggregate_addresses': self.aggregate_addresses,
            'networks': self.networks,
        }

    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_ipv4_unicast_vrf_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'bgp_ipv4_unicast_vrf_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigBgpIpv4UnicastVrf(asn: int, bgp_ipv4_vrf: dict | None) -> ConfigBgpIpv4UnicastVrf | None:
    """Converts the raw configuration dictionary for the BGP IPv4 Unicast address family
    within a VRF into a structured ConfigBgpVrfIpv4Unicast model.

    This function processes the VRF-specific BGP configuration, extracting the VRF name,
    neighbor configurations, aggregate addresses, and network statements relevant to
    the IPv4 Unicast address family inside that VRF.

    Args:
        asn (int): The local **Autonomous System Number (ASN)** under which the BGP process
            is running. This value is included in the resulting model.
        bgp_ipv4_vrf (dict | None): A dictionary representing the BGP IPv4 VRF configuration
            read from the device's running configuration, typically the content of
            ['data']['native']['router']['bgp']['address-family']['with-vrf']['ipv4']['vrf'][<LIST_INDEX>].

    Returns:
        ConfigBgpVrfIpv4Unicast | None: A structured configuration object which maps the running
            configuration, or None if the input dictionary is None or the essential 'name' (vrf_name) key is missing.
    """
    if bgp_ipv4_vrf is None:
        return None

    try:
        vrf_name: str = bgp_ipv4_vrf['name']
    except KeyError:
        return None

    try:
        bgp_ipv4_unicast_vrf = bgp_ipv4_vrf['ipv4-unicast']
    except KeyError:
        return None

    aggregate_addresses: list | None = None
    if check_dict_key(bgp_ipv4_unicast_vrf, 'aggregate-address'):
        aggregate_addresses = running_to_BgpIpv4AggregateAddress_list(bgp_ipv4_unicast_vrf['aggregate-address'])

    networks: list | None = None
    if check_dict_key(bgp_ipv4_unicast_vrf, 'network') and check_dict_key(bgp_ipv4_unicast_vrf['network'], 'with-mask'):
        networks = running_to_BgpIpv4Network_list(bgp_ipv4_unicast_vrf['network']['with-mask'])

    neighbors = []
    if check_dict_key(bgp_ipv4_unicast_vrf, 'neighbor'):
        _neighbors = bgp_ipv4_unicast_vrf['neighbor']
        if not isinstance(_neighbors, list):
            _neighbors = [_neighbors]
        for neighbor in _neighbors:
            try:
                ipv4_address: str = neighbor['id']
            except KeyError:
                continue
            remote_asn: int | None = None
            ebgp_multihop: int | None = None
            route_reflector_client: bool = False
            send_community_extended: bool = False
            send_community_both: bool = False
            as_override: bool = False
            next_hop_self: bool = False
            remove_private_as: bool = False
            soft_reconfiguration_inbound: bool = False
            maximum_prefix: int | None = None
            soo: str | None = None
            allowas_in: int | None = None
            if check_dict_key(neighbor, 'remote-as'):
                remote_asn = neighbor['remote-as']
            if check_dict_key(neighbor, 'ebgp-multihop') and check_dict_key(neighbor['ebgp-multihop'], 'max-hop'):
                ebgp_multihop = neighbor['ebgp-multihop']['max-hop']
            if check_dict_key(neighbor, 'route-reflector-client'):
                route_reflector_client = True
            if check_dict_key(neighbor, 'send-community') and check_dict_key(neighbor['send-community'],
                                                                             'send-community-where') and neighbor['send-community']['send-community-where'] == 'extended':
                send_community_extended = True
            if check_dict_key(neighbor, 'send-community') and check_dict_key(neighbor['send-community'],
                                                                             'send-community-where') and neighbor['send-community']['send-community-where'] == 'both':
                send_community_both = True
            if check_dict_key(neighbor, 'allowas-in') and check_dict_key(neighbor['allowas-in'], 'as-number'):
                allowas_in = neighbor['allowas-in']['as-number']
            if check_dict_key(neighbor, 'as-override'):
                as_override = True
            if check_dict_key(neighbor, 'maximum-prefix') and check_dict_key(neighbor['maximum-prefix'],
                                                                             'max-prefix-no'):
                maximum_prefix = neighbor['maximum-prefix']['max-prefix-no']
            if check_dict_key(neighbor, 'next-hop-self'):
                next_hop_self = True
            if check_dict_key(neighbor, 'remove-private-as'):
                remove_private_as = True
            if check_dict_key(neighbor, 'soft-reconfiguration') and neighbor['soft-reconfiguration'] == 'inbound':
                soft_reconfiguration_inbound = True
            if check_dict_key(neighbor, 'soo'):
                soo = neighbor['soo']

            timers: BgpNeighborTimers | None = None
            if check_dict_key(neighbor, 'timers'):
                timers = running_to_BgpNeighborTimers(neighbor['timers'])

            update_source_interface: Interface | None = None
            if check_dict_key(neighbor, 'update-source') and check_dict_key(neighbor['update-source'], 'interface'):
                update_source_interface = running_to_update_source_interface(neighbor['update-source']['interface'])

            peer_template: BgpNeighborPeerTemplate = BgpNeighborPeerTemplate()
            if check_dict_key(neighbor, 'inherit'):
                if check_dict_key(neighbor['inherit'], 'peer-policy'):
                    peer_template.policy_name = neighbor['inherit']['peer-policy']
                if check_dict_key(neighbor['inherit'], 'peer-session'):
                    peer_template.session_name = neighbor['inherit']['peer-session']

            neighbors.append(BgpNeighbor(ipv4_address=ipv4_address,
                                         peer_template=peer_template,
                                         remote_asn=remote_asn,
                                         ebgp_multihop=ebgp_multihop,
                                         update_source_interface=update_source_interface,
                                         timers=timers,
                                         route_reflector_client=route_reflector_client,
                                         send_community_both=send_community_both,
                                         send_community_extended=send_community_extended,
                                         as_override=as_override, next_hop_self=next_hop_self,
                                         remove_private_as=remove_private_as,
                                         soft_reconfiguration_inbound=soft_reconfiguration_inbound,
                                         maximum_prefix=maximum_prefix,
                                         soo=soo,
                                         allowas_in=allowas_in))

    if len(neighbors) == 0:
        neighbors = None

    return ConfigBgpIpv4UnicastVrf(asn=asn, vrf_name=vrf_name, neighbors=neighbors, aggregate_addresses=aggregate_addresses, networks=networks)

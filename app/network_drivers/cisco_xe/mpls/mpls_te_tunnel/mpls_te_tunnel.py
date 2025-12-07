from pathlib import Path
from pydantic import  field_validator, model_validator
from jinja2 import Environment, FileSystemLoader, Template
from app.heplers.functions import check_dict_key
from app.network_drivers.base_configuration import BaseFastReroute, BaseTunnelPath, BaseTunnelPathExplicit, \
    BaseTunnelPathDynamic, BaseProtectPath, BaseTunnelPathOption, BaseTunnelPriority, BaseConfigMplsTeTunnel, \
    BaseTunnelAffinity
from app.network_drivers.cisco_xe.mpls.heplers import reformat_mpls_te_affinity_str


class FastReroute(BaseFastReroute):
    """Class holds and validates the attributes of the Fast Reroute in MPLS TE Tunnel Configuration on Cisco IOS-XE device.

    Class inherits from BaseFastReroute.

    Attributes:
        enabled (bool): A flag to enable or disable the MPLS TE Fast Reroute feature for the tunnel.
            Enabling this feature provides link protection. Defaults to False.
        node_protect (bool): A flag to enable the **Node Protection** feature, a subset of FRR.
            When enabled, the backup path is computed to bypass not just a failing link,
            but the entire neighboring node. Requires `enabled` to be True. Defaults to False.
    """
    @model_validator(mode='after')
    def check_fast_reroute(self) -> 'FastReroute':
        if not self.enabled and self.node_protect:
            raise ValueError("fast_reroute must be enable to use node protect")
        return self


class TunnelPath(BaseTunnelPath):
    """Class holds and validates attributes of the base Tunnel Path in MPLS TE Tunnel Configuration on Cisco IOS-XE device.

    Class inherits from BaseTunnelPath.

    Attributes:
        id (int): A unique  sequence number for this specific path within the tunnel.
        bandwidth (int | None, optional): The committed bandwidth (in kbps) requested for this path.
            This value is used by the Constrained Shortest Path First (CSPF) algorithm during path computation.
            Defaults to None, indicating no specific bandwidth constraint.
        is_lockdown (bool | None, optional): A flag indicating whether the path should be placed in **lockdown**.
            A path in lockdown will not accept any new tunnels, but existing tunnels remain operational.
            Defaults to None.
    """
    @field_validator("id")
    def check_id(cls, v):
        if not (1 <= v <= 1000):
            raise ValueError("id must be between 1 and 1000")
        return v

    @field_validator("bandwidth")
    def check_bandwidth(cls, v):
        if v is not None and not (0 <= v <= 4294967295):
            raise ValueError("bandwidth must be between 0 and 4294967295")
        return v


class TunnelPathExplicit(BaseTunnelPathExplicit, TunnelPath):
    """Class holds and validates the attributes for an Explicit Path within an MPLS TE Tunnel on Cisco IOS-XE device.

    Class inherits from BaseTunnelPathExplicit, TunnelPath.

    Attributes:
        id (int): A unique  sequence number for this specific path within the tunnel.
        bandwidth (int | None, optional): The committed bandwidth (in kbps) requested for this path.
            This value is used by the Constrained Shortest Path First (CSPF) algorithm during path computation.
            Defaults to None, indicating no specific bandwidth constraint.
        is_lockdown (bool, optional): A flag indicating whether the path should be placed in **lockdown**.
            A path in lockdown will not accept any new tunnels, but existing tunnels remain operational.
            Defaults to False.
        name (str): The name of the pre-defined **IP Explicit Path** object that dictates
            the exact route this tunnel path must follow. This name refers to a
            configured :class:`BaseConfigIpExplicitPath` instance.
        is_explicit (bool): A boolean flag that is always True for this class, explicitly
            indicating that this tunnel path uses an explicit, manually configured route.
            Defaults to True.
    """
    @field_validator("name")
    def check_name(cls, v):
        if not (1 <= len(v) <= 63):
            raise ValueError("name must have between 1 and 63 characters")
        return v

    @field_validator("is_explicit")
    def check_is_explicit(cls, v):
        if not v:
            raise ValueError("is_explicit must be set to True")
        return v


class TunnelPathDynamic(BaseTunnelPathDynamic, TunnelPath):
    """Class holds and validates the attributes for a Dynamically Calculated Path within an MPLS TE Tunnel on Cisco IOS-XE device.

    Class inherits from BaseTunnelPathDynamic, TunnelPath.

    Attributes:
        id (int): A unique  sequence number for this specific path within the tunnel.
        bandwidth (int | None, optional): The committed bandwidth (in kbps) requested for this path.
            This value is used by the Constrained Shortest Path First (CSPF) algorithm during path computation.
            Defaults to None, indicating no specific bandwidth constraint.
        is_lockdown (bool, optional): A flag indicating whether the path should be placed in **lockdown**.
            A path in lockdown will not accept any new tunnels, but existing tunnels remain operational.
            Defaults to False.
        is_dynamic (bool): A boolean flag that is always True for this class, explicitly
            indicating that this tunnel path is calculated dynamically using CSPF. Defaults to True.
    """
    @field_validator("is_dynamic")
    def check_is_dynamic(cls, v):
        if not v:
            raise ValueError("is_dynamic must be set to True")
        return v


class ProtectPath(BaseProtectPath):
    """Class holds and validates attributes to specify a protection path for an MPLS TE tunnel on Cisco IOS-XE device.

    Class inherits from BaseProtectPath.

    Attributes:
        id (int): The unique ID of the **TunnelPath** to which this protection path applies.
            This is typically the ID of the path that is being protected, not the ID of the backup tunnel itself.
        name (str): The name of the **IP Explicit Path** that should be used to configure the protection path's route.
            This name refers to a pre-configured explicit route.
    """
    @field_validator("id")
    def check_id(cls, v):
        if not (1 <= v <= 1000):
            raise ValueError("id must be between 1 and 1000")
        return v

    @field_validator("name")
    def check_name(cls, v):
        if not (1 <= len(v) <= 63):
            raise ValueError("name must have between 1 and 63 characters")
        return v


class TunnelPathOption(BaseTunnelPathOption):
    """Class holds and validates collection of path configurations for an MPLS TE Tunnel on Cisco IOS-XE device.

    Class inherits from BaseTunnelPathOption.

    Attributes:
        paths (list[] | None):
            A list containing one or more path configurations. Defaults to None.
        protect_paths (list[ProtectPath] | None, optional):
            A list of protection path configurations. Defaults to None.
    """
    paths: list[TunnelPathExplicit | TunnelPathDynamic] | None
    protect_paths: list[ProtectPath] | None = None


class TunnelPriority(BaseTunnelPriority):
    """Class holds and validates the setup and hold priorities for an MPLS TE Tunnel on Cisco IOS-XE device.

    Class inherits from BaseTunnelPriority.

    Attributes:
        setup (int): The **Setup Priority** of the tunnel (an integer from 0 to 7, where 0 is the highest priority).
            This value determines the tunnel's priority when competing for bandwidth and resources
            during initial setup or re-establishment. A lower number indicates higher priority.
        hold (int): The **Hold Priority** of the tunnel (an integer from 0 to 7, where 0 is the highest priority).
            This value determines the tunnel's priority when maintaining its reserved resources.
            A tunnel with a lower Hold Priority can preempt resources held by a tunnel with a
            higher (numerically greater) Hold Priority. A lower number indicates higher priority.
    """
    pass


class TunnelAffinity(BaseTunnelAffinity):
    """Class holds the configuration for MPLS Traffic Engineering (TE) Tunnel Affinity.

    Affinity (or administrative groups) is used as a constraint during the
    Constrained Shortest Path First (CSPF) calculation. It ensures that a tunnel
    path uses or avoids links that have been assigned specific color/attribute values.

    Attributes:
        value (str): A hexadecimal string (e.g., "0xDEADBEEF") representing the
            **required** affinity attributes (the "must have" bits) for the tunnel's path.
        mask (str): A hexadecimal string (e.g., "0xFFFFFFFF") representing the
            **significant** affinity bits to consider when matching against link attributes.
            Only bits set to 1 in the mask are compared between the tunnel's required
            value and the link's advertised attributes.
    """
    pass


class ConfigMplsTeTunnel(BaseConfigMplsTeTunnel):
    """Class holds attributes to configure an MPLS Traffic Engineering (TE) Tunnel on Cisco IOS-XE device.

    Class inherits from BaseConfigMplsTeTunnel.

    Attributes:
        tunnel_id (int): A unique numerical identifier for the MPLS TE tunnel on the device.
        description (str): The short description of the tunnel.
        ip_source_interface (str): The name of the local interface whose IP address is used
            as the tunnel's source endpoint (headend).
        destination_ip_address (str): The IP address of the remote node where the tunnel terminates (tailend).
        bandwidth (int): The amount of traffic engineering bandwidth (in kbps) reserved for the tunnel.
        affinity ((BaseTunnelAffinity | None, optional): Configuration parameters of tunnel affinity.
        autoroute_announce (bool): A flag to enable the automatic injection of the tunnel's destination
            route into the IGP (e.g., OSPF or ISIS) routing table. Defaults to False.
        exp_values (list[int] | None, optional): A list of Explicit Path (EXP) values (typically 0-7)
            to be configured for the tunnel. Defaults to None.
        exp_bundle_master (bool): A flag indicating if this tunnel should act as the **master**
            in an EXP-based bundle configuration. Defaults to False.
        exp_bundle_member_tunnel_id (int | None, optional): The ID of the tunnel that is a **member**
            of an EXP-based bundle, where this tunnel acts as the master. Defaults to None.
        fast_reroute (FastReroute | None, optional): Configuration parameters for the
            MPLS TE Fast Reroute (FRR) mechanism, providing link or node protection. Defaults to None.
        path_option (TunnelPathOption | None, optional): Configuration for the paths
            (dynamic or explicit) the tunnel can take. Defaults to None.
        path_selection_metric (str | None, optional): The metric (e.g., 'igp', 'te', 'latency')
            used by the Constrained Shortest Path First (CSPF) algorithm to calculate the tunnel path.
            Defaults to None.
        record_route_enable (bool | None, optional): A flag to enable the recording of the
            router addresses along the tunnel's path (Record Route Object - RRO). Defaults to None.
        priority (TunnelPriority | None, optional): The setup and hold priorities used for
            RSVP-TE resource reservation and preemption. Defaults to None.
    """
    affinity: TunnelAffinity | None = None
    fast_reroute: FastReroute | None = None
    path_option: TunnelPathOption | None = None
    priority: TunnelPriority | None = None
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'tunnel_id': self.tunnel_id,
            'description': self.description,
            'ip_source_interface': self.ip_source_interface,
            'destination_ip_address': self.destination_ip_address,
            'bandwidth': self.bandwidth,
            'affinity': self.affinity,
            'autoroute_announce': self.autoroute_announce,
            'exp_values': self.exp_values,
            'exp_bundle_master': self.exp_bundle_master,
            'exp_bundle_member_tunnel_id': self.exp_bundle_member_tunnel_id,
            'fast_reroute': self.fast_reroute,
            'path_option': self.path_option,
            'path_selection_metric': self.path_selection_metric,
            'priority': self.priority,
            'record_route_enable': self.record_route_enable,
        }

    @field_validator("tunnel_id")
    def check_tunnel_id(cls, v):
        if not (0 <= v <= 2147483647):
            raise ValueError("tunnel_id must be between 0 and 2147483647")
        return v

    @field_validator("description")
    def check_description(cls, v):
        if v is not None and not (0 <= len(v) <= 200):
            raise ValueError("description must be between 0 and 200 characters")
        return v

    @field_validator("bandwidth")
    def check_bandwidth(cls, v):
        if not (0 <= v <= 4294967295):
            raise ValueError("bandwidth must be between 0 and 4294967295")
        return v

    @field_validator("exp_bundle_member_tunnel_id")
    def check_exp_bundle_member_tunnel_id(cls, v):
        if v is not None and not (1 <= v <= 8):
            raise ValueError("exp_bundle_member_tunnel_id must be between 1 and 8")
        return v

    @field_validator("path_selection_metric")
    def check_path_selection_metric(cls, v):
        if v is not None:
            if not ((v == "te") or  (v == "igp")):
                raise ValueError("path_selection_metric must be 'te' or 'igp'")
        return v

    @model_validator(mode='after')
    def check_path(self) -> 'ConfigMplsTeTunnel':
        if 1 <= self.tunnel_id <= 8 and not self.exp_bundle_master:
            raise ValueError("tunnel_id can be between 1 and 8 only if Tunnel is exp bundle master")
        if self.exp_bundle_master and self.exp_bundle_member_tunnel_id is not None:
            raise ValueError("tunnel cannot be master and member tunnel")
        return self

    def get_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'mpls_te_tunnel_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'mpls_te_tunnel_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def get_protect_path(protect_path) -> ProtectPath:
    name: str = None
    id: int = None
    if check_dict_key(protect_path, 'explicit') and check_dict_key(protect_path['explicit'], 'name'):
        name = protect_path['explicit'].get('name')
    if check_dict_key(protect_path, 'id'):
        id = protect_path.get('id')
    return ProtectPath(name=name, id=id)

def get_tunnel_path(tunnel_path) -> TunnelPathExplicit | TunnelPathDynamic:
    id: int = None
    bandwidth: int | None = None
    is_lockdown: bool = False
    if check_dict_key(tunnel_path, 'id'):
        id = tunnel_path.get('id')
    if check_dict_key(tunnel_path, 'explicit'):
        name: str = None
        if check_dict_key(tunnel_path['explicit'], 'bandwidth') and check_dict_key(tunnel_path['explicit']['bandwidth'],
                                                                                   'bandwidth'):
            bandwidth = tunnel_path['explicit']['bandwidth'].get('bandwidth')
        if check_dict_key(tunnel_path['explicit'], 'lockdown'):
            is_lockdown = True
        if check_dict_key(tunnel_path['explicit'], 'name'):
            name = tunnel_path['explicit'].get('name')
        return TunnelPathExplicit(id=id, bandwidth=bandwidth, is_lockdown=is_lockdown, name=name)

    if check_dict_key(tunnel_path, 'dynamic'):
        if check_dict_key(tunnel_path['dynamic'], 'bandwidth') and check_dict_key(tunnel_path['dynamic']['bandwidth'],
                                                                                  'bandwidth'):
            bandwidth = tunnel_path['dynamic']['bandwidth'].get('bandwidth')
        if check_dict_key(tunnel_path['dynamic'], 'lockdown'):
            is_lockdown = True
        return TunnelPathDynamic(id=id, bandwidth=bandwidth, is_lockdown=is_lockdown)

def running_to_ConfigMplsTeTunnel(mpls_te_tunnel: dict | None) -> ConfigMplsTeTunnel | None:
    """Converts the raw configuration dictionary for MPLS TE Tunnel Interface
    configuration into a structured ConfigMplsTeTunnel model.

    This function checks for the presence of the necessary configuration keys to determine
    if the MPLS TE Tunnel is present.

    Args:
        mpls_te_tunnel (dict | None): A dictionary representing the MPLS TE Tunnel configuration
            read from the device's running configuration, typically the content of
            ['data']['native']['interface']['Tunnel'][<LIST_INDEX>].

    Returns:
        ConfigMplsTeTunnel | None: A structured configuration which maps running configuration, or None if no necessary configuration keys are defined.
    """
    if mpls_te_tunnel is None:
        return None

    if not (check_dict_key(mpls_te_tunnel, 'tunnel') and check_dict_key(mpls_te_tunnel['tunnel'],
                                                                        'mode') and check_dict_key(
            mpls_te_tunnel['tunnel']['mode'], 'mpls') and check_dict_key(mpls_te_tunnel['tunnel']['mode']['mpls'],
                                                                         'traffic-eng')):
        # not a mpls te tunnel
        return None

    tunnel_id: int = mpls_te_tunnel.get('name')
    description: str | None = None
    ip_source_interface: str
    destination_ip_address: str
    bandwidth: int = 0
    affinity: TunnelAffinity | None = None
    autoroute_announce: bool = False
    exp_values: list[int] | None = None
    exp_bundle_master: bool = False
    exp_bundle_member_tunnel_id: int | None = None
    path_selection_metric: str | None = None
    record_route_enable: bool | None = None
    fast_reroute: FastReroute | None = FastReroute(enabled=False, node_protect=False)
    path_option: TunnelPathOption | None = None
    priority: TunnelPriority | None = None

    if not (check_dict_key(mpls_te_tunnel, 'ip') and check_dict_key(mpls_te_tunnel['ip'], 'unnumbered')):
        # not valid configuration to load - source ip address must be configured
        return None
    ip_source_interface = mpls_te_tunnel['ip'].get('unnumbered')

    if check_dict_key(mpls_te_tunnel, 'description'):
        description = mpls_te_tunnel.get('description')

    if check_dict_key(mpls_te_tunnel, 'tunnel'):
        tunnel = mpls_te_tunnel['tunnel']

        if not (check_dict_key(tunnel, 'destination-config') and check_dict_key(tunnel['destination-config'], 'ipv4')):
            # not valid configuration to load - destination ip address must be configured
            return None
        destination_ip_address = tunnel['destination-config'].get('ipv4')

        if check_dict_key(tunnel, 'mpls') and check_dict_key(tunnel['mpls'], 'traffic-eng'):
            mpls_te = tunnel['mpls']['traffic-eng']
            if check_dict_key(mpls_te, 'affinity-mask') and check_dict_key(mpls_te['affinity-mask'],
                                                                           'affinity') and check_dict_key(
                    mpls_te['affinity-mask'], 'mask'):
                affinity_value = mpls_te['affinity-mask'].get('affinity')
                affinity_mask = mpls_te['affinity-mask'].get('mask')
                affinity_value = reformat_mpls_te_affinity_str(affinity_value)
                affinity_mask = reformat_mpls_te_affinity_str(affinity_mask)
                affinity = TunnelAffinity(value=affinity_value, mask=affinity_mask)

            if check_dict_key(mpls_te, 'autoroute') and check_dict_key(mpls_te['autoroute'], 'announce'):
                autoroute_announce = True

            if check_dict_key(mpls_te, 'bandwidth') and check_dict_key(mpls_te['bandwidth'], 'bw'):
                bandwidth = mpls_te['bandwidth'].get('bw')

            if check_dict_key(mpls_te, 'exp') and check_dict_key(mpls_te['exp'], 'exp-value'):
                exp_value = mpls_te['exp'].get('exp-value')
                if isinstance(exp_value, list):
                    exp_values = exp_value
                else:
                    exp_values = [exp_value]

            if check_dict_key(mpls_te, 'exp-bundle') and check_dict_key(mpls_te['exp-bundle'], 'master'):
                exp_bundle_master = True

            if check_dict_key(mpls_te, 'fast-reroute'):
                fast_reroute_node_protection: bool = False
                if check_dict_key(mpls_te['fast-reroute'], 'node-protect'):
                    fast_reroute_node_protection = True
                fast_reroute = FastReroute(enabled=True, node_protect=fast_reroute_node_protection)

            if check_dict_key(mpls_te, 'path-selection') and check_dict_key(mpls_te['path-selection'], 'metric'):
                path_selection_metric = mpls_te['path-selection'].get('metric')

            if check_dict_key(mpls_te, 'priority'):
                setup_pr: int = None
                if check_dict_key(mpls_te['priority'], 'setup-priority'):
                    setup_pr = mpls_te['priority'].get('setup-priority')

                hold_pr: int = setup_pr
                if check_dict_key(mpls_te['priority'], 'hold-priority'):
                    hold_pr = mpls_te['priority'].get('hold-priority')
                priority = TunnelPriority(setup=setup_pr, hold=hold_pr)

            if check_dict_key(mpls_te, 'record-route'):
                record_route_enable = True

            if check_dict_key(mpls_te, 'path-option'):
                protect_paths: list[ProtectPath] | None = []
                paths: list[TunnelPathExplicit | TunnelPathDynamic] | None = []
                if check_dict_key(mpls_te['path-option'], 'protect'):
                    pr_paths = mpls_te['path-option'].get('protect')
                    if isinstance(pr_paths, dict):
                        protect_paths.append(get_protect_path(pr_paths))
                    if isinstance(pr_paths, list):
                        for pr_path in pr_paths:
                            protect_paths.append(get_protect_path(pr_path))

                if check_dict_key(mpls_te['path-option'], 'working'):
                    working_paths = mpls_te['path-option'].get('working')
                    if isinstance(working_paths, dict):
                        paths.append(get_tunnel_path(working_paths))
                    if isinstance(working_paths, list):
                        for w_path in working_paths:
                            paths.append(get_tunnel_path(w_path))

                if len(protect_paths) == 0:
                    protect_paths = None
                if len(paths) == 0:
                    paths = None
                path_option = TunnelPathOption(paths=paths, protect_paths=protect_paths)

    return ConfigMplsTeTunnel(tunnel_id=tunnel_id, description=description, ip_source_interface=ip_source_interface, destination_ip_address=destination_ip_address, bandwidth=bandwidth, affinity=affinity, autoroute_announce=autoroute_announce, exp_values=exp_values, exp_bundle_master=exp_bundle_master, exp_bundle_member_tunnel_id=exp_bundle_member_tunnel_id, path_selection_metric=path_selection_metric, record_route_enable=record_route_enable, fast_reroute=fast_reroute, path_option=path_option, priority=priority)
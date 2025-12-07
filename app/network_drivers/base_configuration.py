import ipaddress
import re
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, field_validator, model_validator


class Interface(BaseModel):
    """Class holds attributes of the Interface on Network Device

    Attributes:
        name (str): The name of the Interface
        id (str): The id of the Interface
        full_name (str | None): The full name of the Interface automatically generatyed
    """

    name: str
    id: str
    full_name: str | None = None

    def model_post_init(self, context):
        self.full_name = f"{self.name}{self.id}"

class InterfaceDetails(Interface):
    """Class holds attributes of the Interface on Network Device

    Attributes:
        name (str): The name of the Interface
        id (str): The id of the Interface
        full_name (str | None): The full name of the Interface automatically generatyed
    """
    ipv4_address: str | None = None

    @field_validator("ipv4_address")
    def check_ipv4_address(cls, v):
        if v is not None:
            pattern = r'''
                    ^
                    (?!0\.)
                    (?!127\.)
                    (?!2(?:2[4-9]|3[0-9]|4[0-9]|5[0-5])\.)
                    (?:(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.
                    ){3}
                    (25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)
                    $
                    '''
            if not re.match(pattern, v, re.VERBOSE):
                raise ValueError("ipv4_address must be class A or B or C")
        return v

###########################################################
# BaseConfigIpExplicitPath                                #
###########################################################

class BaseIpExplicitPathEntry(BaseModel):
    """Class holds attributes of the Base Path Entry used in IPv4 Explicit Path.

    This class defines a single hop (entry) within an **IP Explicit Path**,
    which is a manually defined, strict route used for technologies like MPLS Traffic Engineering (TE).

    Class validate the IPv4 address.

    Attributes:
        index (int): The sequence number of the entry in the explicit path.
            Lower numbers represent earlier hops in the path.
        ipv4_address (str): The IPv4 address of the node (router interface) to be included
            at this specific hop in the explicit path.
    """
    index: int
    ipv4_address: str

    @field_validator("ipv4_address")
    def check_ip_address(cls, v):
        pattern = r'''
            ^
            (?!0\.)
            (?!127\.)
            (?!2(?:2[4-9]|3[0-9]|4[0-9]|5[0-5])\.)
            (?:(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.
            ){3}
            (25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)
            $
            '''
        if not re.match(pattern, v, re.VERBOSE):
            raise ValueError("ip_address must be class A or B or C")
        return v


class BaseIpExplicitPathEntryNextAddress(BaseIpExplicitPathEntry):
    """Class holds additional attributes of the Next Address Path Entry used in IPv4 Explicit Path.

    Class inherits from BaseIpExplicitPathEntry.

    Attributes:
        index (int): The sequence number of the entry in the explicit path.
            Lower numbers represent earlier hops in the path.
        ipv4_address (str): The IPv4 address of the node (router interface) to be included
            at this specific hop in the explicit path.
        loose (bool):  A flag to enable the **loose** property of the Next Address Entry.
            When True, the path is allowed to follow any route to reach the specified
            `ip_address`. When False (the default, representing a strict path),
            the path must proceed directly to the specified address. Defaults to False.
    """
    loose: bool = False


class BaseIpExplicitPathEntryExcludeAddress(BaseIpExplicitPathEntry):
    """Class holds additional attributes of the Exclude Address Path Entry used in IPv4 Explicit Path.

    Class inherits from BaseIpExplicitPathEntry.

    Attributes:
        index (int): The sequence number of the entry in the explicit path.
            Lower numbers represent earlier hops in the path.
        ipv4_address (str): The IPv4 address of the node (router interface) to be included
            at this specific hop in the explicit path.
    """
    pass


class BaseConfigIpExplicitPath(BaseModel, ABC):
    """Class holds and validates attributes to configure IPv4 Explicit Path on Network Device.

    This base class defines the configuration for an **IP Explicit Path**, a named,
    pre-defined route used primarily in technologies like MPLS Traffic Engineering (TE).
    The path must be configured using either a list of `next-address` entries or a
    list of `exclude-address` entries, but not both.

    Attributes:
        name (str): The unique name assigned to the IP Explicit Path, used for reference by MPLS TE tunnels.
        path_next_address (list[BaseIpExplicitPathEntryNextAddress] | None, optional): A list of path entries specifying the
            **strict or loose sequence of next-hop IP addresses** the traffic must follow.
            If this is specified, `path_exclude_address` must be None. Defaults to None.
        path_exclude_address (list[BaseIpExplicitPathEntryExcludeAddress] | None, optional): A list of path entries specifying the
            **IP addresses or address ranges that the path must avoid**.
            If this is specified, `path_next_address` must be None. Defaults to None.
    """
    name: str
    path_next_address: list[BaseIpExplicitPathEntryNextAddress] | None = None
    path_exclude_address: list[BaseIpExplicitPathEntryExcludeAddress] | None = None

    @model_validator(mode='after')
    def check_path(self):
        if ((self.path_next_address is None or len(self.path_next_address) <= 0)
                and (self.path_exclude_address is None
                or len(self.path_exclude_address) <= 0)):
            raise ValueError("at least one of path_next_address or path_exclude_address must be specified")
        if self.path_next_address is not None and self.path_exclude_address is not None:
            raise ValueError("both path_next_address and path_exclude_address cannot be specified")
        return self

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

###########################################################
# BaseConfigMplsTeTunnels                                 #
###########################################################

class BaseConfigMplsTeTunnels(BaseModel, ABC):
    """Class holds attributes to configure MPLS Tunnels on Network Device.

    This base class defines the common parameters for enabling or disabling the
    MPLS Traffic Engineering (TE) tunnel feature on a network device.

    Attributes:
        enable (bool): A boolean flag to enable or disable the main MPLS TE tunnel feature.
    """
    enable: bool

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

###########################################################
# BaseConfigMplsTeInterface                               #
###########################################################

class BaseConfigMplsTeInterface(BaseModel, ABC):
    """Class holds attributes to configure specific MPLS TE on Interface on Network Device.

    This base class defines the common configuration parameters for MPLS Traffic Engineering
    (TE) settings applied to a network interface.

    Attributes:
        interface (Interface): The network interface object to which the MPLS TE configuration applies.
        enable (bool): Enable or disable MPLS TE tunnels on the interface.
        backup_path_tunnel_id (int | None): An optional ID of a tunnel to be used as a
            backup path for the interface. Defaults to None.
        attribute_flags (str | None): An optional string representing the attribute flags
            (affinity bits) to be advertised for this interface in the Traffic Engineering Database (TED).
            Defaults to None.
        administrative_weight (int | None): An optional administrative weight (metric) to be
            applied to the interface for MPLS TE path calculation. Defaults to None.
    """
    interface: Interface
    enable: bool
    backup_path_tunnel_id: int | None = None
    attribute_flags: str | None = None
    administrative_weight: int | None = None

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

###########################################################
# BaseConfigMplsTeTunnel                                  #
###########################################################

class BaseFastReroute(BaseModel):
    """Class holds attributes of the Fast Reroute in MPLS TE Tunnel Configuration.

    This base class defines the configuration parameters for **MPLS Traffic Engineering (TE) Fast Reroute (FRR)**,
    a mechanism used to quickly switch traffic to a backup path around a link or node failure
    without waiting for higher-layer routing protocols to converge.

    Attributes:
        enabled (bool): A flag to enable or disable the MPLS TE Fast Reroute feature for the tunnel.
            Enabling this feature provides link protection. Defaults to False.
        node_protect (bool): A flag to enable the **Node Protection** feature, a subset of FRR.
            When enabled, the backup path is computed to bypass not just a failing link,
            but the entire neighboring node. Defaults to False.
    """
    enabled: bool = False
    node_protect: bool = False


class BaseTunnelPath(BaseModel):
    """Class holds attributes of the base Tunnel Path in MPLS TE Tunnel Configuration.

    This base class defines the fundamental properties of a single **path** within an MPLS Traffic Engineering (TE) tunnel.

    Attributes:
        id (int): A unique  sequence number for this specific path within the tunnel.
        bandwidth (int | None, optional): The committed bandwidth (in kbps) requested for this path.
            This value is used by the Constrained Shortest Path First (CSPF) algorithm during path computation.
            Defaults to None, indicating no specific bandwidth constraint.
        is_lockdown (bool, optional): A flag indicating whether the path should be placed in **lockdown**.
            A path in lockdown will not accept any new tunnels, but existing tunnels remain operational.
            Defaults to False.
    """
    id: int
    bandwidth: int | None = None
    is_lockdown: bool = False


class BaseTunnelPathExplicit(BaseTunnelPath):
    """Class holds the attributes for an Explicit Path within an MPLS TE Tunnel.

    This class extends the base :class:`BaseTunnelPath` and is used when the tunnel path
    is defined by a specific, **explicit route** (an IP Explicit Path), rather than
    being calculated dynamically by a Constrained Shortest Path First (CSPF) algorithm.

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
    name: str
    is_explicit: bool = True


class BaseTunnelPathDynamic(BaseTunnelPath):
    """Class holds the attributes for a Dynamically Calculated Path within an MPLS TE Tunnel.

    This class extends the base :class:`BaseTunnelPath` and is used when the tunnel path
    is determined dynamically by the **Constrained Shortest Path First (CSPF)** algorithm,
    based on network topology and constraints (such as bandwidth, administrative weights, etc.).

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
    is_dynamic: bool = True


class BaseProtectPath(BaseModel):
    """Class holds attributes to specify a protection path for an MPLS TE tunnel.

    This class is typically used to reference an already configured tunnel that
    will serve as the **backup or protection path** for a primary MPLS TE tunnel.

    Attributes:
        id (int): The unique ID of the **TunnelPath** to which this protection path applies.
            This is typically the ID of the path that is being protected, not the ID of the backup tunnel itself.
        name (str): The name of the **IP Explicit Path** that should be used to configure the protection path's route.
            This name refers to a pre-configured explicit route.
    """
    id: int
    name: str


class BaseTunnelPathOption(BaseModel):
    """Class holds a collection of path configurations for an MPLS TE Tunnel.

    This class groups the primary (working) paths and any associated protection
    (backup) paths that constitute a single path option for an MPLS TE tunnel.
    A single tunnel can contain multiple path options (e.g., a primary option and a secondary option).

    Attributes:
        paths (list[BaseTunnelPathExplicit | BaseTunnelPathDynamic] | None):
            A list containing one or more path configurations. Defaults to None.
        protect_paths (list[BaseProtectPath] | None, optional):
            A list of protection path configurations. Defaults to None.
    """
    paths: list[BaseTunnelPathExplicit | BaseTunnelPathDynamic] | None
    protect_paths: list[BaseProtectPath] | None = None


class BaseTunnelPriority(BaseModel):
    """Class holds the setup and hold priorities for an MPLS TE Tunnel.

    This class defines the **Setup Priority** and **Hold Priority** values, which are
    used in the resource reservation and preemption mechanisms for MPLS Traffic Engineering (TE)
    tunnels (specifically using RSVP-TE).

    Attributes:
        setup (int): The **Setup Priority** of the tunnel (an integer from 0 to 7, where 0 is the highest priority).
            This value determines the tunnel's priority when competing for bandwidth and resources
            during initial setup or re-establishment. A lower number indicates higher priority.
        hold (int): The **Hold Priority** of the tunnel (an integer from 0 to 7, where 0 is the highest priority).
            This value determines the tunnel's priority when maintaining its reserved resources.
            A tunnel with a lower Hold Priority can preempt resources held by a tunnel with a
            higher (numerically greater) Hold Priority. A lower number indicates higher priority.
    """
    setup: int
    hold: int

    @field_validator("setup")
    def check_setup(cls, v):
        if not (0 <= v <= 7):
            raise ValueError("setup must be between 0 and 7")
        return v

    @field_validator("hold")
    def check_hold(cls, v):
        if not (0 <= v <= 7):
            raise ValueError("hold must be between 0 and 7")
        return v

    @model_validator(mode='after')
    def check_mode(self):
        if self.hold > self.setup:
            raise ValueError("hold must not be greater than setup")
        return self


class BaseTunnelAffinity(BaseModel):
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
    value: str
    mask: str

    @field_validator("value")
    def check_value(cls, v):
        if v is not None and not re.match(r"^0x[0-9a-fA-F]{8}$", v):
            raise ValueError("value must be in format 0x00000000-0xFFFFFFFF")
        return v

    @field_validator("mask")
    def check_mask(cls, v):
        if v is not None and not re.match(r"^0x[0-9a-fA-F]{8}$", v):
            raise ValueError("mask must be in format 0x00000000-0xFFFFFFFF")
        return v

    @model_validator(mode='after')
    def check_affinity(self):
        affinity_int = int(self.value, 16)
        mask_int = int(self.mask, 16)

        not_mask_int = 0xFFFFFFFF ^ mask_int
        result = affinity_int & not_mask_int

        if result != 0:
            raise ValueError("bits cannot be set in affinity if unset in mask")
        return self


class BaseConfigMplsTeTunnel(BaseModel, ABC):
    """Class holds attributes to configure an MPLS Traffic Engineering (TE) Tunnel on Network Device.

    This comprehensive class defines all necessary parameters for provisioning an
    MPLS TE Label Switched Path (LSP), including path definition, traffic engineering
    properties, and protection mechanisms.

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
        fast_reroute (BaseFastReroute | None, optional): Configuration parameters for the
            MPLS TE Fast Reroute (FRR) mechanism, providing link or node protection. Defaults to None.
        path_option (BaseTunnelPathOption | None, optional): Configuration for the paths
            (dynamic or explicit) the tunnel can take. Defaults to None.
        path_selection_metric (str | None, optional): The metric (e.g., 'igp', 'te', 'latency')
            used by the Constrained Shortest Path First (CSPF) algorithm to calculate the tunnel path.
            Defaults to None.
        record_route_enable (bool | None, optional): A flag to enable the recording of the
            router addresses along the tunnel's path (Record Route Object - RRO). Defaults to None.
        priority (BaseTunnelPriority | None, optional): The setup and hold priorities used for
            RSVP-TE resource reservation and preemption. Defaults to None.
    """
    tunnel_id: int
    description: str | None = None
    ip_source_interface: str
    destination_ip_address: str
    bandwidth: int
    affinity: BaseTunnelAffinity | None = None
    autoroute_announce: bool = False
    exp_values: list[int] | None = None
    exp_bundle_master: bool = False
    exp_bundle_member_tunnel_id: int | None = None
    fast_reroute: BaseFastReroute | None = None
    path_option: BaseTunnelPathOption | None = None
    path_selection_metric: str | None = None
    record_route_enable: bool | None = None
    priority: BaseTunnelPriority | None = None

    @field_validator("destination_ip_address")
    def check_destination_ip_address(cls, v):
        pattern = r'''
            ^
            (?!0\.)
            (?!127\.)
            (?!2(?:2[4-9]|3[0-9]|4[0-9]|5[0-5])\.)
            (?:(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.
            ){3}
            (25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)
            $
            '''
        if not re.match(pattern, v, re.VERBOSE):
            raise ValueError("ip_address must be class A or B or C")
        return v

    @field_validator("exp_values")
    def check_exp_values(cls, v):
        if v is not None:
            for exp in v:
                if not (0 <= exp <= 7):
                    raise ValueError("exp_value must be between 0 and 7")
        return v

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass


###########################################################
# BaseConfigVrf                                           #
###########################################################
class BaseVrfRouteTarget(BaseModel):
    """Class holds the Route Target (RT) values for configuring a VRF (Virtual Routing and Forwarding) instance on Network Device.

    Route Targets are extended community attributes used in BGP (Border Gateway Protocol)
    to define which VPN routes should be imported into or exported from a specific VRF.
    They are essential for maintaining VPN segregation and connectivity.

    The supported formats for Route Target strings are:
    * **AS:NN** (Autonomous System number and a number): e.g., '65000:100'
        Format 1: $0.0.0.0-255.255.255.255:0-65535$ (32-bit IP, 16-bit number)
        Format 2: $0-4294967295:0-65535$ (32-bit AS number, 16-bit number)

    Attributes:
        export (list[str] | None, optional): A list of Route Target strings that should be
            **attached** to routes when they are **exported** from this VRF into BGP.
            These routes can then be imported by other VRFs matching these RTs. Defaults to None.
        import_ (list[str] | None, optional): A list of Route Target strings that defines
            which BGP routes should be **imported** into this VRF. Only routes carrying
            one of these RTs will be placed into the VRF's routing table. Defaults to None.
    """
    export: list[str] | None = None
    import_: list[str] | None = None

    @field_validator("export")
    def check_export(cls, v):
        if v is not None:
            for export_rt in v:
                try:
                    asn_ipv4, tag = export_rt.split(":")
                    if "." not in asn_ipv4:
                        asn_ipv4 = int(asn_ipv4)
                    asn_ipv4 = int(ipaddress.IPv4Address(asn_ipv4))
                except (ipaddress.AddressValueError, ValueError):
                    raise ValueError(
                        "route target export correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
                if (not (0 <= int(tag) <= 65535)) or (not (0 <= asn_ipv4 <= 4294967295)):
                    raise ValueError("route target export correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
        return v

    @field_validator("import_")
    def check__import(cls, v):
        if v is not None:
            for import_rt in v:
                try:
                    asn_ipv4, tag = import_rt.split(":")
                    if "." not in asn_ipv4:
                        asn_ipv4 = int(asn_ipv4)
                    asn_ipv4 = int(ipaddress.IPv4Address(asn_ipv4))
                except (ipaddress.AddressValueError, ValueError):
                    raise ValueError(
                        "route target import correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
                if (not (0 <= int(tag) <= 65535)) or (not (0 <= asn_ipv4 <= 4294967295)):
                    raise ValueError(
                        "route target import correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
        return v


class BaseVrfMaximumRoutes(BaseModel):
    """Class holds attributes for configuring maximum route limits and associated thresholds for a VRF (Virtual Routing and Forwarding) instance.

    This configuration is crucial for preventing a VRF's routing table from consuming
    excessive memory or CPU resources, often acting as a protective measure against
    routing attacks or misconfigurations.

    Attributes:
        max_routes (int): The absolute **maximum number of routes** (prefixes) that the
            VRF's routing table is allowed to hold. If this limit is exceeded, new routes
            are typically dropped, and logging/alerts may be triggered.
        warning_only (bool): A flag to configure the action when `max_routes` is exceeded.
            If **True**, the router logs a message but **continues to accept** new routes
            (it acts only as a warning mechanism). If False (the default behavior),
            exceeding the limit results in the suppression of new routes. Defaults to False.
        warning_threshold (int | None, optional): The percentage (0-100) of `max_routes` at which a **warning
            message** should be logged, notifying the operator that the route limit is being approached.
            Defaults to None.
        reinstall_threshold (int | None, optional): The percentage (0-100) of `max_routes` to which the
            number of routes must drop before previously suppressed routes are **re-installed**
            into the routing table. This prevents route flapping when the limit is slightly exceeded.
            Defaults to None.
    """
    max_routes: int
    warning_only: bool = False
    warning_threshold: int | None = None
    reinstall_threshold: int | None = None

    @field_validator("warning_threshold")
    def check_warning_threshold(cls, v):
        if v is not None and not (0 <= v <= 100):
            raise ValueError("warning threshold value can be from 0 to 100")
        return v

    @field_validator("reinstall_threshold")
    def check_reinstall_threshold(cls, v):
        if v is not None and not (0 <= v <= 100):
            raise ValueError("reinstall threshold value can be from 0 to 100")
        return v

    @model_validator(mode='after')
    def check_model(self):
        if not self.warning_only and self.warning_threshold is None:
            raise ValueError("when warning_only is disabled, warning threshold must be specified")
        return self


class BaseConfigVrf(BaseModel, ABC):
    """Class holds attributes for configuring a Virtual Routing and Forwarding (VRF) instance on Network Device.

    A VRF is a technology that allows multiple instances of a routing table to
    coexist within the same router at the same time. This provides network
    segmentation, often used for Multi-Protocol Label Switching (MPLS) VPNs.

    Attributes:
        name (str): The unique name assigned to the VRF instance on the device (e.g., 'VPN_A').
        rd (str | None, optional): The **Route Distinguisher (RD)** value for the VRF.
            The RD is prepended to an IPv4 prefix to create a unique VPNv4 prefix,
            ensuring that overlapping addresses across different VPNs remain distinct.
            It is typically in the format 'AS:NN' or 'IP-address:NN'. Defaults to None.
        route_target (BaseVrfRouteTarget | None, optional): A structured object containing the
            **Route Target (RT)** communities used to control the import and export
            of VPN routes between this VRF and BGP. Defaults to None.
        maximum_routes (BaseVrfMaximumRoutes | None, optional): Configuration for limiting the
            **maximum number of routes** that the VRF's routing table can hold,
            including thresholds for warnings and route re-installation. Defaults to None.
    """
    name: str
    rd: str | None = None
    route_target: BaseVrfRouteTarget | None = None
    maximum_routes: BaseVrfMaximumRoutes | None = None

    @field_validator("rd")
    def check_rd(cls, v):
        if v is not None:
            try:
                asn_ipv4, tag = v.split(":")
                if "." not in asn_ipv4:
                    asn_ipv4 = int(asn_ipv4)
                asn_ipv4 = int(ipaddress.IPv4Address(asn_ipv4))
            except (ipaddress.AddressValueError, ValueError):
                raise ValueError(
                    "rd correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
            if (not (0 <= int(tag) <= 65535)) or (not (0 <= asn_ipv4 <= 4294967295)):
                raise ValueError(
                    "rd correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
        return v

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass


###########################################################
# BaseConfigInterfaceVrf                                  #
###########################################################
class BaseConfigInterfaceVrf(BaseModel, ABC):
    """Class holds attributes to configure a Virtual Routing and Forwarding (VRF) instance
    on a specific network interface on Network Device.

    This configuration isolates the interface's routing table to the specified VRF,
    which is essential for maintaining network segmentation, particularly in MPLS VPN environments.

    Attributes:
        interface (Interface): The network interface object to which the VRF is being applied.
        vrf_name (str): The name of the pre-configured VRF instance (e.g., 'VPN_A')
            that the interface should be associated with.
        ipv4_address (str): The IPv4 address to be assigned to the interface within the context
            of the specified VRF.
        ipv4_mask (str): The subnet mask (in dotted-decimal notation, e.g., '255.255.255.0')
            associated with the interface's IPv4 address.
    """
    interface: Interface
    vrf_name: str
    ipv4_address: str
    ipv4_mask: str

    @model_validator(mode='after')
    def check_mode(self):
        try:
            ipaddress.IPv4Address(self.ipv4_address)
        except (ipaddress.AddressValueError, Exception):
            raise ValueError("ipv4_address must be class A or B or C")

        try:
            ipaddress.IPv4Address(self.ipv4_mask)
        except (ipaddress.AddressValueError, Exception):
            raise ValueError("ipv4_mask incorrect format")

        try:
            network = ipaddress.IPv4Network(f'{self.ipv4_address}/{self.ipv4_mask}', strict=False)
            if self.ipv4_address == str(network.network_address):
                raise ValueError(f"Incorrect ipv4 address with provided mask")
            if self.ipv4_address == str(network.broadcast_address):
                raise ValueError(f"Incorrect ipv4 address with provided mask")
        except ipaddress.NetmaskValueError:
            raise ValueError(f"Incorrect ipv4 address with provided mask")
        return self

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass


###########################################################
# BaseConfigBgpTemplatePeerPolicy                         #
###########################################################
class BaseConfigBgpTemplatePeerPolicy(BaseModel, ABC):
    """Class holds attributes for configuring a BGP Peer Policy template on Network Device.

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
    asn: int
    name: str
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

    @field_validator("asn")
    def check_asn(cls, v):
        if not (1 <= v <= 4294967295):
            raise ValueError("asn must be value from 1 to 4294967295")
        return v

    @field_validator("soo")
    def check_soo(cls, v):
        if v is not None:
            try:
                asn_ipv4, tag = v.split(":")
                if "." not in asn_ipv4:
                    asn_ipv4 = int(asn_ipv4)
                asn_ipv4 = int(ipaddress.IPv4Address(asn_ipv4))
            except (ipaddress.AddressValueError, ValueError):
                raise ValueError(
                    "rd correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
            if (not (0 <= int(tag) <= 65535)) or (not (0 <= asn_ipv4 <= 4294967295)):
                raise ValueError(
                    "rd correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
        return v

    @model_validator(mode='after')
    def check_mode(self):
        if self.send_community_both:
            self.send_community_extended = False
        if self.soft_reconfiguration_inbound and self.maximum_prefix is not None:
            raise ValueError("soft_reconfiguration_inbound and maximum_prefix cannot be both specified")
        return self


    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass


###########################################################
# BaseConfigBgpTemplatePeerSession                        #
###########################################################
class BaseBgpNeighborTimers(BaseModel):
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
    keepalive_interval: int
    holdtime: int
    minimum_neighbor_holdtime: int | None = None

    @field_validator("keepalive_interval")
    def check_keepalive_interval(cls, v):
        if not (0 <= v <= 65535):
            raise ValueError("keepalive_interval must be value from 1 to 65535")
        return v

    @field_validator("holdtime")
    def check_holdtime(cls, v):
        if not (0 <= v <= 65535):
            raise ValueError("holdtime must be value from 1 to 65535")
        return v

    @field_validator("minimum_neighbor_holdtime")
    def check_minimum_neighbor_holdtime(cls, v):
        if v is not None and not (0 <= v <= 65535):
            raise ValueError("minimum_neighbor_holdtime must be value from 1 to 65535")
        return v

    @model_validator(mode='after')
    def check_model(self):
        if self.holdtime <= self.keepalive_interval:
            raise ValueError("holdtime must be greater than keepalive_interval")
        if self.minimum_neighbor_holdtime is not None and self.minimum_neighbor_holdtime > self.holdtime:
            raise ValueError("minimum_neighbor_holdtime must be less or equal than holdtime")
        return self


class BaseConfigBgpTemplatePeerSession(BaseModel, ABC):
    """Class holds attributes for configuring a BGP Peer Session template on a Network Device.

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
        timers (BaseBgpNeighborTimers | None, optional): A structured object defining the
            **keepalive and hold timers** for the BGP session. Defaults to None.
    """
    asn: int
    name: str
    remote_asn: int | None = None
    ebgp_multihop: int | None = None
    update_source_interface: Interface | None = None
    timers: BaseBgpNeighborTimers | None = None

    @field_validator("asn")
    def check_asn(cls, v):
        if not (1 <= v <= 4294967295):
            raise ValueError("asn must be value from 1 to 4294967295")
        return v

    @field_validator("remote_asn")
    def check_remote_asn(cls, v):
        if v is not None and not (1 <= v <= 4294967295):
            raise ValueError("peer remote_asn must be value from 1 to 4294967295")
        return v

    @field_validator("ebgp_multihop")
    def check_ebgp_multihop(cls, v):
        if v is not None and not (1 <= v <= 255):
            raise ValueError("ebgp_multihop must be value from 1 to 255")
        return v

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass


###########################################################
# BaseConfigBgpIpv4UnicastNeighbor                        #
###########################################################
class BaseBgpNeighborPeerTemplate(BaseModel):
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
    session_name: str | None = None
    policy_name: str | None = None


class BaseBgpNeighbor(BaseModel):
    """Class holds attributes for configuring a BGP (Border Gateway Protocol) neighbor (peer).

    This comprehensive class combines the core neighbor parameters with common policy and
    session settings, typically used when the neighbor configuration **does not fully rely
    on separate BGP templates**. Attributes that are often part of a peer policy or session
    template are included here for direct configuration.

    Attributes:
        ipv4_address (str): The **IPv4 address** of the remote BGP neighbor. This is the
            address used to establish the TCP connection for the BGP session.
        peer_template (BaseBgpNeighborPeerTemplate): An object containing references to
            pre-configured BGP **Peer Session** and **Peer Policy** templates that should
            be applied to this neighbor. Defaults to an empty instance of BaseBgpNeighborPeerTemplate.
        remote_asn (int | None, optional): The **Autonomous System Number (ASN)** of the remote
            BGP neighbor. If this is the same as the local router's ASN, it indicates an iBGP session;
            otherwise, it indicates an eBGP session. Defaults to None.
        ebgp_multihop (int | None, optional): Specifies the **maximum number of hops** for an eBGP session.
            This is used when eBGP neighbors are not directly connected. Defaults to None (directly connected).
        update_source_interface (Interface | None, optional): The structured object representing the
            **interface** (e.g., Loopback0) whose IP address should be used as the source IP address
            for the BGP session. Defaults to None.
        timers (BaseBgpNeighborTimers | None, optional): A structured object defining the
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
    ipv4_address: str
    peer_template: BaseBgpNeighborPeerTemplate = BaseBgpNeighborPeerTemplate()
    remote_asn: int | None = None
    ebgp_multihop: int | None = None
    update_source_interface: Interface | None = None
    timers: BaseBgpNeighborTimers | None = None
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

    @field_validator("ipv4_address")
    def check_ipv4_address(cls, v):
        pattern = r'''
                ^
                (?!0\.)
                (?!127\.)
                (?!2(?:2[4-9]|3[0-9]|4[0-9]|5[0-5])\.)
                (?:(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.
                ){3}
                (25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)
                $
                '''
        if not re.match(pattern, v, re.VERBOSE):
            raise ValueError("ipv4_address must be class A or B or C")
        return v

    @field_validator("remote_asn")
    def check_remote_asn(cls, v):
        if v is not None and not (1 <= v <= 4294967295):
            raise ValueError("asn must be value from 1 to 4294967295")
        return v

    @field_validator("ebgp_multihop")
    def check_ebgp_multihop(cls, v):
        if v is not None and not (1 <= v <= 255):
            raise ValueError("ebgp_multihop must be value from 1 to 255")
        return v

    @field_validator("soo")
    def check_soo(cls, v):
        if v is not None:
            try:
                asn_ipv4, tag = v.split(":")
                if "." not in asn_ipv4:
                    asn_ipv4 = int(asn_ipv4)
                asn_ipv4 = int(ipaddress.IPv4Address(asn_ipv4))
            except (ipaddress.AddressValueError, ValueError):
                raise ValueError(
                    "rd correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
            if (not (0 <= int(tag) <= 65535)) or (not (0 <= asn_ipv4 <= 4294967295)):
                raise ValueError(
                    "rd correct format: 0.0.0.0-255.255.255.255:0-65535 or 0-4294967295:0-65535")
        return v

    @model_validator(mode='after')
    def check_mode(self):
        if self.send_community_both:
            self.send_community_extended = False
        if self.soft_reconfiguration_inbound and self.maximum_prefix is not None:
            raise ValueError("soft_reconfiguration_inbound and maximum_prefix cannot be both specified")
        return self


class BaseConfigBgpIpv4UnicastNeighbor(BaseModel, ABC):
    """Class holds attributes to configure a specific BGP neighbor under the IPv4 Unicast address family.

    This configuration is used to activate the exchange of standard IPv4 Unicast routes
    with a specific neighbor. This is the foundational address family used for Internet
    and general-purpose routing in BGP.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which this BGP neighbor
            is defined. This provides the context for the BGP process on the device.
        neighbor (BaseBgpNeighbor): A structured object containing the specific configuration
            details for the remote BGP neighbor, including its IPv4 address, template
            references, and various policy/session parameters.
    """
    asn: int
    neighbor: BaseBgpNeighbor

    @field_validator("asn")
    def check_asn(cls, v):
        if not (1 <= v <= 4294967295):
            raise ValueError("asn must be value from 1 to 4294967295")
        return v

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

###########################################################
# BaseConfigBgpVpnv4UnicastNeighbor                       #
###########################################################
class BaseConfigBgpVpnv4UnicastNeighbor(BaseModel, ABC):
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
    asn: int
    neighbor: BaseBgpNeighbor

    @field_validator("asn")
    def check_asn(cls, v):
        if not (1 <= v <= 4294967295):
            raise ValueError("asn must be value from 1 to 4294967295")
        return v

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

###########################################################
# BaseConfigBgpVrfIpv4Unicast                             #
###########################################################
class BaseBgpIpv4AggregateAddress(BaseModel):
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
    ipv4_address: str
    ipv4_mask: str
    summary_only: bool = False

    @model_validator(mode='after')
    def check_mode(self):
        try:
            ipaddress.IPv4Address(self.ipv4_address)
        except (ipaddress.AddressValueError, Exception):
            raise ValueError("ipv4_address must be class A or B or C")

        try:
            ipaddress.IPv4Address(self.ipv4_mask)
        except (ipaddress.AddressValueError, Exception):
            raise ValueError("ipv4_mask incorrect format")

        try:
            network = ipaddress.IPv4Network(f'{self.ipv4_address}/{self.ipv4_mask}', strict=False)
            if self.ipv4_address != str(network.network_address):
                raise ValueError(f"Incorrect ipv4 network address with provided mask")
        except ipaddress.NetmaskValueError:
            raise ValueError(f"Incorrect mask")
        return self


class BaseBgpIpv4Network(BaseModel):
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
    ipv4_address: str
    ipv4_mask: str

    @model_validator(mode='after')
    def check_mode(self):
        try:
            ipaddress.IPv4Address(self.ipv4_address)
        except (ipaddress.AddressValueError, Exception):
            raise ValueError("ipv4_address must be class A or B or C")

        try:
            ipaddress.IPv4Address(self.ipv4_mask)
        except (ipaddress.AddressValueError, Exception):
            raise ValueError("ipv4_mask incorrect format")

        try:
            network = ipaddress.IPv4Network(f'{self.ipv4_address}/{self.ipv4_mask}', strict=False)
            if self.ipv4_address != str(network.network_address):
                raise ValueError(f"Incorrect ipv4 network address with provided mask")
        except ipaddress.NetmaskValueError:
            raise ValueError(f"Incorrect mask")
        return self


class BaseConfigBgpIpv4UnicastVrf(BaseModel, ABC):
    """Class holds attributes for configuring the BGP IPv4 Unicast address family specifically
    within the context of a VRF (Virtual Routing and Forwarding) instance.

    This configuration is crucial for enabling the exchange of **VPN-specific IPv4 routes**
    within the VRF's routing table, typically used for customer sites in an MPLS VPN environment.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which the BGP process is running.
            This defines the BGP instance that manages the VRF's routes.
        vrf_name (str): The **unique name** of the VRF instance (e.g., 'VPN_A') to which these
            BGP IPv4 Unicast configurations apply.
        neighbors (list[BaseBgpNeighbor] | None, optional): A list of BGP neighbor configurations
            that are **activated** or specifically configured within this VRF's IPv4 Unicast
            address family. Defaults to None.
        aggregate_addresses (list[BaseBgpIpv4AggregateAddress] | None, optional): A list of
            **aggregate (summary) route** configurations to be generated and advertised
            within the context of this VRF's routing domain. Defaults to None.
        networks (list[BaseBgpIpv4Network] | None, optional): A list of **network** statements
            defining specific IPv4 prefixes that should be injected (advertised) into the
            BGP routing table of this VRF, provided the routes exist in the VRF's routing table.
            Defaults to None.
    """
    asn: int
    vrf_name: str
    neighbors: list[BaseBgpNeighbor] | None = None
    aggregate_addresses: list[BaseBgpIpv4AggregateAddress] | None = None
    networks: list[BaseBgpIpv4Network] | None = None

    @field_validator("asn")
    def check_asn(cls, v):
        if not (1 <= v <= 4294967295):
            raise ValueError("asn must be value from 1 to 4294967295")
        return v

    @field_validator("neighbors")
    def check_neighbors(cls, v):
        if v is not None and len(v) == 0:
            raise ValueError("neighbors must contain at list 1 neighbor")
        return v

    @field_validator("aggregate_addresses")
    def check_aggregate_addresses(cls, v):
        if v is not None and len(v) == 0:
            raise ValueError("aggregate_addresses must contain at list 1 aggregate_addresse")
        return v

    @field_validator("networks")
    def check_networks(cls, v):
        if v is not None and len(v) == 0:
            raise ValueError("networks must contain at list 1 network")
        return v

    @abstractmethod
    def get_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

    @abstractmethod
    def delete_config_netconf(self) -> str:
        """Abstract Method used to generate NETCONF payload

        Subclasses MUST implement this method.

        Returns:
            str: NETCONF XML payload
        """
        pass

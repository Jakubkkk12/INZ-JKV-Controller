from pathlib import Path
from jinja2 import Environment, FileSystemLoader, Template
from pydantic import field_validator
from app.heplers.functions import check_dict_key
from app.network_drivers.base_configuration import BaseVrfRouteTarget, BaseConfigVrf, BaseVrfMaximumRoutes


class VrfRouteTarget(BaseVrfRouteTarget):
    """Class holds the Route Target (RT) values for configuring a VRF (Virtual Routing and Forwarding) instance on Cisco IOS-XE device.

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
        _import (list[str] | None, optional): A list of Route Target strings that defines
            which BGP routes should be **imported** into this VRF. Only routes carrying
            one of these RTs will be placed into the VRF's routing table. Defaults to None.
    """
    pass


class VrfMaximumRoutes(BaseVrfMaximumRoutes):
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
    @field_validator("max_routes")
    def check_max_routes(cls, v):
        if not (1 <= v <= 4294967294):
            raise ValueError("max routes value can be from 1 to 4294967294")
        return v


class ConfigVrf(BaseConfigVrf):
    """Class holds attributes for configuring a Virtual Routing and Forwarding (VRF) instance on Cisco IOS-XE device.

    A VRF is a technology that allows multiple instances of a routing table to
    coexist within the same router at the same time. This provides network
    segmentation, often used for Multi-Protocol Label Switching (MPLS) VPNs.

    Attributes:
        name (str): The unique name assigned to the VRF instance on the device (e.g., 'VPN_A').
        rd (str | None, optional): The **Route Distinguisher (RD)** value for the VRF.
            The RD is prepended to an IPv4 prefix to create a unique VPNv4 prefix,
            ensuring that overlapping addresses across different VPNs remain distinct.
            It is typically in the format 'AS:NN' or 'IP-address:NN'. Defaults to None.
        route_target (VrfRouteTarget | None, optional): A structured object containing the
            **Route Target (RT)** communities used to control the import and export
            of VPN routes between this VRF and BGP. Defaults to None.
        maximum_routes (VrfMaximumRoutes | None, optional): Configuration for limiting the
            **maximum number of routes** that the VRF's routing table can hold,
            including thresholds for warnings and route re-installation. Defaults to None.
    """
    route_target: VrfRouteTarget | None = None
    maximum_routes: VrfMaximumRoutes | None = None
    render_args: dict | None = None

    @field_validator("name")
    def check_name(cls, v):
        if v is not None:
            if not (1 <= len( v) <= 32):
                raise ValueError("name can have from 1 to 32 characters")
        return v

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'name': self.name,
            'rd': self.rd,
            'route_target': self.route_target,
            'maximum_routes': self.maximum_routes,
        }

    def get_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'vrf_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'vrf_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigVrf(vrf: dict | None) -> ConfigVrf | None:
    """Converts the raw configuration dictionary for a Virtual Routing and Forwarding (VRF) instance
    into a structured ConfigVrf model.

    This function processes the VRF configuration data, extracting parameters like the VRF name,
    Route Distinguisher (RD), and Route Targets (RTs).

    Args:
        vrf (dict | None): A dictionary representing the VRF definition configuration
            read from the device's running configuration, typically the content of
            ['data']['native']['vrf']['definition'][<LIST_INDEX>].

    Returns:
        ConfigVrf | None: A structured configuration object which maps the running configuration,
            or None if the input dictionary is None or essential keys are missing.
    """
    if vrf is None:
        return None

    if not check_dict_key(vrf, 'name'):
        return None

    name: str = vrf.get('name')
    rd: str | None = None
    route_target: VrfRouteTarget | None = None

    if check_dict_key(vrf, 'rd'):
        rd = vrf.get('rd')

    route_target_export_list: list | None = []
    route_target_import_list: list | None = []
    max_routes: int = None
    warning_only: bool = False
    warning_threshold: int | None = None
    reinstall_threshold: int | None = None
    if check_dict_key(vrf, 'address-family'):
        if not check_dict_key(vrf['address-family'], 'ipv4'):
            return None
        if check_dict_key(vrf['address-family'], 'ipv6'):
            return None
        if check_dict_key(vrf['address-family']['ipv4'], 'route-target'):
            route_target = vrf['address-family']['ipv4'].get('route-target')
            if check_dict_key(route_target, 'export-route-target'):
                route_target_export = route_target.get('export-route-target')
                if check_dict_key(route_target_export, 'without-stitching'):
                    route_target_export_without_stitching = route_target_export.get('without-stitching')
                    if isinstance(route_target_export_without_stitching, dict):
                        route_target_export_without_stitching = [route_target_export_without_stitching]
                    for rt_export in route_target_export_without_stitching:
                        if check_dict_key(rt_export, 'asn-ip'):
                            route_target_export_list.append(rt_export.get('asn-ip'))
            if check_dict_key(route_target, 'import-route-target'):
                route_target_import = route_target.get('import-route-target')
                if check_dict_key(route_target_import, 'without-stitching'):
                    route_target_import_without_stitching = route_target_import.get('without-stitching')
                    if isinstance(route_target_import_without_stitching, dict):
                        route_target_import_without_stitching = [route_target_import_without_stitching]
                    for rt_import in route_target_import_without_stitching:
                        if check_dict_key(rt_import, 'asn-ip'):
                            route_target_import_list.append(rt_import.get('asn-ip'))
        if check_dict_key(vrf['address-family']['ipv4'], 'maximum') and check_dict_key(
                vrf['address-family']['ipv4']['maximum'], 'routes'):
            max_routes = vrf['address-family']['ipv4']['maximum'].get('routes')
            if not check_dict_key(vrf['address-family']['ipv4']['maximum'], 'warning-only'):
                warning_threshold = vrf['address-family']['ipv4']['maximum'].get('threshold')
                if check_dict_key(vrf['address-family']['ipv4']['maximum'], 'reinstall'):
                    reinstall_threshold = vrf['address-family']['ipv4']['maximum'].get('reinstall')
            else:
                warning_only = True

    maximum_routes = None
    if max_routes is not None:
        maximum_routes = VrfMaximumRoutes(max_routes=max_routes, warning_only=warning_only, warning_threshold=warning_threshold, reinstall_threshold=reinstall_threshold)

    if len(route_target_export_list) == 0:
        route_target_export_list = None

    if len(route_target_import_list) == 0:
        route_target_import_list = None

    return ConfigVrf(name=name, rd=rd, route_target=VrfRouteTarget(export=route_target_export_list, import_=route_target_import_list), maximum_routes=maximum_routes)
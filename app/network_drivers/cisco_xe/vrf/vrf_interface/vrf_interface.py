from pathlib import Path
from jinja2 import Environment, FileSystemLoader, Template
from pydantic import field_validator
from app.network_drivers.base_configuration import Interface, BaseConfigInterfaceVrf


class ConfigInterfaceVrf(BaseConfigInterfaceVrf):
    """Class holds attributes to configure a Virtual Routing and Forwarding (VRF) instance
    on a specific network interface on Cisco IOS-XE device.

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
    render_args: dict | None = None

    @field_validator("vrf_name")
    def check_vrf_name(cls, v):
        if v is not None:
            if not (1 <= len(v) <= 32):
                raise ValueError("vrf_name can have from 1 to 32 characters")
        return v

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'interface': self.interface,
            'vrf_name': self.vrf_name,
            'ipv4_address': self.ipv4_address,
            'ipv4_mask': self.ipv4_mask,
        }

    def get_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'vrf_interface_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'vrf_interface_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigInterfaceVrf(interface: Interface, interface_vrf: dict | None) -> ConfigInterfaceVrf | None:
    """Converts the raw configuration dictionary for a VRF (Virtual Routing and Forwarding)
    interface assignment into a structured ConfigInterfaceVrf model.

    This function processes the interface-specific VRF configuration to establish the
    link between a network interface and a defined VRF instance, including the interface's
    IP addressing within that VRF.

    Args:
        interface (Interface): The structured object representing the network interface
            to which this VRF configuration applies.
        interface_vrf (dict | None): A dictionary representing the interface VRF configuration
            read from the device's running configuration, typically the content of
            ['data']['native']['interface'][<INTERFACE_NAME>][<LIST_INDEX>]

    Returns:
        ConfigInterfaceVrf | None: A structured configuration object containing the interface,
            VRF name, and IP details, or None if the input dictionary is None or essential
            configuration keys (vrf name, IP address/mask) are missing.
    """
    if interface_vrf is None:
        return None

    try:
        vrf_name: str = interface_vrf['vrf']['forwarding']
        ipv4_address: str = interface_vrf['ip']['address']['primary']['address']
        ipv4_mask: str = interface_vrf['ip']['address']['primary']['mask']
    except KeyError:
        return None

    return ConfigInterfaceVrf(interface=interface, vrf_name=vrf_name, ipv4_address=ipv4_address, ipv4_mask=ipv4_mask)
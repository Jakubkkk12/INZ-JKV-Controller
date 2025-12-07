from pathlib import Path
from pydantic import field_validator
from jinja2 import Environment, FileSystemLoader, Template
import re
from app.heplers.functions import check_dict_key
from app.network_drivers.base_configuration import Interface, BaseConfigMplsTeInterface
from app.network_drivers.cisco_xe.mpls.heplers import reformat_mpls_te_affinity_str


class ConfigMplsTeInterface(BaseConfigMplsTeInterface):
    """Class holds attributes to configure specific MPLS TE on Interface on Cisco IOS-XE device.

    Class inherits from BaseConfigMplsTeInterface.

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
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'interface': self.interface,
            'enable': self.enable,
            'backup_path_tunnel_id': self.backup_path_tunnel_id,
            'attribute_flags': self.attribute_flags,
            'administrative_weight': self.administrative_weight,
        }

    @field_validator("backup_path_tunnel_id")
    def check_backup_path_tunnel_id(cls, v):
        if v is not None and not (0 <= v <= 2147483647):
            raise ValueError("backup_path_tunnel_id must be between 0 and 2147483647")
        return v

    @field_validator("attribute_flags")
    def check_attribute_flags(cls, v):
        if v is not None and not re.match(r"^0x[0-9a-fA-F]{8}$", v):
            raise ValueError("attribute_flags must be in format 0x00000000-0xFFFFFFFF")
        return v

    @field_validator("administrative_weight")
    def check_administrative_weight(cls, v):
        if v is not None and not (0 <= v <= 4294967295):
            raise ValueError("administrative_weight must be between 0 and 4294967295")
        return v

    def get_config_netconf(self):
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'mpls_te_interface_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self):
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'mpls_te_interface_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigMplsTeInterface(interface: Interface, interface_mpls_te: dict | None) -> ConfigMplsTeInterface | None:
    """Converts the raw configuration dictionary for MPLS Traffic Engineering (TE) Interface
    configuration into a structured ConfigMplsTeInterface model.

    This function checks for the presence of the necessary configuration keys to determine
    if the MPLS TE Interface configuration is present.

    Args:
        interface (Interface): The network interface object to which the MPLS TE configuration applies.
        interface_mpls_te (dict | None): A dictionary representing the MPLS TE configuration
            read from the device's running configuration, typically the content of
            ['data']['native']['interface'][<INTERFACE_NAME>][<LIST_INDEX>]['mpls']['traffic-eng'].

    Returns:
        ConfigMplsTeInterface | None: A structured configuration which maps running configuration, or None if no necessary configuration keys are defined.
    """
    if interface_mpls_te is None:
        return None
    enable: bool = False
    backup_path_tunnel_id: int | None = None
    attribute_flags: str | None = None
    administrative_weight: int | None = None
    if check_dict_key(interface_mpls_te, 'tunnels'):
        enable = True

    if check_dict_key(interface_mpls_te, 'attribute-flags'):
        attribute_flags = interface_mpls_te.get('attribute-flags')
        attribute_flags = reformat_mpls_te_affinity_str(attribute_flags)

    if check_dict_key(interface_mpls_te, 'backup-path'):
        backup_path_tunnel_id = interface_mpls_te['backup-path']['Tunnel'].get('name')

    if check_dict_key(interface_mpls_te, 'administrative-weight'):
        administrative_weight = interface_mpls_te.get('administrative-weight')

    return ConfigMplsTeInterface(interface=interface, enable=enable, backup_path_tunnel_id=backup_path_tunnel_id, attribute_flags=attribute_flags, administrative_weight=administrative_weight)
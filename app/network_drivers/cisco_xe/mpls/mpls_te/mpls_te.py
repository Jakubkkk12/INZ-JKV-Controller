from pathlib import Path
from jinja2 import Environment, FileSystemLoader, Template
from app.heplers.functions import check_dict_key
from app.network_drivers.base_configuration import BaseConfigMplsTeTunnels


class ConfigMplsTeTunnels(BaseConfigMplsTeTunnels):
    """Class holds and validates attributes to configure MPLS Tunnels on Cisco IOS-XE device.

    Class inherits from BaseConfigMplsTeTunnels.

    Attributes:
        enable (bool): A boolean flag to enable or disable the main MPLS TE tunnel feature.
    """
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'enable': self.enable,
        }

    def get_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'mpls_te_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'mpls_te_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def running_to_ConfigMplsTeTunnels(mpls: dict | None) -> ConfigMplsTeTunnels | None:
    """Converts the raw configuration dictionary for MPLS Traffic Engineering (TE) tunnels
    into a structured ConfigMplsTeTunnels model.

    This function checks for the presence of the necessary configuration keys to determine
    if the MPLS TE Tunnels feature is enabled globally.

    Args:
        mpls (dict | None): A dictionary representing the MPLS TE configuration
            read from the device's running configuration, typically the content of
            ['data']['native']['mpls'].

    Returns:
        ConfigMplsTeTunnels | None: A structured configuration object with 'enable=True'
            if tunnel configuration is present, or None if no necessary configuration keys are defined.
    """
    if mpls is None:
        return None
    if check_dict_key(mpls, 'traffic-eng') and check_dict_key(mpls['traffic-eng'], 'tunnels'):
        return ConfigMplsTeTunnels(enable=True)
    return ConfigMplsTeTunnels(enable=False)


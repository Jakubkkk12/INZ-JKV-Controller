from pathlib import Path
from pydantic import field_validator
from jinja2 import Environment, FileSystemLoader, Template
from app.heplers.functions import check_dict_key
from app.network_drivers.base_configuration import BaseIpExplicitPathEntry, BaseIpExplicitPathEntryNextAddress, \
    BaseIpExplicitPathEntryExcludeAddress, BaseConfigIpExplicitPath


class IpExplicitPathEntry(BaseIpExplicitPathEntry):
    """Class holds and validates attributes of the Base Path Entry used in IPv4 Explicit Path on Cisco IOS-XE device.

    Class inherits from BaseIpExplicitPathEntry.

    Attributes:
        index (int): The sequence number of the entry in the explicit path.
            Lower numbers represent earlier hops in the path.
        ipv4_address (str): The IPv4 address of the node (router interface) to be included
            at this specific hop in the explicit path.
    """
    @field_validator("index")
    def check_index(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError("index must be between 1 and 65535")
        return v


class IpExplicitPathEntryNextAddress(BaseIpExplicitPathEntryNextAddress, IpExplicitPathEntry):
    """Class holds additional attributes of the Next Address Path Entry used in IPv4 Explicit Path on Cisco IOS-XE device.

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
    pass


class IpExplicitPathEntryExcludeAddress(BaseIpExplicitPathEntryExcludeAddress, IpExplicitPathEntry):
    """Class holds additional attributes of the Exclude Address Path Entry used in IPv4 Explicit Path on Cisco IOS-XE device.

    Class inherits from BaseIpExplicitPathEntry.

    Attributes:
        index (int): The sequence number of the entry in the explicit path.
            Lower numbers represent earlier hops in the path.
        ipv4_address (str): The IPv4 address of the node (router interface) to be included
            at this specific hop in the explicit path.
    """
    pass


class ConfigIpExplicitPath(BaseConfigIpExplicitPath):
    """Class holds and validates attributes to configure IPv4 Explicit Path on Cisco IOS-XE device.

    Class inherits from BaseConfigIpExplicitPath.

    Attributes:
        name (str): The unique name assigned to the IP Explicit Path, used for reference by MPLS TE tunnels.
        path_next_address (list[IpExplicitPathEntryNextAddress] | None, optional): A list of path entries specifying the
            **strict or loose sequence of next-hop IP addresses** the traffic must follow.
            If this is specified, `path_exclude_address` must be None. Defaults to None.
        path_exclude_address (list[IpExplicitPathEntryExcludeAddress] | None, optional): A list of path entries specifying the
            **IP addresses or address ranges that the path must avoid**.
            If this is specified, `path_next_address` must be None. Defaults to None.
    """
    path_next_address: list[IpExplicitPathEntryNextAddress] | None = None
    path_exclude_address: list[IpExplicitPathEntryExcludeAddress] | None = None
    render_args: dict | None = None

    def model_post_init(self, __context) -> None:
        """Define render_args which will be used in Jinja2 template rendering."""
        self.render_args = {
            'name': self.name,
            'path_exclude_address': self.path_exclude_address,
            'path_next_address': self.path_next_address,
        }

    @field_validator("name")
    def check_name(cls, v):
        if not (1 <= len(v) <= 63):
            raise ValueError("name must have between 1 and 63 characters")
        return v

    def get_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'ip_explicit_path_netconf.j2')
        return netconf_template.render(**self.render_args, operation="replace")

    def delete_config_netconf(self) -> str:
        """Method used to generate NETCONF payload

        Returns:
            str: NETCONF XML payload
        """
        dir_with_template = Path(__file__).resolve().parent
        netconf_template: Template = Environment(loader=FileSystemLoader(dir_with_template)).get_template(
            'ip_explicit_path_netconf.j2')
        return netconf_template.render(**self.render_args, operation="delete")


def get_path_entry(path_entry: dict) -> IpExplicitPathEntryNextAddress | IpExplicitPathEntryExcludeAddress:
    index: int = path_entry.get('idx')
    if check_dict_key(path_entry, 'next-address'):
        ip_address: str = path_entry['next-address'].get('ipv4')
        loose: bool = False
        if check_dict_key(path_entry['next-address'], 'loose'):
            loose = True
        return IpExplicitPathEntryNextAddress(index=index, ipv4_address=ip_address, loose=loose)
    elif check_dict_key(path_entry, 'exclude-address'):
        ip_address: str = path_entry.get('exclude-address')
        return IpExplicitPathEntryExcludeAddress(index=index, ipv4_address=ip_address)
    return None

def running_to_ConfigIpExplicitPath(ip_explicit_path: dict | None) -> ConfigIpExplicitPath | None:
    """Converts the raw configuration dictionary for IP Explicit Path
    configuration into a structured ConfigIpExplicitPath model.

    This function checks for the presence of the necessary configuration keys to determine
    if the IP Explicit Path is present.

    Args:
        ip_explicit_path (dict | None): A dictionary representing the IP Explicit Path  configuration
            read from the device's running configuration, typically the content of
            ['data']['native']['ip']['explicit-path']['name'][<LIST_INDEX>].

    Returns:
        ConfigIpExplicitPath | None: A structured configuration which maps running configuration, or None if no necessary configuration keys are defined.
    """
    if ip_explicit_path is None:
        return None

    if not check_dict_key(ip_explicit_path, 'pname'):
        return None

    name: str = ip_explicit_path.get('pname')
    path_next_address: list[IpExplicitPathEntryNextAddress] | None = []
    path_exclude_address: list[IpExplicitPathEntryExcludeAddress] | None = []
    if check_dict_key(ip_explicit_path, 'index'):
        path_entries = ip_explicit_path.get('index')
        if isinstance(path_entries, dict):
            p_entry: IpExplicitPathEntryExcludeAddress | IpExplicitPathEntryNextAddress = get_path_entry(path_entries)
            if isinstance(p_entry, IpExplicitPathEntryExcludeAddress):
                path_exclude_address.append(p_entry)
            if isinstance(p_entry, IpExplicitPathEntryNextAddress):
                path_next_address.append(p_entry)

        elif isinstance(path_entries, list):
            for path_entry in path_entries:
                p_entry: IpExplicitPathEntryExcludeAddress | IpExplicitPathEntryNextAddress = get_path_entry(path_entry)
                if isinstance(p_entry, IpExplicitPathEntryExcludeAddress):
                    path_exclude_address.append(p_entry)
                if isinstance(p_entry, IpExplicitPathEntryNextAddress):
                    path_next_address.append(p_entry)

    if len(path_exclude_address) == 0:
        path_exclude_address = None
    if len(path_next_address) == 0:
        path_next_address = None

    return ConfigIpExplicitPath(name=name, path_next_address=path_next_address, path_exclude_address=path_exclude_address)
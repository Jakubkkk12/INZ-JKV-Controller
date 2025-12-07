from pathlib import Path
from decouple import config

USER_ACTION_LOG_FILE_PATH: str = str(Path(__file__).parent.parent / "logs" / "app.log")
DEVELOPER_LOG_FILE_PATH: str = str(Path(__file__).parent.parent / "logs" / "developer.log")
NORNIR_LOG_FILE_PATH: str = str(Path(__file__).parent.parent / "logs" / "nornir.log")

USER_NETWORK_CONFIGURATION_DIR_NAME: str = "network_configuration"
USER_NETWORK_CONFIGURATION_PATH: Path = Path(__file__).parent.parent.parent / USER_NETWORK_CONFIGURATION_DIR_NAME

NORNIR_NUM_WORKERS: int = 5
NORNIR_CONFIGURATION_FILE_NAME: str = "nornir_config.yml"
NORNIR_HOSTS_FILE_NAME: str = "nornir_hosts.yml"
NORNIR_GROUPS_FILE_NAME: str = "nornir_groups.yml"
MPLS_TE_TUNNEL_SERVICES_FILE_NAME: str = "mpls_te_tunnels.yml"
MPLS_L3_VPN_SERVICES_FILE_NAME: str = "mpls_l3_vpns.yml"
DEVICES_CONFIGURATION_DIR_NAME: str = "devices_configuration"
DEVICES_CONFIGURATION_DIR_PATH: Path = USER_NETWORK_CONFIGURATION_PATH / DEVICES_CONFIGURATION_DIR_NAME
NEW_PROJECTS_ELEMENTS: list[dict[str, str | bool]] = [
    {"name": NORNIR_CONFIGURATION_FILE_NAME, "is_file": True},
    {"name": NORNIR_HOSTS_FILE_NAME, "is_file": True},
    {"name": NORNIR_GROUPS_FILE_NAME, "is_file": True},
    {"name": MPLS_TE_TUNNEL_SERVICES_FILE_NAME, "is_file": True},
    {"name": MPLS_L3_VPN_SERVICES_FILE_NAME, "is_file": True},
    {"name": DEVICES_CONFIGURATION_DIR_NAME, "is_file": False},
]
NORNIR_CONFIGURATION_FILE_PATH: Path = Path(__file__).parent.parent.parent / USER_NETWORK_CONFIGURATION_DIR_NAME / NORNIR_CONFIGURATION_FILE_NAME
NORNIR_HOSTS_FILE_PATH: Path = Path(__file__).parent.parent.parent / USER_NETWORK_CONFIGURATION_DIR_NAME / NORNIR_HOSTS_FILE_NAME
NORNIR_GROUPS_FILE_PATH : Path = Path(__file__).parent.parent.parent / USER_NETWORK_CONFIGURATION_DIR_NAME / NORNIR_GROUPS_FILE_NAME
MPLS_L3_VPN_SERVICES_FILE_PATH: Path = Path(__file__).parent.parent.parent / USER_NETWORK_CONFIGURATION_DIR_NAME / MPLS_L3_VPN_SERVICES_FILE_NAME
MPLS_TE_TUNNEL_SERVICES_FILE_PATH : Path = Path(__file__).parent.parent.parent / USER_NETWORK_CONFIGURATION_DIR_NAME / MPLS_TE_TUNNEL_SERVICES_FILE_NAME

USER_DB_FILE_NAME: str = "users.db"
USER_DB_FILE_PATH: Path = Path(__file__).parent.parent / "controller" / USER_DB_FILE_NAME

DEFAULT_USER_USERNAME: str = "admin"
DEFAULT_USER_PASSWORD: str = "admin"
DEFAULT_USER_PRIVILEGE_LEVEL: int = 3

CISCO_XE: str = "cisco_xe"
SUPPORTED_PLATFORMS: list[str] = [CISCO_XE]

NCCLIENT_PLATFORM: str = "ncclient_platform"
NCCLIENT_CISCO_XE: str = "iosxe"

SSH_GROUP: str = "ssh_conf"
SSH_PORT_CONF_KEY: str = "ssh_port"
NETCONF_GROUP: str = "netconf_conf"
NETCONF_PORT_CONF_KEY: str = "netconf_port"
MANDATORY_GROUPS: list[str] = [SSH_GROUP, NETCONF_GROUP]

NOT_IN_RUNNING: str = "NOT_IN_RUNNING_1234"

API_VERSION_V1: str = "/api/v1"

JWT_SECRET: str = config("secret")
JWT_ALGORITHM: str = config("algorithm")
ACCESS_TOKEN_EXPIRATION_SECONDS: int = 1800 # 30min
REFRESH_TOKEN_EXPIRATION_SECONDS: int = 32400 # 9h

# IP Explicit Path
class IpExplicitPathConfigurationMethod:
    EXPLICIT: str = "explicit"
    NETWORK_DEVICE_NAME: str = "network_device_name"
    NETWORK_DEVICE_INTERFACE: str = "network_device_interface"

class IpExplicitPathConfigurationType:
    EXCLUDE: str = "exclude"
    NEXT_IP_ADDRESS: str = "next_ip_address"

class ConfigurationOperation:
    NEW: str = "new"
    UPDATE: str = "update"

MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME = "Loopback0"

class ServiceMplsTeTunnelDestinationConfigurationMethod:
    IPV4_ADDRESS: str = "ipv4_address"
    NETWORK_DEVICE_NAME: str = "network_device_name"

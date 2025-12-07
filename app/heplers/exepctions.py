class ProjectAlreadyExists(Exception):
    """Exception raised when a project already exists."""
    pass

class ProjectNotFound(Exception):
    """Exception raised when a project does not exist."""
    pass

class ProjectCreationError(Exception):
    """Exception raised when a project fails to create."""
    pass

class ProjectDeletionError(Exception):
    """Exception raised when a project fails to delete."""
    pass

class ProjectFailedToLoad(Exception):
    """Exception raised when a project fails to load."""
    pass

class ProjectNotInitialized(Exception):
    """Exception raised when a project is not initialized."""
    pass

# ----------------------------------------------------------------------
# Exceptions related to Device Group management
# ----------------------------------------------------------------------
class DeviceGroupAlreadyExists(Exception):
    """Exception raised when a Device group with the same name already exists in the configuration."""
    pass

class DeviceGroupNotFound(Exception):
    """Exception raised when the specified Device group does not exist."""
    pass

class DeviceGroupSaveError(Exception):
    """Exception raised when saving the Device group configuration fails."""
    pass

class DeviceGroupReadError(Exception):
    """Exception raised when reading the Device group configuration file fails."""
    pass

class DeviceGroupMandatoryDeleteError(Exception):
    """Exception raised when try to delete a Device mandatory group"""
    pass

# ----------------------------------------------------------------------
# Exceptions related to Device management
# ----------------------------------------------------------------------
class DeviceAlreadyExists(Exception):
    """Exception raised when a Device with the same name already exists in the configuration."""
    pass

class DeviceNotFound(Exception):
    """Exception raised when the specified Device does not exist."""
    pass

class DeviceSaveError(Exception):
    """Exception raised when saving the Device configuration fails."""
    pass

class DeviceReadError(Exception):
    """Exception raised when reading the Device configuration file fails."""
    pass

class DeviceUnsupportedPlatform(Exception):
    """Exception raised when device with unsupported platform is requested."""
    pass

# ----------------------------------------------------------------------
# Exceptions related to Network Devices
# ----------------------------------------------------------------------
class NetworkDeviceNotFound(Exception):
    """Exception raised when the specified Network Device does not exist."""
    def __init__(self, network_device_name: str):
        self.network_device_name = network_device_name

class NetworkDeviceInterfaceNotFound(Exception):
    """Exception raised when a device interface does not exist."""
    def __init__(self, network_device_name: str, network_device_interface_fullname: str):
        self.network_device_name = network_device_name
        self.network_device_interface_fullname = network_device_interface_fullname

# ----------------------------------------------------------------------
# Exceptions related to Nornir Engine / Tasks
# ----------------------------------------------------------------------
class GetRunningFailed(Exception):
    """Exception raised when Nornir is unable to get a running configuration from Network Device."""
    pass

class NetconfConfigurationRejected(Exception):
    """Exception raised when Network Device not replay OK to RPC"""
    def __init__(self, message: str):
        self.message = message

class IncorrectConfiguration(Exception):
    """Exception raised when a configuration does not match the expected value."""
    pass

# ----------------------------------------------------------------------
# Exceptions related MPLS TE
# ----------------------------------------------------------------------
class InterfaceIpAddressMissing(Exception):
    """Exception raised when Network Device does not have configured IP Address on interface"""
    pass

# ----------------------------------------------------------------------
# Exceptions related configuration IP Explicit Path
# ----------------------------------------------------------------------
class IpExplicitPathAlreadyExists(Exception):
    """Exception raised when Network Device have IP Explicit Path"""
    def __init__(self, ip_explicit_path_name: str):
        self.ip_explicit_path_name = ip_explicit_path_name
    pass

class IpExplicitPathNotFound(Exception):
    """Exception raised when IP Explicit Path does not exist"""
    def __init__(self, ip_explicit_path_name: str):
        self.ip_explicit_path_name = ip_explicit_path_name

class IpExplicitPathTypeError(Exception):
    """Exception raised when IP Explicit Path has incorrect type"""
    pass

class IpExplicitPathConfigurationMethodError(Exception):
    """Exception raised when IP Explicit Path has incorrect configuration method"""
    pass

# ----------------------------------------------------------------------
# Exceptions related configuration MPLS TE Tunnels
# ----------------------------------------------------------------------
class MplsTeTunnelNotFound(Exception):
    """Exception raised when MPLS TE Tunnel does not exist"""
    def __init__(self, mpls_te_tunnel_fullname: str):
        self.mpls_te_tunnel_fullname = mpls_te_tunnel_fullname

# ----------------------------------------------------------------------
# Exceptions related VRF
# ----------------------------------------------------------------------
class VrfNotFound(Exception):
    """Exception raised when VRF does not exist"""
    def __init__(self, vrf_name: str):
        self.vrf_name = vrf_name

class VrfAlreadyExists(Exception):
    """Exception raised when Network Device have VRF"""
    def __init__(self, vrf_name: str):
        self.vrf_name = vrf_name

# ----------------------------------------------------------------------
# Exceptions related BGP Peer Session Template
# ----------------------------------------------------------------------
class BgpPeerSessionTemplateNotFound(Exception):
    """Exception raised when BGP Peer Session Template does not exist"""
    def __init__(self, template_name: str):
        self.template_name = template_name

class BgpPeerSessionTemplateAlreadyExists(Exception):
    """Exception raised when Network Device have BGP Peer Session Template"""
    def __init__(self, template_name: str):
        self.template_name = template_name

class BgpPeerSessionTemplateInUse(Exception):
    """Exception raised when Network Device have BGP Peer Session Template connected to neighbor,
    and you try to delete it"""
    def __init__(self, template_name: str):
        self.template_name = template_name

# ----------------------------------------------------------------------
# Exceptions related BGP Peer Policy Template
# ----------------------------------------------------------------------
class BgpPeerPolicyTemplateNotFound(Exception):
    """Exception raised when BGP Peer Policy Template does not exist"""
    def __init__(self, template_name: str):
        self.template_name = template_name

class BgpPeerPolicyTemplateAlreadyExists(Exception):
    """Exception raised when Network Device have BGP Peer Policy Template"""
    def __init__(self, template_name: str):
        self.template_name = template_name

class BgpPeerPolicyTemplateInUse(Exception):
    """Exception raised when Network Device have BGP Peer Policy Template connected to neighbor,
    and you try to delete it"""
    def __init__(self, template_name: str):
        self.template_name = template_name

# ----------------------------------------------------------------------
# Exceptions related BGP IPv4 Unicast Neighbor
# ----------------------------------------------------------------------
class BgpIPv4UnicastNeighborNotFound(Exception):
    """Exception raised when BGP IPv4 Unicast Neighbor does not exist"""
    def __init__(self, id: str):
        self.id = id

class BgpIPv4UnicastNeighborAlreadyExists(Exception):
    """Exception raised when Network Device have BGP IPv4 Unicast Neighbore"""
    def __init__(self, id: str):
        self.id = id
    pass

# ----------------------------------------------------------------------
# Exceptions related BGP VPNv4 Unicast Neighbor
# ----------------------------------------------------------------------
class BgpVpnv4UnicastNeighborNotFound(Exception):
    """Exception raised when BGP VPNv4 Unicast Neighbor does not exist"""
    def __init__(self, id: str):
        self.id = id

class BgpVpnv4UnicastNeighborAlreadyExists(Exception):
    """Exception raised when Network Device have BGP VPNv4 Unicast Neighbore"""
    def __init__(self, id: str):
        self.id = id
    pass

# ----------------------------------------------------------------------
# Exceptions related BGP IPv4 Unicast VRF
# ----------------------------------------------------------------------
class BgpIpv4UnicastVrfNotFound(Exception):
    """Exception raised when BGP VPNv4 Unicast Neighbor does not exist"""
    def __init__(self, vrf_name: str):
        self.vrf_name = vrf_name

class BgpIpv4UnicastVrfAlreadyExists(Exception):
    """Exception raised when Network Device have BGP IPv4 Unicast VRF"""
    def __init__(self, vrf_name: str):
        self.vrf_name = vrf_name
    pass

# ----------------------------------------------------------------------
# Exceptions related MPLS TE Tunnel service
# ----------------------------------------------------------------------
class FunctionalityNotImplemented(Exception):
    """Exception raised when a functionality is not implemented."""
    def __init__(self, message: str):
        self.message = message

class ServiceMplsTeTunnelDestinationConfigurationMethodError(Exception):
    """Exception raised when Service MPLS TE Tunnel has incorrect destination configuration method"""
    pass

class ServiceMplsTeTunnelNotFound(Exception):
    """Exception raised when Service MPLS TE Tunnel do not exist"""
    def __init__(self, mpls_te_tunnel_service_name: str):
        self.mpls_te_tunnel_service_name = mpls_te_tunnel_service_name

class ServiceMplsTeTunnelAlreadyExists(Exception):
    """Exception raised when Service MPLS TE Tunnel already exist"""
    def __init__(self, mpls_te_tunnel_service_name: str):
        self.mpls_te_tunnel_service_name = mpls_te_tunnel_service_name

# ----------------------------------------------------------------------
# Exceptions related MPLS L3 VPN service
# ----------------------------------------------------------------------
class ServiceMplsL3VpnNotFound(Exception):
    """Exception raised when Service MPLS L3 VPN do not exist"""
    def __init__(self, mpls_l3_vpn_service_name: str):
        self.mpls_l3_vpn_service_name = mpls_l3_vpn_service_name

class ServiceMplsL3VpnAlreadyExists(Exception):
    """Exception raised when Service MPLS L3 VPN already exist"""
    def __init__(self, mpls_l3_vpn_service_name: str):
        self.mpls_l3_vpn_service_name = mpls_l3_vpn_service_name

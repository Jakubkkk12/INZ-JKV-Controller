import traceback
import xmltodict as x2d
from pydantic import BaseModel
from app.heplers.constants import CISCO_XE
from app.heplers.exepctions import ProjectNotInitialized, GetRunningFailed
import app.network_drivers.cisco_xe.ip.explicit_path.explicit_path as ip_explicit_path_cisco_xe
import app.network_drivers.cisco_xe.mpls.mpls_te.mpls_te as mpls_te_cisco_xe
import app.network_drivers.cisco_xe.mpls.mpls_te_interface.mpls_te_interface as mpls_te_interface_cisco_xe
import app.network_drivers.cisco_xe.mpls.mpls_te_tunnel.mpls_te_tunnel as mpls_te_tunnel_cisco_xe
import app.network_drivers.cisco_xe.vrf.vrf as vrf_cisco_xe
import app.network_drivers.cisco_xe.vrf.vrf_interface.vrf_interface as vrf_interface_cisco_xe
import app.network_drivers.cisco_xe.bgp.bgp as bgp_cisco_xe
import app.network_drivers.base_configuration as base
from app.heplers.functions import check_dict_key
from app.logs.logger import DeveloperLogger


class NetworkDeviceBgpConfiguration(BaseModel):
    """Class models the Border Gateway Protocol (BGP) configuration for a network device,
    structured under a single Autonomous System Number (ASN).

    This model provides a centralized view of some BGP components, including reusable templates,
    neighbor definitions under various address families (IPv4 Unicast, VPNv4), and
    VRF-specific BGP configurations.

    Attributes:
        asn (int): The local **Autonomous System Number (ASN)** under which the BGP process is running.
        peer_policy_templates (dict[str, bgp_cisco_xe.ConfigBgpTemplatePeerPolicy] | None, optional):
            A dictionary where keys are the **names** of the BGP peer policy templates and
            values are the corresponding structured configuration objects. These templates
            define reusable routing policies (e.g. next-hop-self).
            Defaults to None.
        peer_session_templates (dict[str, bgp_cisco_xe.ConfigBgpTemplatePeerSession] | None, optional):
            A dictionary where keys are the **names** of the BGP peer session templates and
            values are the corresponding structured configuration objects. These templates
            define reusable session parameters (e.g., remote ASN, update source, timers).
            Defaults to None.
        ipv4_unicast_neighbors (dict[str, bgp_cisco_xe.ConfigBgpIpv4UnicastNeighbor] | None, optional):
            A dictionary where keys are the **IPv4 addresses** of the neighbors and values
            are the structured configurations for neighbors participating in the **global IPv4 Unicast**
            address family (used for standard Internet routing). Defaults to None.
        vpnv4_unicast_neighbors (dict[str, bgp_cisco_xe.ConfigBgpVpnv4UnicastNeighbor] | None, optional):
            A dictionary where keys are the **IPv4 addresses** of the neighbors and values
            are the structured configurations for neighbors participating in the **VPNv4 Unicast**
            address family (used for exchanging MPLS VPN routes between Provider Edge devices).
            Defaults to None.
        ipv4_unicast_vrfs (dict[str, bgp_cisco_xe.ConfigBgpIpv4UnicastVrf] | None, optional):
            A dictionary where keys are the **names** of the VRF instances and values are
            the structured configurations for BGP under the **IPv4 Unicast address family within that VRF**
            (used for customer-specific routing). Defaults to None.
    """
    asn: int
    peer_policy_templates: dict[str, bgp_cisco_xe.ConfigBgpTemplatePeerPolicy] | None = None
    peer_session_templates: dict[str, bgp_cisco_xe.ConfigBgpTemplatePeerSession] | None = None
    ipv4_unicast_neighbors: dict[str, bgp_cisco_xe.ConfigBgpIpv4UnicastNeighbor] | None = None
    vpnv4_unicast_neighbors: dict[str, bgp_cisco_xe.ConfigBgpVpnv4UnicastNeighbor] | None = None
    ipv4_unicast_vrfs: dict[str, bgp_cisco_xe.ConfigBgpIpv4UnicastVrf] | None = None


class NetworkDeviceBaselineConfiguration(BaseModel):
    """Class models the baseline (non-current-state) configuration
    for a network device, centralizing various essential service and control plane components.

    This model serves as a container for configuration objects that define the foundation
    of the device's service capabilities, particularly in an MPLS/VPN environment.

    Attributes:
        ipv4_explicit_paths (dict[str, ip_explicit_path_cisco_xe.ConfigIpExplicitPath] | None, optional):
            A dictionary where keys are the **names** of the IPv4 Explicit Paths and values are the
            structured configurations. Explicit Paths define a specific sequence of hops for
            traffic engineering. Defaults to None.
        mpls_te (mpls_te_cisco_xe.ConfigMplsTeTunnels | None, optional):
            The structured object for the global **MPLS Traffic Engineering (TE)** configuration,
            defining global MPLS TE. Defaults to None.
        mpls_te_interfaces (dict[str, mpls_te_interface_cisco_xe.ConfigMplsTeInterface] | None, optional):
            A dictionary where keys are the **full name** of the interfaces and values are the
            structured configurations for **MPLS TE Interface** properties (e.g., TE metric,
            affinity). Defaults to None.
        mpls_te_tunnels (dict[str, mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel] | None, optional):
            A dictionary where keys are the **names** of the MPLS TE Tunnels and values are the
            structured configurations for the tunnels themselves (e.g., destination, path options,
            fast reroute). Defaults to None.
        vrfs (dict[str, vrf_cisco_xe.ConfigVrf] | None, optional):
            A dictionary where keys are the **names** of the VRF instances and values are the
            structured configurations for the VRFs (e.g., Route Distinguisher, Route Targets,
            maximum routes). Defaults to None.
        vrf_interfaces (dict[str, vrf_interface_cisco_xe.ConfigInterfaceVrf] | None, optional):
            A dictionary where keys are the **full names** of the interfaces and values are the
            structured configurations for assigning an interface to a specific **VRF** and
            its IP addressing within that VRF. Defaults to None.
        bgp (NetworkDeviceBgpConfiguration | None, optional):
            A structured object containing the **BGP configuration** for the device,
            including templates, neighbors, and VRF-specific BGP instances. Defaults to None.
    """
    # add other vendor types in ipv4_explicit_paths, mpls_te_interfaces ...
    ipv4_explicit_paths: dict[str, ip_explicit_path_cisco_xe.ConfigIpExplicitPath] | None = None
    mpls_te: mpls_te_cisco_xe.ConfigMplsTeTunnels | None = None
    mpls_te_interfaces: dict[str, mpls_te_interface_cisco_xe.ConfigMplsTeInterface] | None = None
    mpls_te_tunnels: dict[str, mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel] | None = None
    vrfs: dict[str, vrf_cisco_xe.ConfigVrf] | None = None
    vrf_interfaces: dict[str, vrf_interface_cisco_xe.ConfigInterfaceVrf] | None = None
    bgp: NetworkDeviceBgpConfiguration | None = None


class NetworkDeviceRunningConfiguration(BaseModel):
    """Class models the complete **running configuration** of a network device, providing
    a structured, operational view of configured components at a given time.

    This model extends the baseline configuration by including interface details
    and is designed to map the entire output of a device's 'show running-config' command.

    Attributes:
        interfaces (dict[str, base.InterfaceDetails] | None, optional):
            A dictionary where keys are the **full names** of the interfaces (e.g., 'Loopback0', 'GigabitEthernet0/1/0')
            and values are structured objects containing their operational details (e.g. IP address).
            Defaults to None.
        ipv4_explicit_paths (dict[str, ip_explicit_path_cisco_xe.ConfigIpExplicitPath] | None, optional):
            A dictionary where keys are the **names** of the IPv4 Explicit Paths and values are the
            structured configurations. Explicit Paths define a specific sequence of hops for
            traffic engineering. Defaults to None.
        mpls_te (mpls_te_cisco_xe.ConfigMplsTeTunnels | None, optional):
            The structured object for the global **MPLS Traffic Engineering (TE)** configuration,
            defining global MPLS TE. Defaults to None.
        mpls_te_interfaces (dict[str, mpls_te_interface_cisco_xe.ConfigMplsTeInterface] | None, optional):
            A dictionary where keys are the **full name** of the interfaces and values are the
            structured configurations for **MPLS TE Interface** properties (e.g., TE metric,
            affinity). Defaults to None.
        mpls_te_tunnels (dict[str, mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel] | None, optional):
            A dictionary where keys are the **names** of the MPLS TE Tunnels and values are the
            structured configurations for the tunnels themselves (e.g., destination, path options,
            fast reroute). Defaults to None.
        vrfs (dict[str, vrf_cisco_xe.ConfigVrf] | None, optional):
            A dictionary where keys are the **names** of the VRF instances and values are the
            structured configurations for the VRFs (e.g., Route Distinguisher, Route Targets,
            maximum routes). Defaults to None.
        vrf_interfaces (dict[str, vrf_interface_cisco_xe.ConfigInterfaceVrf] | None, optional):
            A dictionary where keys are the **full names** of the interfaces and values are the
            structured configurations for assigning an interface to a specific **VRF** and
            its IP addressing within that VRF. Defaults to None.
        bgp (NetworkDeviceBgpConfiguration | None, optional):
            A structured object containing the **BGP configuration** for the device,
            including templates, neighbors, and VRF-specific BGP instances. Defaults to None.
    """
    # add other vendor types in ipv4_explicit_paths, mpls_te_interfaces ...
    interfaces: dict[str, base.InterfaceDetails] | None = None

    # the same as in NetworkDeviceBaselineConfiguration
    ipv4_explicit_paths: dict[str, ip_explicit_path_cisco_xe.ConfigIpExplicitPath] | None = None
    mpls_te: mpls_te_cisco_xe.ConfigMplsTeTunnels | None = None
    mpls_te_interfaces: dict[str, mpls_te_interface_cisco_xe.ConfigMplsTeInterface] | None = None
    mpls_te_tunnels: dict[str, mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel] | None = None
    vrfs: dict[str, vrf_cisco_xe.ConfigVrf] | None = None
    vrf_interfaces: dict[str, vrf_interface_cisco_xe.ConfigInterfaceVrf] | None = None
    bgp: NetworkDeviceBgpConfiguration | None = None


class NetworkDevice(BaseModel):
    name: str
    hostname: str
    platform: str
    baseline_configuration: NetworkDeviceBaselineConfiguration | None = None
    running_configuration: NetworkDeviceRunningConfiguration | None = None
    last_used_tunnel_id: int | None = None

    def load_saved_configuration(self, saved_configuration: dict):
        ipv4_explicit_paths = {}
        mpls_te = None
        mpls_te_interfaces = {}
        mpls_te_tunnels = {}
        vrfs = {}
        vrf_interfaces = {}
        bgp = None

        if self.platform == CISCO_XE:
            # ipv4_explicit_paths
            try:
                for k, ipv4_explicit_path in saved_configuration["ipv4_explicit_paths"].items():
                    try:
                        ipv4_explicit_paths[k] = ip_explicit_path_cisco_xe.ConfigIpExplicitPath(**ipv4_explicit_path)
                    except ValueError:
                        DeveloperLogger().log_error(f"Invalid ipv4_explicit_path {k} configuration in baseline file: {traceback.format_exc()}")
                        continue
            except (KeyError, AttributeError):
                pass

            # mpls_te_interfaces
            try:
                for k, mpls_te_interface in saved_configuration["mpls_te_interfaces"].items():
                    try:
                        mpls_te_interfaces[k] = mpls_te_interface_cisco_xe.ConfigMplsTeInterface(**mpls_te_interface)
                    except ValueError:
                        DeveloperLogger().log_error(f"Invalid mpls_te_interface {k} configuration in baseline file: {traceback.format_exc()}")
                        continue
            except (KeyError, AttributeError):
                pass

            # mpls_te_tunnels
            try:
                for k, mpls_te_tunnel in saved_configuration["mpls_te_tunnels"].items():
                    try:
                        mpls_te_tunnels[k] = mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel(**mpls_te_tunnel)
                    except ValueError:
                        DeveloperLogger().log_error(f"Invalid mpls_te_tunnel {k} configuration in baseline file: {traceback.format_exc()}")
                        continue
            except (KeyError, AttributeError):
                pass

            # mpls_te
            try:
                mpls_te = mpls_te_cisco_xe.ConfigMplsTeTunnels(**saved_configuration["mpls_te"])
            except ValueError:
                DeveloperLogger().log_error(f"Invalid mpls_te {k} configuration in baseline file: {traceback.format_exc()}")
            except (KeyError, AttributeError, TypeError):
                pass

            # vrfs
            try:
                for k, vrf in saved_configuration["vrfs"].items():
                    try:
                        Project().vrf_name_in_use.add(k)
                        Project().client_rd_in_use.add(int(vrf['rd'].split(":")[1]))
                        vrfs[k] = vrf_cisco_xe.ConfigVrf(**vrf)
                    except ValueError:
                        DeveloperLogger().log_error(f"Invalid vrf {k} configuration in baseline file: {traceback.format_exc()}")
                        continue
            except (KeyError, AttributeError):
                pass

            # vrf_interfaces
            try:
                for k, vrf_interface in saved_configuration["vrf_interfaces"].items():
                    try:
                        vrf_interfaces[k] = vrf_interface_cisco_xe.ConfigInterfaceVrf(**vrf_interface)
                    except ValueError:
                        DeveloperLogger().log_error(f"Invalid vrf_interface {k} configuration in baseline file: {traceback.format_exc()}")
                        continue
            except (KeyError, AttributeError):
                pass

            # bgp
            try:
                bgp_ = saved_configuration["bgp"]
                asn = bgp_["asn"]
                peer_policy_templates = {}
                peer_session_templates = {}
                ipv4_unicast_neighbors = {}
                vpnv4_unicast_neighbors = {}
                ipv4_unicast_vrfs = {}
                # peer_policy_templates
                try:
                    for k, peer_policy_template in bgp_["peer_policy_templates"].items():
                        try:
                            peer_policy_templates[k] = bgp_cisco_xe.ConfigBgpTemplatePeerPolicy(**peer_policy_template)
                        except ValueError:
                            DeveloperLogger().log_error(f"Invalid peer_policy_template {k} configuration in baseline file: {traceback.format_exc()}")
                            continue
                except (KeyError, AttributeError):
                    pass

                # peer_session_templates
                try:
                    for k, peer_session_template in bgp_["peer_session_templates"].items():
                        try:
                            peer_session_templates[k] = bgp_cisco_xe.ConfigBgpTemplatePeerSession(**peer_session_template)
                        except ValueError:
                            DeveloperLogger().log_error(f"Invalid peer_session_template {k} configuration in baseline file: {traceback.format_exc()}")
                            continue
                except (KeyError, AttributeError):
                    pass

                # ipv4_unicast_neighbors
                try:
                    for k, ipv4_unicast_neighbor in bgp_["ipv4_unicast_neighbors"].items():
                        try:
                            ipv4_unicast_neighbors[k] = bgp_cisco_xe.ConfigBgpIpv4UnicastNeighbor(**ipv4_unicast_neighbor)
                        except ValueError:
                            DeveloperLogger().log_error(f"Invalid ipv4_unicast_neighbor {k} configuration in baseline file: {traceback.format_exc()}")
                            continue
                except (KeyError, AttributeError):
                    pass

                # vpnv4_unicast_neighbors
                try:
                    for k, vpnv4_unicast_neighbor in bgp_["vpnv4_unicast_neighbors"].items():
                        try:
                            vpnv4_unicast_neighbors[k] = bgp_cisco_xe.ConfigBgpVpnv4UnicastNeighbor(**vpnv4_unicast_neighbor)
                        except ValueError:
                            DeveloperLogger().log_error(f"Invalid vpnv4_unicast_neighbor {k} configuration in baseline file: {traceback.format_exc()}")
                            continue
                except (KeyError, AttributeError):
                    pass

                # ipv4_unicast_vrfs
                try:
                    for k, ipv4_unicast_vrf in bgp_["ipv4_unicast_vrfs"].items():
                        try:
                            ipv4_unicast_vrfs[k] = bgp_cisco_xe.ConfigBgpIpv4UnicastVrf(**ipv4_unicast_vrf)
                        except ValueError:
                            DeveloperLogger().log_error(f"Invalid ipv4_unicast_vrf {k} configuration in baseline file: {traceback.format_exc()}")
                            continue
                except (KeyError, AttributeError):
                    pass

                bgp = NetworkDeviceBgpConfiguration(asn=asn, peer_policy_templates=peer_policy_templates, peer_session_templates=peer_session_templates, ipv4_unicast_neighbors=ipv4_unicast_neighbors, vpnv4_unicast_neighbors=vpnv4_unicast_neighbors, ipv4_unicast_vrfs=ipv4_unicast_vrfs)
            except (KeyError, AttributeError, TypeError):
                pass

            self.baseline_configuration = NetworkDeviceBaselineConfiguration(ipv4_explicit_paths=ipv4_explicit_paths, mpls_te=mpls_te, mpls_te_interfaces=mpls_te_interfaces, mpls_te_tunnels=mpls_te_tunnels, vrfs=vrfs, vrf_interfaces=vrf_interfaces, bgp=bgp)

    def load_running_configuration(self, running_configuration: str):
        ipv4_explicit_paths = {}
        interfaces = {}
        mpls_te = None
        mpls_te_interfaces = {}
        mpls_te_tunnels = {}
        vrfs = {}
        vrf_interfaces = {}
        bgp = None

        if self.platform == CISCO_XE:
            if not running_configuration.startswith('<?xml'):
                raise GetRunningFailed
            running_conf = dict(x2d.parse(running_configuration))

            # ipv4_explicit_paths
            try:
                if not isinstance(running_conf['data']['native']['ip']['explicit-path']['name'], list):
                    running_conf['data']['native']['ip']['explicit-path']['name'] = [running_conf['data']['native']['ip']['explicit-path']['name']]
                for ipv4_explicit_path in running_conf['data']['native']['ip']['explicit-path']['name']:
                    try:
                        p = ip_explicit_path_cisco_xe.running_to_ConfigIpExplicitPath(ipv4_explicit_path)
                        ipv4_explicit_paths[p.name] = p
                    except ValueError:
                        continue
            except KeyError:
                pass

            # interfaces, vrf_interfaces
            try:
                for interface_name, interface_v in running_conf['data']['native']['interface'].items():
                    if isinstance(interface_v, dict):
                        interface_v = [interface_v]
                    for interface_conf in interface_v:
                        try:
                            i = base.InterfaceDetails(name=interface_name, id=interface_conf['name'])
                            interfaces[i.full_name] = i

                            v = vrf_interface_cisco_xe.running_to_ConfigInterfaceVrf(
                                interface=base.Interface(name=interface_name, id=interface_conf['name']),
                                interface_vrf=interface_conf)
                            if v is not None:
                                vrf_interfaces[v.interface.full_name] = v

                            i.ipv4_address = interface_conf['ip']['address']['primary']['address']
                            interfaces[i.full_name] = i
                        except KeyError:
                            pass
            except KeyError:
                pass

            # mpls_te_interfaces
            try:
                for interface_name, interface_v in running_conf['data']['native']['interface'].items():
                    if interface_name == "Tunnel" or interface_name == "Loopback":
                        continue
                    if isinstance(interface_v, dict):
                        interface_v = [interface_v]
                    for interface_conf in interface_v:
                        try:
                            m = mpls_te_interface_cisco_xe.running_to_ConfigMplsTeInterface(interface=base.Interface(name=interface_name, id=interface_conf['name']), interface_mpls_te=interface_conf['mpls']['traffic-eng'])
                        except KeyError:
                            continue
                        if m is not None:
                            mpls_te_interfaces[m.interface.full_name] = m
            except KeyError:
                pass

            # mpls_te_tunnels
            try:
                if not isinstance(running_conf['data']['native']['interface']['Tunnel'], list):
                    running_conf['data']['native']['interface']['Tunnel'] = [running_conf['data']['native']['interface']['Tunnel']]
                for mpls_te_tunnel in running_conf['data']['native']['interface']['Tunnel']:
                    m = mpls_te_tunnel_cisco_xe.running_to_ConfigMplsTeTunnel(mpls_te_tunnel)
                    if m is not None:
                        mpls_te_tunnels[f"Tunnel{m.tunnel_id}"] = m
            except KeyError:
                pass

            # mpls_te
            try:
                mpls_te = mpls_te_cisco_xe.running_to_ConfigMplsTeTunnels(running_conf['data']['native']['mpls'])
            except KeyError:
                mpls_te = mpls_te_cisco_xe.ConfigMplsTeTunnels(enable=False)

            # vrfs
            try:
                if not isinstance(running_conf['data']['native']['vrf']['definition'], list):
                    running_conf['data']['native']['vrf']['definition'] = [running_conf['data']['native']['vrf']['definition']]
                for vrf in running_conf['data']['native']['vrf']['definition']:
                    try:
                        Project().vrf_name_in_use.add(vrf['name'])
                        if check_dict_key(vrf, "rd"):
                            Project().client_rd_in_use.add(int(vrf['rd'].split(":")[1]))
                        v = vrf_cisco_xe.running_to_ConfigVrf(vrf)
                        if v is not None:
                            vrfs[v.name] = v
                    except ValueError:
                        continue
            except KeyError:
                pass

            # bgp
            try:
                asn = running_conf['data']['native']['router']['bgp']['id']
                peer_policy_templates = {}
                peer_session_templates = {}
                ipv4_unicast_neighbors = {}
                vpnv4_unicast_neighbors = {}
                ipv4_unicast_vrfs = {}
                # peer_policy_templates
                try:
                    if not isinstance(running_conf['data']['native']['router']['bgp']['template']['peer-policy'], list):
                        running_conf['data']['native']['router']['bgp']['template']['peer-policy'] = [running_conf['data']['native']['router']['bgp']['template']['peer-policy']]
                    for peer_policy_template in running_conf['data']['native']['router']['bgp']['template']['peer-policy']:
                        try:
                            p_p_t = bgp_cisco_xe.running_to_ConfigBgpTemplatePeerPolicy(asn=asn, bgp_template_peer_policy=peer_policy_template)
                            if p_p_t is not None:
                                peer_policy_templates[p_p_t.name] = p_p_t
                        except ValueError:
                            continue
                except KeyError:
                    pass

                # peer_session_templates
                try:
                    if not isinstance(running_conf['data']['native']['router']['bgp']['template']['peer-session'], list):
                        running_conf['data']['native']['router']['bgp']['template']['peer-session'] = [running_conf['data']['native']['router']['bgp']['template']['peer-session']]
                    for peer_session_template in running_conf['data']['native']['router']['bgp']['template']['peer-session']:
                        try:
                            p_s_t = bgp_cisco_xe.running_to_ConfigBgpTemplatePeerSession(asn=asn, bgp_template_peer_session=peer_session_template)
                            if p_s_t is not None:
                                peer_session_templates[p_s_t.name] = p_s_t
                        except ValueError:
                            continue
                except KeyError:
                    pass

                # ipv4_unicast_neighbors
                try:
                    # {
                    #  "ipv4_address": [bgp_neighbor, bgp_ipv4_unicast_neighbor]
                    # }
                    bgp_ipv4_neighbor_conf_sync = {}
                    if not isinstance(running_conf['data']['native']['router']['bgp']['neighbor'], list):
                        running_conf['data']['native']['router']['bgp']['neighbor'] = [running_conf['data']['native']['router']['bgp']['neighbor']]
                    if not isinstance(running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['ipv4']['ipv4-unicast']['neighbor'], list):
                        running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['ipv4']['ipv4-unicast']['neighbor'] = [running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['ipv4']['ipv4-unicast']['neighbor']]

                    for bgp_neighbor in running_conf['data']['native']['router']['bgp']['neighbor']:
                        bgp_ipv4_neighbor_conf_sync[bgp_neighbor['id']] = [bgp_neighbor]
                    for bgp_ipv4_unicast_neighbor in running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['ipv4']['ipv4-unicast']['neighbor']:
                        bgp_ipv4_neighbor_conf_sync[bgp_ipv4_unicast_neighbor['id']].append(bgp_ipv4_unicast_neighbor)

                    for k, conf_sync in bgp_ipv4_neighbor_conf_sync.items():
                        if len(conf_sync) != 2:
                            continue
                        try:
                            ipv4_uni_nei = bgp_cisco_xe.running_to_ConfigBgpIpv4UnicastNeighbor(asn=asn, bgp_neighbor=conf_sync[0], bgp_ipv4_unicast_neighbor=conf_sync[1])
                            if ipv4_uni_nei is not None:
                                ipv4_unicast_neighbors[k] = ipv4_uni_nei
                        except ValueError:
                            continue
                except KeyError:
                    pass

                # vpnv4_unicast_neighbors
                try:
                    if not isinstance(running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['vpnv4']['vpnv4-unicast']['neighbor'], list):
                        running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['vpnv4']['vpnv4-unicast']['neighbor'] = [running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['vpnv4']['vpnv4-unicast']['neighbor']]
                    for vpnv4_unicast_neighbor in running_conf['data']['native']['router']['bgp']['address-family']['no-vrf']['vpnv4']['vpnv4-unicast']['neighbor']:
                        try:
                            v_u_n = bgp_cisco_xe.running_to_ConfigBgpVpnv4UnicastNeighbor(asn=asn, bgp_vpnv4_unicast_neighbor=vpnv4_unicast_neighbor)
                            if v_u_n is not None:
                                vpnv4_unicast_neighbors[v_u_n.neighbor.ipv4_address] = v_u_n
                        except ValueError:
                            continue
                except KeyError:
                    pass

                # ipv4_unicast_vrfs
                try:
                    if not isinstance(running_conf['data']['native']['router']['bgp']['address-family']['with-vrf']['ipv4']['vrf'], list):
                        running_conf['data']['native']['router']['bgp']['address-family']['with-vrf']['ipv4']['vrf'] = [running_conf['data']['native']['router']['bgp']['address-family']['with-vrf']['ipv4']['vrf']]
                    for ipv4_uni_vrf in running_conf['data']['native']['router']['bgp']['address-family']['with-vrf']['ipv4']['vrf']:
                        try:
                            ipv4_u_v = bgp_cisco_xe.running_to_ConfigBgpIpv4UnicastVrf(asn=asn, bgp_ipv4_vrf=ipv4_uni_vrf)
                            if ipv4_u_v is not None:
                                ipv4_unicast_vrfs[ipv4_u_v.vrf_name] = ipv4_u_v
                        except ValueError:
                            continue
                except KeyError:
                    pass

                bgp = NetworkDeviceBgpConfiguration(asn=asn, peer_policy_templates=peer_policy_templates,
                                                    peer_session_templates=peer_session_templates,
                                                    ipv4_unicast_neighbors=ipv4_unicast_neighbors,
                                                    vpnv4_unicast_neighbors=vpnv4_unicast_neighbors,
                                                    ipv4_unicast_vrfs=ipv4_unicast_vrfs)
            except KeyError:
                pass

            self.running_configuration = NetworkDeviceRunningConfiguration(ipv4_explicit_paths=ipv4_explicit_paths, interfaces=interfaces, mpls_te=mpls_te, mpls_te_interfaces=mpls_te_interfaces, mpls_te_tunnels=mpls_te_tunnels, vrfs=vrfs, vrf_interfaces=vrf_interfaces, bgp=bgp)

    def get_free_tunnel_id(self) -> int:
        free_tunnel_id: int = 10
        if self.last_used_tunnel_id is not None:
            free_tunnel_id = self.last_used_tunnel_id + 1

        reserved_tunnel_ids = []
        for name, interface in self.running_configuration.interfaces.items():
            if interface.name == "Tunnel":
                reserved_tunnel_ids.append(int(interface.id))

        while free_tunnel_id in reserved_tunnel_ids:
            free_tunnel_id = free_tunnel_id + 1

        self.last_used_tunnel_id = free_tunnel_id
        return free_tunnel_id

    def clear_last_used_tunnel_id(self):
        self.last_used_tunnel_id = None


class Project:
    __instance = None
    owner: str
    network_devices: dict = {}
    service_mpls_l3_vpn: dict = {}
    service_mpls_te_tunnel: dict = {}
    vrf_name_in_use: set = set()
    client_rd_in_use: set = set()

    def __new__(cls, owner: str = None):
        if cls.__instance is None:
            cls.__instance = super(Project, cls).__new__(cls)
            cls.__instance.__initialized = False
        return cls.__instance

    def __init__(self, owner: str = None):
        if self.__initialized:
            return
        if owner is None:
            raise ProjectNotInitialized
        self.owner = owner
        self.__initialized = True

    def get_free_client_rd(self) -> int:
        for client_id in range(5, 65531, 5):
            if client_id not in self.client_rd_in_use:
                return client_id
        raise Exception("No Free Client RD")


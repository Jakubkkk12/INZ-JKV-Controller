import copy
import ipaddress
import json
import re
import shutil
import traceback
import yaml
from deepdiff import DeepDiff
from app.controller.nornir_engine.nornir_engine import NornirEngine
from app.controller.nornir_engine.nornir_utils import DeviceGroup, Device
from app.heplers.constants import CISCO_XE, SSH_GROUP, SSH_PORT_CONF_KEY, \
    NETCONF_GROUP, NETCONF_PORT_CONF_KEY, MANDATORY_GROUPS, NORNIR_NUM_WORKERS, USER_NETWORK_CONFIGURATION_PATH, \
    NEW_PROJECTS_ELEMENTS, NORNIR_CONFIGURATION_FILE_PATH, NORNIR_GROUPS_FILE_PATH, NORNIR_HOSTS_FILE_PATH, \
    DEVICES_CONFIGURATION_DIR_PATH, IpExplicitPathConfigurationType, IpExplicitPathConfigurationMethod, \
    MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME, ConfigurationOperation, ServiceMplsTeTunnelDestinationConfigurationMethod, \
    MPLS_TE_TUNNEL_SERVICES_FILE_PATH, MPLS_L3_VPN_SERVICES_FILE_PATH
from app.heplers.exepctions import ProjectAlreadyExists, ProjectCreationError, ProjectDeletionError, \
    DeviceGroupAlreadyExists, DeviceGroupNotFound, DeviceGroupSaveError, DeviceReadError, DeviceGroupReadError, \
    DeviceSaveError, DeviceNotFound, DeviceAlreadyExists, ProjectFailedToLoad, \
    DeviceGroupMandatoryDeleteError, NetworkDeviceInterfaceNotFound, NetworkDeviceNotFound, IpExplicitPathAlreadyExists, \
    IpExplicitPathTypeError, IpExplicitPathConfigurationMethodError, InterfaceIpAddressMissing, IncorrectConfiguration, \
    IpExplicitPathNotFound, ServiceMplsTeTunnelDestinationConfigurationMethodError, MplsTeTunnelNotFound, \
    VrfNotFound, VrfAlreadyExists, BgpPeerSessionTemplateNotFound, \
    BgpPeerSessionTemplateAlreadyExists, BgpPeerPolicyTemplateNotFound, BgpPeerPolicyTemplateAlreadyExists, \
    BgpIPv4UnicastNeighborAlreadyExists, BgpIPv4UnicastNeighborNotFound, BgpVpnv4UnicastNeighborNotFound, \
    BgpVpnv4UnicastNeighborAlreadyExists, \
    BgpIpv4UnicastVrfNotFound, BgpIpv4UnicastVrfAlreadyExists, ServiceMplsTeTunnelNotFound, \
    ServiceMplsTeTunnelAlreadyExists, BgpPeerSessionTemplateInUse, BgpPeerPolicyTemplateInUse, ServiceMplsL3VpnNotFound, \
    ServiceMplsL3VpnAlreadyExists
from app.heplers.functions import remove_all_key_from_dict, check_dict_key
from app.logs.logger import UserActionLogger, DeveloperLogger
import app.network_drivers.cisco_xe.ip.explicit_path.explicit_path as ip_explicit_path_cisco_xe
import app.network_drivers.cisco_xe.mpls.mpls_te.mpls_te as mpls_te_cisco_xe
import app.network_drivers.cisco_xe.mpls.mpls_te_interface.mpls_te_interface as mpls_te_interface_cisco_xe
import app.network_drivers.cisco_xe.mpls.mpls_te_tunnel.mpls_te_tunnel as mpls_te_tunnel_cisco_xe
import app.network_drivers.cisco_xe.vrf.vrf as vrf_cisco_xe
import app.network_drivers.cisco_xe.vrf.vrf_interface.vrf_interface as vrf_interface_cisco_xe
import app.network_drivers.cisco_xe.bgp.bgp as bgp_cisco_xe
import app.network_drivers.base_configuration as base
from app.manage_project.manage_project import Project, NetworkDevice, NetworkDeviceBaselineConfiguration


## Project
def create_project(project_owner: str):
    for element in NEW_PROJECTS_ELEMENTS:
        if (USER_NETWORK_CONFIGURATION_PATH / element["name"]).exists():
            DeveloperLogger().log_error(
                f"Failed to create new project, project already exists, existing file: {element['name']}")
            raise ProjectAlreadyExists

    try:
        for element in NEW_PROJECTS_ELEMENTS:
            new_element = USER_NETWORK_CONFIGURATION_PATH / element["name"]
            if element["is_file"]:
                new_element.touch(exist_ok=True)
            else:
                new_element.mkdir(parents=True, exist_ok=True)

        nornir_config = {
            "project_owner": project_owner,
            "inventory": {
                "plugin": "SimpleInventory",
                "options": {
                    "host_file": str(NORNIR_HOSTS_FILE_PATH),
                    "group_file": str(NORNIR_GROUPS_FILE_PATH),
                }
            },
            "runner": {
                "plugin": "threaded",
                "options": {
                    "num_workers": NORNIR_NUM_WORKERS
                }
            }
        }
        with open(NORNIR_CONFIGURATION_FILE_PATH, "w", encoding='utf-8') as f:
            yaml.safe_dump(nornir_config, f, sort_keys=False, explicit_start=True)

        nornir_groups = {
            f"{SSH_GROUP}": {
                "data": {
                    f"{SSH_PORT_CONF_KEY}": 22
                }
            },
            f"{NETCONF_GROUP}": {
                "data": {
                    f"{NETCONF_PORT_CONF_KEY}": 830
                }
            }
        }
        with open(NORNIR_GROUPS_FILE_PATH, "w", encoding='utf-8') as f:
            yaml.safe_dump(nornir_groups, f, sort_keys=False, explicit_start=True)

    except Exception:
        DeveloperLogger().log_error(f"Failed to create new project: {traceback.format_exc()}")
        raise ProjectCreationError
    Project(owner=project_owner)

def delete_project():
    try:
        shutil.rmtree(USER_NETWORK_CONFIGURATION_PATH)
        USER_NETWORK_CONFIGURATION_PATH.mkdir(parents=True, exist_ok=True)
    except Exception:
        DeveloperLogger().log_error(f"Failed to delete project: {traceback.format_exc()}")
        raise ProjectDeletionError

def start_project(project_owner: str):
    try:
        mpls_te_tunnel_services = get_service_mpls_te_tunnels()
        Project(owner=project_owner).service_mpls_te_tunnel = mpls_te_tunnel_services

        mpls_l3_vpn_services = get_service_mpls_l3_vpns()
        Project(owner=project_owner).service_mpls_l3_vpn = mpls_l3_vpn_services

        devices_with_configuration_drift = {
            "network_devices": [],
            "configuration_drift_on": [],
            "failed_to_connect_network_devices": [],
        }
        running = NornirEngine().get_running_config()
        devices = get_devices()
        for device_name in devices.keys():
            try:
                devices_with_configuration_drift["network_devices"].append(device_name)
                network_device: NetworkDevice = NetworkDevice(name=device_name, hostname=devices[device_name]["hostname"], platform=devices[device_name]["platform"])
                network_device.load_saved_configuration(get_device_configuration(device_name))
                network_device.load_running_configuration(running[device_name])
                Project(owner=project_owner).network_devices[device_name] = network_device
                if check_network_device_configuration_drift(device_name):
                    devices_with_configuration_drift["configuration_drift_on"].append(device_name)
            except Exception:
                DeveloperLogger().log_error(f"Failed to start device {device_name}: {traceback.format_exc()}")
                devices_with_configuration_drift["failed_to_connect_network_devices"].append(device_name)

        return devices_with_configuration_drift
    except Exception:
        DeveloperLogger().log_error(f"Failed to start project: {traceback.format_exc()}")
        raise ProjectFailedToLoad

def get_network_device_name_and_interface_fullname(ipv4_address: str) -> tuple | None:
    for network_device_name, network_device in Project().network_devices.items():
        for interface_fullname, interface in network_device.running_configuration.interfaces.items():
            if interface.ipv4_address == ipv4_address:
                return network_device_name, interface_fullname
    return None

## Device Group
def save_device_groups(current_groups: dict):
    try:
        with open(NORNIR_GROUPS_FILE_PATH, "w", encoding='utf-8') as f:
            yaml.safe_dump(current_groups, f, sort_keys=False, explicit_start=True)
    except Exception:
        DeveloperLogger().log_error(f"Failed to save device groups: {traceback.format_exc()}")
        raise DeviceGroupSaveError

def get_device_groups() -> dict:
    try:
        with open(NORNIR_GROUPS_FILE_PATH, "r", encoding='utf-8') as f:
            current_groups = yaml.safe_load(f)
    except Exception:
        DeveloperLogger().log_error(f"Failed to read device groups file: {traceback.format_exc()}")
        raise DeviceGroupReadError
    if not current_groups:
        return {}
    return current_groups

def get_device_group(group_name: str) -> tuple:
    current_groups = get_device_groups()
    if group_name not in current_groups.keys():
        raise DeviceGroupNotFound
    return group_name, current_groups[group_name]

def add_device_group(group: DeviceGroup):
    current_groups = get_device_groups()
    if group.name in current_groups.keys():
        UserActionLogger().log_error(f"Failed to add new device group {group.name}: group already exists.")
        raise DeviceGroupAlreadyExists

    current_groups[group.name] = group.value
    save_device_groups(current_groups)

def edit_device_group(group: DeviceGroup):
    current_groups = get_device_groups()
    if group.name not in current_groups.keys():
        UserActionLogger().log_error(f"Failed to edit device group {group.name}: group does not exist.")
        raise DeviceGroupNotFound

    current_groups[group.name] = group.value
    save_device_groups(current_groups)

def delete_device_group(group_name: str):
    current_groups = get_device_groups()
    if group_name not in current_groups.keys():
        UserActionLogger().log_error(f"Failed to delete device group {group_name}: group does not exist.")
        raise DeviceGroupNotFound
    if group_name in MANDATORY_GROUPS:
        UserActionLogger().log_error(f"Failed to delete device group {group_name}: cannot delete mandatory group.")
        raise DeviceGroupMandatoryDeleteError

    del current_groups[group_name]
    save_device_groups(current_groups)


## Device
def save_device(current_devices: dict):
    try:
        with open(NORNIR_HOSTS_FILE_PATH, "w", encoding='utf-8') as f:
            yaml.safe_dump(current_devices, f, sort_keys=False, explicit_start=True)
    except Exception:
        DeveloperLogger().log_error(f"Failed to save device: {traceback.format_exc()}")
        raise DeviceSaveError

def create_device_configuration_file(device_name: str) -> str:
    try:
        new_device_conf_file = DEVICES_CONFIGURATION_DIR_PATH / f"{device_name}.yml"
        new_device_conf_file.touch(exist_ok=True)
        return str(new_device_conf_file)
    except Exception:
        DeveloperLogger().log_error(f"Failed to create new device {device_name} configuration file : {traceback.format_exc()}")
        raise DeviceSaveError

def delete_device_configuration_file(device_name: str):
    try:
        device_conf_file = DEVICES_CONFIGURATION_DIR_PATH / f"{device_name}.yml"
        device_conf_file.unlink(missing_ok=True)
    except Exception:
        DeveloperLogger().log_error(f"Failed to delete device {device_name} configuration file: {traceback.format_exc()}")
        raise DeviceSaveError

def save_device_configuration(device_name: str, configuration: dict):
    try:
        with open(DEVICES_CONFIGURATION_DIR_PATH / f"{device_name}.yml", "w", encoding='utf-8') as f:
            yaml.safe_dump(configuration, f, sort_keys=False, explicit_start=True)
    except Exception:
        DeveloperLogger().log_error(f"Failed to save device {device_name} configuration: {traceback.format_exc()}")
        raise DeviceSaveError

def get_device_configuration(device_name: str) -> dict:
    try:
        with open(DEVICES_CONFIGURATION_DIR_PATH / f"{device_name}.yml",
                  "r", encoding='utf-8') as f:
            configuration = yaml.safe_load(f)
    except Exception:
        DeveloperLogger().log_error(f"Failed to get device {device_name} configuration: {traceback.format_exc()}")
        raise DeviceReadError
    if not configuration:
        return {}
    return configuration

def get_devices() -> dict:
    try:
        with open(NORNIR_HOSTS_FILE_PATH, "r", encoding='utf-8') as f:
            current_devices = yaml.safe_load(f)
    except Exception:
        DeveloperLogger().log_error(f"Failed to get devices: {traceback.format_exc()}")
        raise DeviceReadError
    if not current_devices:
        return {}
    return current_devices

def get_device(device_name: str) -> tuple:
    current_devices = get_devices()
    if device_name not in current_devices.keys():
        raise DeviceNotFound
    return device_name, current_devices[device_name]

def add_device(device: Device):
    current_devices = get_devices()
    if device.name in current_devices.keys():
        UserActionLogger().log_error(f"Failed to add new device {device.name}: device already exists.")
        raise DeviceAlreadyExists

    groups = list(get_device_groups().keys())
    for group_name in device.value["groups"]:
        if group_name not in groups:
            raise DeviceGroupNotFound

    device.value["data"]["configuration"] = create_device_configuration_file(device.name)
    current_devices[device.name] = device.value
    save_device(current_devices)

def edit_device(device: Device):
    current_devices = get_devices()
    if device.name not in current_devices.keys():
        UserActionLogger().log_error(f"Failed to edit device {device.name}: device does not exist.")
        raise DeviceNotFound

    groups = list(get_device_groups().keys())
    for group_name in device.value["groups"]:
        if group_name not in groups:
            raise DeviceGroupNotFound

    device.value["data"]["configuration"] = current_devices[device.name]["data"]["configuration"]
    current_devices[device.name] = device.value
    save_device(current_devices)

def delete_device(device_name: str):
    current_devices = get_devices()
    if device_name not in current_devices.keys():
        UserActionLogger().log_error(f"Failed to delete device {device_name}: device does not exist.")
        raise DeviceNotFound

    del current_devices[device_name]
    save_device(current_devices)
    delete_device_configuration_file(device_name)

## NetworkDevice - Management
def get_network_device(network_device_name: str) -> NetworkDevice:
    try:
        return Project().network_devices[network_device_name]
    except KeyError:
        raise NetworkDeviceNotFound(network_device_name=network_device_name)

def save_network_device(network_device_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    running = NornirEngine(filter_parameter={"hostname": network_device.hostname}).get_running_config()
    network_device.load_running_configuration(running[network_device_name])
    save_device_configuration(network_device_name, remove_all_key_from_dict(network_device.baseline_configuration.model_dump(), "render_args"))

def update_running_configuration(network_device_name: str):
    network_device = get_network_device(network_device_name)
    running = NornirEngine(filter_parameter={"hostname": network_device.hostname}).get_running_config()
    network_device.load_running_configuration(running[network_device_name])

def get_network_device_interface(network_device: NetworkDevice, network_device_interface_fullname: str) -> base.InterfaceDetails:
    try:
        return network_device.running_configuration.interfaces[network_device_interface_fullname]
    except KeyError:
        raise NetworkDeviceInterfaceNotFound(network_device_name=network_device.name, network_device_interface_fullname=network_device_interface_fullname)

def check_network_device_interface_ipv4_address(network_device_interface: base.InterfaceDetails):
    # TODO HOW TO ADD DEVICE NAME?
    if network_device_interface.ipv4_address is None:
        raise InterfaceIpAddressMissing

def check_network_device_configuration_drift(network_device_name: str) -> bool | dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    running, baseline = copy.deepcopy(network_device.running_configuration), copy.deepcopy(network_device.baseline_configuration)
    if (running.mpls_te == baseline.mpls_te and running.mpls_te_interfaces == baseline.mpls_te_interfaces and
            running.mpls_te_tunnels == baseline.mpls_te_tunnels and running.ipv4_explicit_paths == baseline.ipv4_explicit_paths and
            running.vrfs == baseline.vrfs and running.vrf_interfaces == baseline.vrf_interfaces and running.bgp == baseline.bgp):
        return False

    baseline_dict = baseline.model_dump()
    baseline_dict = remove_all_key_from_dict(baseline_dict, "render_args")
    baseline_dict = remove_all_key_from_dict(baseline_dict, "interfaces")
    running_dict = running.model_dump()
    running_dict = remove_all_key_from_dict(running_dict, "render_args")
    running_dict = remove_all_key_from_dict(running_dict, "interfaces")

    diff = DeepDiff(baseline_dict, running_dict, report_repetition=True)
    diff_dict = json.loads(diff.to_json())
    diff_dict = remove_all_key_from_dict(diff_dict, "old_type")
    diff_dict = remove_all_key_from_dict(diff_dict, "new_type")
    return diff_dict

def get_network_device_running_configuration(network_device_name: str) -> dict | None:
    network_device: NetworkDevice = get_network_device(network_device_name)
    return remove_all_key_from_dict(network_device.running_configuration.model_dump(), "render_args")

def get_network_device_baseline_configuration(network_device_name: str) -> dict | None:
    network_device: NetworkDevice = get_network_device(network_device_name)
    return remove_all_key_from_dict(network_device.baseline_configuration.model_dump(), "render_args")

def save_network_device_running_configuration(network_device_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    configuration = NetworkDeviceBaselineConfiguration(ipv4_explicit_paths=network_device.running_configuration.ipv4_explicit_paths,
                                                       mpls_te=network_device.running_configuration.mpls_te,
                                                       mpls_te_tunnels=network_device.running_configuration.mpls_te_tunnels,
                                                       mpls_te_interfaces=network_device.running_configuration.mpls_te_interfaces,
                                                       vrfs=network_device.running_configuration.vrfs,
                                                       vrf_interfaces=network_device.running_configuration.vrf_interfaces,
                                                       bgp=network_device.running_configuration.bgp).model_dump()
    save_device_configuration(network_device_name, remove_all_key_from_dict(configuration, "render_args"))
    network_device.load_saved_configuration(get_device_configuration(network_device_name))

def push_network_device_baseline_configuration(network_device_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    conf_drift: bool | dict = check_network_device_configuration_drift(network_device_name)

    if conf_drift is False:
        return

    def process_drift_output(drift_string: str) -> tuple:
        pattern = r"'(.*?)'"
        matches = re.findall(pattern, drift_string)

        try:
            if matches[0] == "mpls_te":
                return "mpls_te", None
            elif matches[0] == "bgp":
                return matches[1], matches[2]
            else:
                return matches[0], matches[1]
        except IndexError:
            return None, None

    def process_drift_values_changed(drift_string: str) -> tuple:
        pattern = r"'(.*?)'"
        matches = re.findall(pattern, drift_string)

        if matches[0] == "bgp":
            return matches[1]
        else:
            return matches[0]

    config_to_delete = set()
    if check_dict_key(conf_drift, "dictionary_item_added"):
        for drift_key in conf_drift["dictionary_item_added"]:
            type_, name = process_drift_output(drift_key)
            config_to_delete.add((type_, name))

    config_to_update = set()
    if check_dict_key(conf_drift, "values_changed"):
        for drift_key in conf_drift["values_changed"]:
            type_, name = process_drift_output(drift_key)
            if type_ is None:
                type_ = process_drift_values_changed(drift_key)
                for name in conf_drift["values_changed"][drift_key]["old_value"]:
                    config_to_update.add((type_, name))
            else:
                config_to_update.add((type_, name))
    if check_dict_key(conf_drift, "iterable_item_added"):
        for drift_key in conf_drift["iterable_item_added"]:
            type_, name = process_drift_output(drift_key)
            config_to_update.add((type_, name))
    if check_dict_key(conf_drift, "iterable_item_removed"):
        for drift_key in conf_drift["iterable_item_removed"]:
            type_, name = process_drift_output(drift_key)
            config_to_update.add((type_, name))
    if check_dict_key(conf_drift, "dictionary_item_removed"):
        for drift_key in conf_drift["dictionary_item_removed"]:
            type_, name = process_drift_output(drift_key)
            config_to_update.add((type_, name))
    if check_dict_key(conf_drift, "type_changes"):
        for drift_key in conf_drift["type_changes"]:
            type_, name = process_drift_output(drift_key)
            config_to_update.add((type_, name))

    netconf_configuration_payload = []
    DELETE_ORDER = {
        "mpls_te_tunnels": 1,
        "mpls_te_interfaces": 2,
        "mpls_te": 3,
        "ipv4_explicit_paths": 4,
        "vrf_interfaces": 5,
        "ipv4_unicast_vrfs": 6,
        "vrfs": 7,
        "vpnv4_unicast_neighbors": 8,
        "ipv4_unicast_neighbors": 9,
        "peer_policy_templates": 10,
        "peer_session_templates": 11
    }
    config_to_delete = sorted(list(config_to_delete), key=lambda item: DELETE_ORDER.get(item[0], 999))
    for type_, name in config_to_delete:
        if type_ == "ipv4_explicit_paths":
            netconf_configuration_payload.append(network_device.running_configuration.ipv4_explicit_paths[name].delete_config_netconf())
        elif type_ == "mpls_te":
            netconf_configuration_payload.append(network_device.running_configuration.mpls_te.delete_config_netconf())
        elif type_ == "mpls_te_interfaces":
            netconf_configuration_payload.append(network_device.running_configuration.mpls_te_interfaces[name].delete_config_netconf())
        elif type_ == "mpls_te_tunnels":
            netconf_configuration_payload.append(network_device.running_configuration.mpls_te_tunnels[name].delete_config_netconf())
        elif type_ == "vrfs":
            netconf_configuration_payload.append(network_device.running_configuration.vrfs[name].delete_config_netconf())
        elif type_ == "vrf_interfaces":
            netconf_configuration_payload.append(network_device.running_configuration.vrf_interfaces[name].delete_config_netconf())
        elif type_ == "peer_policy_templates":
            netconf_configuration_payload.append(network_device.running_configuration.bgp.peer_policy_templates[name].delete_config_netconf())
        elif type_ == "peer_session_templates":
            netconf_configuration_payload.append(network_device.running_configuration.bgp.peer_session_templates[name].delete_config_netconf())
        elif type_ == "ipv4_unicast_neighbors":
            netconf_configuration_payload.append(network_device.running_configuration.bgp.ipv4_unicast_neighbors[name].delete_config_netconf())
        elif type_ == "vpnv4_unicast_neighbors":
            netconf_configuration_payload.append(network_device.running_configuration.bgp.vpnv4_unicast_neighbors[name].delete_config_netconf())
        elif type_ == "ipv4_unicast_vrfs":
            netconf_configuration_payload.append(network_device.running_configuration.bgp.ipv4_unicast_vrfs[name].delete_config_netconf())

    CONFIGURE_ORDER = {
        "mpls_te": 1,
        "ipv4_explicit_paths": 2,
        "mpls_te_interfaces": 3,
        "mpls_te_tunnels": 4,
        "vrfs": 5,
        "vrf_interfaces": 6,
        "peer_policy_templates": 7,
        "peer_session_templates": 8,
        "ipv4_unicast_neighbors": 9,
        "vpnv4_unicast_neighbors": 10,
        "ipv4_unicast_vrfs": 11
    }
    config_to_update = sorted(list(config_to_update), key=lambda item: CONFIGURE_ORDER.get(item[0], 999))
    for type_, name in config_to_update:
        if type_ == "ipv4_explicit_paths":
            netconf_configuration_payload.append(network_device.baseline_configuration.ipv4_explicit_paths[name].get_config_netconf())
        elif type_ == "mpls_te":
            netconf_configuration_payload.append(network_device.baseline_configuration.mpls_te.get_config_netconf())
        elif type_ == "mpls_te_interfaces":
            netconf_configuration_payload.append(network_device.baseline_configuration.mpls_te_interfaces[name].get_config_netconf())
        elif type_ == "mpls_te_tunnels":
            netconf_configuration_payload.append(network_device.baseline_configuration.mpls_te_tunnels[name].get_config_netconf())
        elif type_ == "vrfs":
            netconf_configuration_payload.append(network_device.baseline_configuration.vrfs[name].get_config_netconf())
        elif type_ == "vrf_interfaces":
            netconf_configuration_payload.append(network_device.baseline_configuration.vrf_interfaces[name].get_config_netconf())
        elif type_ == "peer_policy_templates":
            netconf_configuration_payload.append(network_device.baseline_configuration.bgp.peer_policy_templates[name].get_config_netconf())
        elif type_ == "peer_session_templates":
            netconf_configuration_payload.append(network_device.baseline_configuration.bgp.peer_session_templates[name].get_config_netconf())
        elif type_ == "ipv4_unicast_neighbors":
            netconf_configuration_payload.append(network_device.baseline_configuration.bgp.ipv4_unicast_neighbors[name].get_config_netconf())
        elif type_ == "vpnv4_unicast_neighbors":
            netconf_configuration_payload.append(network_device.baseline_configuration.bgp.vpnv4_unicast_neighbors[name].get_config_netconf())
        elif type_ == "ipv4_unicast_vrfs":
            netconf_configuration_payload.append(network_device.baseline_configuration.bgp.ipv4_unicast_vrfs[name].get_config_netconf())

    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname},
                          netconf_payloads=netconf_configuration_payload).send_configs_netconf()
    if resalt[network_device.name] is None:
        update_running_configuration(network_device_name)
        return
    else:
        DeveloperLogger().log_error(f"NORNIR NETCONF: push_network_device_baseline_configuration: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - MPLS TE Interface
def get_network_device_configuration_interface_mpls_te(network_device_name: str, interface_fullname: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    network_device_interface: base.InterfaceDetails = get_network_device_interface(network_device, interface_fullname)

    configuration = {}
    if check_dict_key(network_device.baseline_configuration.mpls_te_interfaces, interface_fullname):
        configuration = network_device.baseline_configuration.mpls_te_interfaces[interface_fullname].model_dump()

    if network_device.platform == CISCO_XE:
        # delete unused class fields before returning dict
        # eg. configuration = remove_all_key_from_dict(configuration, "unused_key")
        # or create separate function to do that and hide logic
        pass

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_interface_mpls_te_configuration(network_device: NetworkDevice, network_device_interface: base.InterfaceDetails, mpls_te_configuration: dict) -> tuple:
    interface_mpls_te_conf, netconf_configuration_payload = None, None
    if network_device.platform == CISCO_XE:
        mpls_te_configuration['interface'] = {
            'name': network_device_interface.name,
            'id': network_device_interface.id
        }
        interface_mpls_te_conf = mpls_te_interface_cisco_xe.ConfigMplsTeInterface(**mpls_te_configuration)
        netconf_configuration_payload = interface_mpls_te_conf.get_config_netconf()
    return interface_mpls_te_conf, netconf_configuration_payload

def configure_network_device_interface_mpls_te(network_device_name: str, interface_fullname: str, mpls_te_configuration: dict):
    network_device: NetworkDevice = get_network_device(network_device_name)
    network_device_interface: base.InterfaceDetails = get_network_device_interface(network_device, interface_fullname)

    interface_mpls_te_conf, netconf_configuration_payload = prepare_network_device_interface_mpls_te_configuration(network_device, network_device_interface, mpls_te_configuration)

    if netconf_configuration_payload is not None and interface_mpls_te_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.mpls_te_interfaces[interface_fullname] = interface_mpls_te_conf
            save_network_device(network_device_name)
            return
        else:
            raise IncorrectConfiguration

def delete_network_device_configuration_interface_mpls_te(network_device_name: str, interface_fullname: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    network_device_interface: base.InterfaceDetails = get_network_device_interface(network_device, interface_fullname)
    netconf_configuration_payload = network_device.baseline_configuration.mpls_te_interfaces[interface_fullname].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.mpls_te_interfaces[interface_fullname]
        save_network_device(network_device_name)
        return
    else:
        raise IncorrectConfiguration


## NetworkDevice - MPLS TE Global
def is_network_device_mpls_te_enabled(network_device_name: str) -> bool:
    network_device: NetworkDevice = get_network_device(network_device_name)
    if network_device.baseline_configuration.mpls_te is not None:
        return True
    return False

def configure_network_device_mpls_te(network_device_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    mpls_te_conf, netconf_configuration_payload = None, None
    if network_device.platform == CISCO_XE:
        mpls_te_conf = mpls_te_cisco_xe.ConfigMplsTeTunnels(enable=True)
        netconf_configuration_payload = mpls_te_conf.get_config_netconf()

    if netconf_configuration_payload is not None and mpls_te_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.mpls_te = mpls_te_conf
            save_network_device(network_device_name)
            return
        else:
            raise IncorrectConfiguration

def delete_network_device_configuration_mpls_te(network_device_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    netconf_configuration_payload = network_device.baseline_configuration.mpls_te.delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        network_device.baseline_configuration.mpls_te = None
        save_network_device(network_device_name)
        return
    else:
        raise IncorrectConfiguration


## NetworkDevice - IP Explicit Path
def check_ip_explicit_path_type(ip_explicit_path_type: str):
    if ip_explicit_path_type not in [IpExplicitPathConfigurationType.NEXT_IP_ADDRESS,
                                     IpExplicitPathConfigurationType.EXCLUDE]:
        raise IpExplicitPathTypeError

def check_ip_explicit_path_configuration_method(ip_explicit_path_configuration_method: str):
    if ip_explicit_path_configuration_method not in [IpExplicitPathConfigurationMethod.EXPLICIT,
                                                     IpExplicitPathConfigurationMethod.NETWORK_DEVICE_NAME,
                                                     IpExplicitPathConfigurationMethod.NETWORK_DEVICE_INTERFACE]:
        raise IpExplicitPathConfigurationMethodError

def prepare_ip_explicit_path_data(ip_explicit_path_configuration_method: str, ip_explicit_path_data: list) -> list:
    ip_explicit_path_data_full = []
    if ip_explicit_path_configuration_method == IpExplicitPathConfigurationMethod.EXPLICIT:
        return ip_explicit_path_data
    if ip_explicit_path_configuration_method == IpExplicitPathConfigurationMethod.NETWORK_DEVICE_NAME:
        for entry in ip_explicit_path_data:
            network_device: NetworkDevice = get_network_device(entry['device_name'])
            loopback_interface: base.InterfaceDetails = get_network_device_interface(network_device, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME)
            check_network_device_interface_ipv4_address(loopback_interface)
            entry['ipv4_address'] = loopback_interface.ipv4_address
            ip_explicit_path_data_full.append(entry)
        return ip_explicit_path_data_full
    if ip_explicit_path_configuration_method == IpExplicitPathConfigurationMethod.NETWORK_DEVICE_INTERFACE:
        for entry in ip_explicit_path_data:
            network_device: NetworkDevice = get_network_device(entry['device_name'])
            interface: base.InterfaceDetails = get_network_device_interface(network_device, entry['interface_fullname'])
            check_network_device_interface_ipv4_address(interface)
            entry['ipv4_address'] = interface.ipv4_address
            ip_explicit_path_data_full.append(entry)
        return ip_explicit_path_data_full
    raise IpExplicitPathConfigurationMethodError

def prepare_ip_explicit_path_configuration(network_device: NetworkDevice, ip_explicit_path_configuration: dict, operation: str):
    current_ipv4_explicit_paths = _get_ip_explicit_paths(network_device)

    if operation == ConfigurationOperation.NEW:
        if ip_explicit_path_configuration['name'] in current_ipv4_explicit_paths.keys():
            UserActionLogger().log_error(f"Failed to configure IP explicit path {ip_explicit_path_configuration['name']}: already exist")
            raise IpExplicitPathAlreadyExists(ip_explicit_path_name=ip_explicit_path_configuration['name'])
    elif operation == ConfigurationOperation.UPDATE:
        if ip_explicit_path_configuration['name'] not in current_ipv4_explicit_paths.keys():
            UserActionLogger().log_error(f"Failed to edit IP explicit path {ip_explicit_path_configuration['name']}: does not exist")
            raise IpExplicitPathNotFound(ip_explicit_path_name=ip_explicit_path_configuration['name'])

    check_ip_explicit_path_type(ip_explicit_path_configuration['type'])
    check_ip_explicit_path_configuration_method(ip_explicit_path_configuration['configuration_method'])
    ip_explicit_path_data_full = prepare_ip_explicit_path_data(ip_explicit_path_configuration['configuration_method'],
                                                               ip_explicit_path_configuration['data'])

    ip_explicit_path_conf, netconf_configuration_payload = None, None
    if network_device.platform == CISCO_XE:
        if ip_explicit_path_configuration['type'] == IpExplicitPathConfigurationType.EXCLUDE:
            path_exclude_address: list[ip_explicit_path_cisco_xe.IpExplicitPathEntryExcludeAddress] = []
            index = 10
            for ip_explicit_path_entry in ip_explicit_path_data_full:
                path_exclude_address.append(ip_explicit_path_cisco_xe.IpExplicitPathEntryExcludeAddress(index=index, ipv4_address=ip_explicit_path_entry['ipv4_address']))
                index = index + 10

            ip_explicit_path_conf = ip_explicit_path_cisco_xe.ConfigIpExplicitPath(name=ip_explicit_path_configuration['name'], path_exclude_address=path_exclude_address)
            netconf_configuration_payload = ip_explicit_path_conf.get_config_netconf()

        elif ip_explicit_path_configuration['type'] == IpExplicitPathConfigurationType.NEXT_IP_ADDRESS:
            path_next_address: list[ip_explicit_path_cisco_xe.IpExplicitPathEntryNextAddress] = []
            index = 10
            for ip_explicit_path_entry in ip_explicit_path_data_full:
                path_next_address.append(ip_explicit_path_cisco_xe.IpExplicitPathEntryNextAddress(index=index, ipv4_address=ip_explicit_path_entry['ipv4_address'], loose=ip_explicit_path_entry['loose']))
                index += 10

            ip_explicit_path_conf = ip_explicit_path_cisco_xe.ConfigIpExplicitPath(name=ip_explicit_path_configuration['name'], path_next_address=path_next_address)
            netconf_configuration_payload = ip_explicit_path_conf.get_config_netconf()

    return ip_explicit_path_conf, netconf_configuration_payload

def _get_ip_explicit_paths(network_device: NetworkDevice) -> dict:
    return network_device.baseline_configuration.ipv4_explicit_paths

def get_ip_explicit_paths(network_device_name: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    return _get_ip_explicit_paths(network_device)

def get_ip_explicit_path_configuration(network_device_name: str, ip_explicit_path_name: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    current_ipv4_explicit_paths = _get_ip_explicit_paths(network_device)

    if ip_explicit_path_name not in current_ipv4_explicit_paths.keys():
        UserActionLogger().log_error(f"Failed to delete IP explicit path {ip_explicit_path_name}: dose not exist")
        raise IpExplicitPathNotFound(ip_explicit_path_name=ip_explicit_path_name)

    configuration = network_device.baseline_configuration.ipv4_explicit_paths[ip_explicit_path_name].model_dump()
    if network_device.platform == CISCO_XE:
        # delete unused class fields before returning dict
        # eg. configuration = remove_all_key_from_dict(configuration, "unused_key")
        # or create separate function to do that and hide logic
        pass

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def configure_network_device_ip_explicit_path(network_device_name: str, ip_explicit_path_configuration: dict, operation: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    ip_explicit_path_conf, netconf_configuration_payload = prepare_ip_explicit_path_configuration(network_device, ip_explicit_path_configuration, operation)

    if netconf_configuration_payload is not None and ip_explicit_path_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device_name] is None:
            network_device.baseline_configuration.ipv4_explicit_paths[ip_explicit_path_configuration['name']] = ip_explicit_path_conf
            save_network_device(network_device_name)
            return
        else:
            raise IncorrectConfiguration

def delete_network_device_ip_explicit_path(network_device_name: str, ip_explicit_path_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    current_ipv4_explicit_paths = _get_ip_explicit_paths(network_device)

    if ip_explicit_path_name not in current_ipv4_explicit_paths.keys():
        UserActionLogger().log_error(f"Failed to delete IP explicit path {ip_explicit_path_name}: dose not exist")
        raise IpExplicitPathNotFound

    netconf_configuration_payload = network_device.baseline_configuration.ipv4_explicit_paths[ip_explicit_path_name].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.ipv4_explicit_paths[ip_explicit_path_name]
        save_network_device(network_device_name)
        return
    else:
        raise IncorrectConfiguration

## NetworkDevice - MPLS TE Tunnel
def get_mpls_te_tunnels(network_device: NetworkDevice) -> dict:
    return network_device.baseline_configuration.mpls_te_tunnels

def get_mpls_te_tunnel(network_device: NetworkDevice, mpls_te_tunnel_fullname: str):
    current_mpls_te_tunnels = get_mpls_te_tunnels(network_device)
    if mpls_te_tunnel_fullname not in current_mpls_te_tunnels.keys():
        raise MplsTeTunnelNotFound(mpls_te_tunnel_fullname=mpls_te_tunnel_fullname)
    return network_device.baseline_configuration.mpls_te_tunnels[mpls_te_tunnel_fullname]

def get_mpls_te_tunnel_path(network_device: NetworkDevice, mpls_te_tunnel_fullname: str) -> list[dict]:
    tunnel_path = []
    if network_device.platform == CISCO_XE:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}).get_show_command_output(f"show mpls tr tun {mpls_te_tunnel_fullname}")
        if resalt[network_device.name] is None:
            return []
        resalt = resalt[network_device.name]

        resv_info_pattern = re.compile(r"RSVP Resv Info:\s*Record\s*Route:\s*(.*?)\s*Fspec:",re.DOTALL | re.IGNORECASE)
        match = resv_info_pattern.search(resalt)
        if not match:
            return []

        record_route_string = match.group(1).strip()
        if not record_route_string:
            return []

        # Regex IP(Label)
        ip_label_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\((\d+)\)")
        matches = ip_label_pattern.findall(record_route_string)

        tunnel_path = []
        for ip, label in matches:
            tunnel_path.append({
                "ipv4_address": ip,
                "label": label
            })

    tunnel_path_with_names = []
    for path in tunnel_path:
        network_device_name, network_device_interface_fullname = get_network_device_name_and_interface_fullname(path['ipv4_address'])
        # if network_device_interface_fullname.startswith("Loopback"):
        #     continue
        path['network_device_name'] = network_device_name
        path['network_device_interface_fullname'] = network_device_interface_fullname
        tunnel_path_with_names.append(path)

    return tunnel_path_with_names



def get_network_device_mpls_te_tunnel_configuration(network_device_name: str, mpls_te_tunnel_fullname: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    mpls_te_tunnel = get_mpls_te_tunnel(network_device, mpls_te_tunnel_fullname)

    configuration = mpls_te_tunnel.model_dump()
    if network_device.platform == CISCO_XE:
        # delete unused class fields before returning dict
        # eg. configuration = remove_all_key_from_dict(configuration, "unused_key")
        # or create separate function to do that and hide logic
        pass

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def get_network_device_mpls_te_tunnel_path(network_device_name: str, mpls_te_tunnel_fullname: str) -> list[dict]:
    network_device: NetworkDevice = get_network_device(network_device_name)
    mpls_te_tunnel = get_mpls_te_tunnel(network_device, mpls_te_tunnel_fullname)
    return get_mpls_te_tunnel_path(network_device, mpls_te_tunnel_fullname)

def delete_network_device_configuration_mpls_te_tunnel(network_device_name: str, mpls_te_tunnel_fullname: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    mpls_te_tunnel = get_mpls_te_tunnel(network_device, mpls_te_tunnel_fullname)
    netconf_configuration_payload = mpls_te_tunnel.delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.mpls_te_tunnels[mpls_te_tunnel_fullname]
        save_network_device(network_device_name)
        return
    else:
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_mpls_te_tunnel: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - VRF
def get_network_device_vrf(network_device: NetworkDevice, vrf_name: str):
    if vrf_name not in network_device.baseline_configuration.vrfs.keys():
        raise VrfNotFound(vrf_name=vrf_name)
    return network_device.baseline_configuration.vrfs[vrf_name]

def get_network_device_vrf_configuration(network_device_name: str, vrf_name: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    vrf = get_network_device_vrf(network_device, vrf_name)

    configuration = vrf.model_dump()

    if network_device.platform == CISCO_XE:
        # delete unused class fields before returning dict
        # eg. configuration = remove_all_key_from_dict(configuration, "unused_key")
        # or create separate function to do that and hide logic
        pass

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_vrf_configuration(network_device: NetworkDevice, vrf_configuration: dict) -> tuple:
    vrf_conf, netconf_configuration_payload = None, None
    if network_device.platform == CISCO_XE:
        if check_dict_key(vrf_configuration, 'route_target'):
            vrf_configuration['route_target']['import_'] = vrf_configuration['route_target']['import']
            vrf_configuration = remove_all_key_from_dict(vrf_configuration, 'import')
        vrf_conf = vrf_cisco_xe.ConfigVrf(**vrf_configuration)
        netconf_configuration_payload = vrf_conf.get_config_netconf()
    return vrf_conf, netconf_configuration_payload

def configure_network_device_vrf(network_device_name: str, vrf_configuration: dict, operation: str):
    network_device: NetworkDevice = get_network_device(network_device_name)

    if operation == ConfigurationOperation.NEW:
        if vrf_configuration['name'] in network_device.baseline_configuration.vrfs.keys():
            raise VrfAlreadyExists(vrf_configuration['name'])
    elif operation == ConfigurationOperation.UPDATE:
        get_network_device_vrf(network_device, vrf_configuration['name'])

    vrf_conf, netconf_configuration_payload = prepare_network_device_vrf_configuration(network_device, vrf_configuration)

    if netconf_configuration_payload is not None and vrf_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.vrfs[vrf_conf.name] = vrf_conf
            save_network_device(network_device_name)
            return
        else:
            DeveloperLogger().log_error(f"NORNIR NETCONF: configure_network_device_interface_vrf: {resalt}")
            raise IncorrectConfiguration

def delete_network_device_configuration_vrf(network_device_name: str, vrf_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    vrf = get_network_device_vrf(network_device, vrf_name)
    netconf_configuration_payload = network_device.baseline_configuration.vrfs[vrf_name].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.vrfs[vrf_name]
        save_network_device(network_device_name)
        return
    else:
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_interface_vrf: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - Interface VRF
def get_network_device_configuration_interface_vrf(network_device_name: str, interface_fullname: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    network_device_interface: base.InterfaceDetails = get_network_device_interface(network_device, interface_fullname)

    configuration = {}
    if check_dict_key(network_device.baseline_configuration.vrf_interfaces, interface_fullname):
        configuration = network_device.baseline_configuration.vrf_interfaces[interface_fullname].model_dump()

    if network_device.platform == CISCO_XE:
        # delete unused class fields before returning dict
        # eg. configuration = remove_all_key_from_dict(configuration, "unused_key")
        # or create separate function to do that and hide logic
        pass

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_interface_vrf_configuration(network_device: NetworkDevice, network_device_interface: base.InterfaceDetails, vrf_configuration: dict) -> tuple:
    interface_vrf_conf, netconf_configuration_payload = None, None
    if network_device.platform == CISCO_XE:
        vrf_configuration['interface'] = {
            'name': network_device_interface.name,
            'id': network_device_interface.id
        }
        vrf_configuration['ipv4_mask'] = str(ipaddress.IPv4Network(f'0.0.0.0/{vrf_configuration['ipv4_mask']}', strict=False).netmask)
        interface_vrf_conf = vrf_interface_cisco_xe.ConfigInterfaceVrf(**vrf_configuration)
        netconf_configuration_payload = interface_vrf_conf.get_config_netconf()
    return interface_vrf_conf, netconf_configuration_payload

def configure_network_device_interface_vrf(network_device_name: str, interface_fullname: str, vrf_configuration: dict):
    network_device: NetworkDevice = get_network_device(network_device_name)
    network_device_interface: base.InterfaceDetails = get_network_device_interface(network_device, interface_fullname)
    vrf = get_network_device_vrf(network_device, vrf_configuration['vrf_name'])

    interface_vrf_conf, netconf_configuration_payload = prepare_network_device_interface_vrf_configuration(network_device, network_device_interface, vrf_configuration)

    if netconf_configuration_payload is not None and interface_vrf_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.vrf_interfaces[interface_fullname] = interface_vrf_conf
            save_network_device(network_device_name)
            return
        else:
            DeveloperLogger().log_error(f"NORNIR NETCONF: configure_network_device_interface_vrf: {resalt}")
            raise IncorrectConfiguration

def delete_network_device_configuration_interface_vrf(network_device_name: str, interface_fullname: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    network_device_interface: base.InterfaceDetails = get_network_device_interface(network_device, interface_fullname)
    netconf_configuration_payload = network_device.baseline_configuration.vrf_interfaces[interface_fullname].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.vrf_interfaces[interface_fullname]
        save_network_device(network_device_name)
        return
    else:
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_interface_vrf: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - BGP Peer Session Template
def get_network_device_bgp_peer_session_template(network_device: NetworkDevice, template_name: str):
    if template_name not in network_device.baseline_configuration.bgp.peer_session_templates.keys():
        raise BgpPeerSessionTemplateNotFound(template_name=template_name)
    return network_device.baseline_configuration.bgp.peer_session_templates[template_name]

def get_network_device_bgp_peer_session_template_configuration(network_device_name: str, template_name: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    template = get_network_device_bgp_peer_session_template(network_device, template_name)

    configuration = template.model_dump()

    if network_device.platform == CISCO_XE:
        # delete unused class fields before returning dict
        # eg. configuration = remove_all_key_from_dict(configuration, "unused_key")
        # or create separate function to do that and hide logic
        pass

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_bgp_peer_session_template_configuration(network_device: NetworkDevice, template_configuration: dict) -> tuple:
    template_conf, netconf_configuration_payload = None, None
    template_configuration['asn'] = network_device.baseline_configuration.bgp.asn

    if network_device.platform == CISCO_XE:
        if check_dict_key(template_configuration, "update_source_interface_fullname") and template_configuration['update_source_interface_fullname'] is not None:
            network_device_interface: base.InterfaceDetails = get_network_device_interface(network_device, template_configuration['update_source_interface_fullname'])
            template_configuration['update_source_interface'] = base.Interface(name=network_device_interface.name, id=network_device_interface.id)
            template_configuration = remove_all_key_from_dict(template_configuration, "update_source_interface_fullname")

        template_conf = bgp_cisco_xe.ConfigBgpTemplatePeerSession(**template_configuration)
        netconf_configuration_payload = template_conf.get_config_netconf()
    return template_conf, netconf_configuration_payload

def configure_network_device_bgp_peer_session_template(network_device_name: str, template_configuration: dict, operation: str):
    network_device: NetworkDevice = get_network_device(network_device_name)

    if operation == ConfigurationOperation.NEW:
        if template_configuration['name'] in network_device.baseline_configuration.bgp.peer_session_templates.keys():
            raise BgpPeerSessionTemplateAlreadyExists(template_configuration['name'])
    elif operation == ConfigurationOperation.UPDATE:
        get_network_device_bgp_peer_session_template(network_device, template_configuration['name'])

    template_conf, netconf_configuration_payload = prepare_network_device_bgp_peer_session_template_configuration(network_device, template_configuration)

    if netconf_configuration_payload is not None and template_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.bgp.peer_session_templates[template_conf.name] = template_conf
            save_network_device(network_device_name)
            return
        else:
            DeveloperLogger().log_error(f"NORNIR NETCONF: configure_network_device_bgp_peer_session_template: {resalt}")
            raise IncorrectConfiguration

def delete_network_device_configuration_bgp_peer_session_template(network_device_name: str, template_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    template = get_network_device_bgp_peer_session_template(network_device, template_name)
    netconf_configuration_payload = network_device.baseline_configuration.bgp.peer_session_templates[template_name].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.bgp.peer_session_templates[template_name]
        save_network_device(network_device_name)
        return
    else:
        if "RPCError: illegal reference" in resalt[network_device.name]:
            raise BgpPeerSessionTemplateInUse(template_name)
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_bgp_peer_session_template: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - BGP Peer Policy Template
def get_network_device_bgp_peer_policy_template(network_device: NetworkDevice, template_name: str):
    if template_name not in network_device.baseline_configuration.bgp.peer_policy_templates.keys():
        raise BgpPeerPolicyTemplateNotFound(template_name=template_name)
    return network_device.baseline_configuration.bgp.peer_policy_templates[template_name]

def get_network_device_bgp_peer_policy_template_configuration(network_device_name: str, template_name: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    template = get_network_device_bgp_peer_policy_template(network_device, template_name)

    configuration = template.model_dump()

    if network_device.platform == CISCO_XE:
        # delete unused class fields before returning dict
        # eg. configuration = remove_all_key_from_dict(configuration, "unused_key")
        # or create separate function to do that and hide logic
        pass

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_bgp_peer_policy_template_configuration(network_device: NetworkDevice, template_configuration: dict) -> tuple:
    template_conf, netconf_configuration_payload = None, None
    template_configuration['asn'] = network_device.baseline_configuration.bgp.asn

    if network_device.platform == CISCO_XE:
        template_conf = bgp_cisco_xe.ConfigBgpTemplatePeerPolicy(**template_configuration)
        netconf_configuration_payload = template_conf.get_config_netconf()
    return template_conf, netconf_configuration_payload

def configure_network_device_bgp_peer_policy_template(network_device_name: str, template_configuration: dict, operation: str):
    network_device: NetworkDevice = get_network_device(network_device_name)

    if operation == ConfigurationOperation.NEW:
        if template_configuration['name'] in network_device.baseline_configuration.bgp.peer_policy_templates.keys():
            raise BgpPeerPolicyTemplateAlreadyExists(template_configuration['name'])
    elif operation == ConfigurationOperation.UPDATE:
        get_network_device_bgp_peer_policy_template(network_device, template_configuration['name'])

    template_conf, netconf_configuration_payload = prepare_network_device_bgp_peer_policy_template_configuration(network_device, template_configuration)

    if netconf_configuration_payload is not None and template_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.bgp.peer_policy_templates[template_conf.name] = template_conf
            save_network_device(network_device_name)
            return
        else:
            DeveloperLogger().log_error(f"NORNIR NETCONF: configure_network_device_bgp_peer_policy_template: {resalt}")
            raise IncorrectConfiguration

def delete_network_device_configuration_bgp_peer_policy_template(network_device_name: str, template_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    template = get_network_device_bgp_peer_policy_template(network_device, template_name)
    netconf_configuration_payload = network_device.baseline_configuration.bgp.peer_policy_templates[template_name].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.bgp.peer_policy_templates[template_name]
        save_network_device(network_device_name)
        return
    else:
        if "RPCError: illegal reference" in resalt[network_device.name]:
            raise BgpPeerPolicyTemplateInUse(template_name)
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_bgp_peer_policy_template: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - BGP IPv4 Unicast Neighbor
def get_network_device_bgp_ipv4_unicast_neighbor(network_device: NetworkDevice, neighbor_id: str):
    if neighbor_id not in network_device.baseline_configuration.bgp.ipv4_unicast_neighbors.keys():
        raise BgpIPv4UnicastNeighborNotFound(id=neighbor_id)
    return network_device.baseline_configuration.bgp.ipv4_unicast_neighbors[neighbor_id]

def get_network_device_bgp_ipv4_unicast_neighbor_configuration(network_device_name: str, neighbor_id: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    ipv4_unicast_neighbor = get_network_device_bgp_ipv4_unicast_neighbor(network_device, neighbor_id)

    configuration = ipv4_unicast_neighbor.model_dump()

    if network_device.platform == CISCO_XE:
        configuration = configuration['neighbor']

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_bgp_ipv4_unicast_neighbor_configuration(network_device: NetworkDevice, bgp_neighbor_configuration: dict) -> tuple:
    bgp_ipv4_unicast_neighbor_conf, netconf_configuration_payload = None, None
    
    bgp_ipv4_unicast_neighbor_configuration = {
        "asn": network_device.baseline_configuration.bgp.asn,
        "neighbor": bgp_neighbor_configuration
    }

    if network_device.platform == CISCO_XE:
        bgp_ipv4_unicast_neighbor_conf = bgp_cisco_xe.ConfigBgpIpv4UnicastNeighbor(**bgp_ipv4_unicast_neighbor_configuration)
        netconf_configuration_payload = bgp_ipv4_unicast_neighbor_conf.get_config_netconf()
    return bgp_ipv4_unicast_neighbor_conf, netconf_configuration_payload

def configure_network_device_bgp_ipv4_unicast_neighbor(network_device_name: str, bgp_neighbor_configuration: dict, operation: str):
    network_device: NetworkDevice = get_network_device(network_device_name)

    if operation == ConfigurationOperation.NEW:
        if bgp_neighbor_configuration['ipv4_address'] in network_device.baseline_configuration.bgp.ipv4_unicast_neighbors.keys():
            raise BgpIPv4UnicastNeighborAlreadyExists(bgp_neighbor_configuration['ipv4_address'])
    elif operation == ConfigurationOperation.UPDATE:
        get_network_device_bgp_ipv4_unicast_neighbor(network_device, bgp_neighbor_configuration['ipv4_address'])

    if check_dict_key(bgp_neighbor_configuration, "peer_template") and bgp_neighbor_configuration["peer_template"] is not None:
        if check_dict_key(bgp_neighbor_configuration["peer_template"], "session_name") and bgp_neighbor_configuration["peer_template"]["session_name"] is not None:
            get_network_device_bgp_peer_session_template(network_device, bgp_neighbor_configuration["peer_template"]["session_name"])
        if check_dict_key(bgp_neighbor_configuration["peer_template"], "policy_name") and bgp_neighbor_configuration["peer_template"]["policy_name"] is not None:
            get_network_device_bgp_peer_policy_template(network_device, bgp_neighbor_configuration["peer_template"]["policy_name"])
    if check_dict_key(bgp_neighbor_configuration, "update_source_interface_fullname") and bgp_neighbor_configuration["update_source_interface_fullname"] is not None:
        interface = get_network_device_interface(network_device, bgp_neighbor_configuration["update_source_interface_fullname"])
        bgp_neighbor_configuration["update_source_interface"] = base.Interface(name=interface.name, id=interface.id)
        bgp_neighbor_configuration = remove_all_key_from_dict(bgp_neighbor_configuration, "update_source_interface_fullname")

    bgp_ipv4_unicast_neighbor_conf, netconf_configuration_payload = prepare_network_device_bgp_ipv4_unicast_neighbor_configuration(network_device, bgp_neighbor_configuration)

    if netconf_configuration_payload is not None and bgp_ipv4_unicast_neighbor_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.bgp.ipv4_unicast_neighbors[bgp_ipv4_unicast_neighbor_conf.neighbor.ipv4_address] = bgp_ipv4_unicast_neighbor_conf
            save_network_device(network_device_name)
            return
        else:
            DeveloperLogger().log_error(f"NORNIR NETCONF: configure_network_device_bgp_ipv4_unicast_neighbor: {resalt}")
            raise IncorrectConfiguration

def delete_network_device_configuration_bgp_ipv4_unicast_neighbor(network_device_name: str, neighbor_id: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    bgp_ipv4_unicast_neighbor = get_network_device_bgp_ipv4_unicast_neighbor(network_device, neighbor_id)
    netconf_configuration_payload = network_device.baseline_configuration.bgp.ipv4_unicast_neighbors[neighbor_id].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.bgp.ipv4_unicast_neighbors[neighbor_id]
        save_network_device(network_device_name)
        return
    else:
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_bgp_ipv4_unicast_neighbor: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - BGP VPNv4 Unicast Neighbor
def get_network_device_bgp_vpnv4_unicast_neighbor(network_device: NetworkDevice, neighbor_id: str):
    if neighbor_id not in network_device.baseline_configuration.bgp.vpnv4_unicast_neighbors.keys():
        raise BgpVpnv4UnicastNeighborNotFound(id=neighbor_id)
    return network_device.baseline_configuration.bgp.vpnv4_unicast_neighbors[neighbor_id]

def get_network_device_bgp_vpnv4_unicast_neighbor_configuration(network_device_name: str, neighbor_id: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    vpnv4_unicast_neighbor = get_network_device_bgp_vpnv4_unicast_neighbor(network_device, neighbor_id)

    configuration = vpnv4_unicast_neighbor.model_dump()

    if network_device.platform == CISCO_XE:
        configuration = configuration['neighbor']

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_bgp_vpnv4_unicast_neighbor_configuration(network_device: NetworkDevice, bgp_neighbor_configuration: dict) -> tuple:
    bgp_vpnv4_unicast_neighbor_conf, netconf_configuration_payload = None, None
    
    bgp_vpnv4_unicast_neighbor_configuration = {
        "asn": network_device.baseline_configuration.bgp.asn,
        "neighbor": bgp_neighbor_configuration
    }

    if network_device.platform == CISCO_XE:
        bgp_vpnv4_unicast_neighbor_conf = bgp_cisco_xe.ConfigBgpVpnv4UnicastNeighbor(**bgp_vpnv4_unicast_neighbor_configuration)
        netconf_configuration_payload = bgp_vpnv4_unicast_neighbor_conf.get_config_netconf()
    return bgp_vpnv4_unicast_neighbor_conf, netconf_configuration_payload

def configure_network_device_bgp_vpnv4_unicast_neighbor(network_device_name: str, bgp_neighbor_configuration: dict, operation: str):
    network_device: NetworkDevice = get_network_device(network_device_name)

    if operation == ConfigurationOperation.NEW:
        if bgp_neighbor_configuration['ipv4_address'] in network_device.baseline_configuration.bgp.vpnv4_unicast_neighbors.keys():
            raise BgpVpnv4UnicastNeighborAlreadyExists(bgp_neighbor_configuration['ipv4_address'])
    elif operation == ConfigurationOperation.UPDATE:
        get_network_device_bgp_vpnv4_unicast_neighbor(network_device, bgp_neighbor_configuration['ipv4_address'])

    if check_dict_key(bgp_neighbor_configuration, "peer_template") and bgp_neighbor_configuration["peer_template"] is not None:
        if check_dict_key(bgp_neighbor_configuration["peer_template"], "policy_name") and bgp_neighbor_configuration["peer_template"]["policy_name"] is not None:
            get_network_device_bgp_peer_policy_template(network_device, bgp_neighbor_configuration["peer_template"]["policy_name"])
    if check_dict_key(bgp_neighbor_configuration, "update_source_interface_fullname") and bgp_neighbor_configuration["update_source_interface_fullname"] is not None:
        get_network_device_interface(network_device, bgp_neighbor_configuration["update_source_interface_fullname"])

    bgp_vpnv4_unicast_neighbor_conf, netconf_configuration_payload = prepare_network_device_bgp_vpnv4_unicast_neighbor_configuration(network_device, bgp_neighbor_configuration)

    if netconf_configuration_payload is not None and bgp_vpnv4_unicast_neighbor_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.bgp.vpnv4_unicast_neighbors[bgp_vpnv4_unicast_neighbor_conf.neighbor.ipv4_address] = bgp_vpnv4_unicast_neighbor_conf
            save_network_device(network_device_name)
            return
        else:
            DeveloperLogger().log_error(f"NORNIR NETCONF: configure_network_device_bgp_vpnv4_unicast_neighbor: {resalt}")
            raise IncorrectConfiguration

def delete_network_device_configuration_bgp_vpnv4_unicast_neighbor(network_device_name: str, neighbor_id: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    bgp_vpnv4_unicast_neighbor = get_network_device_bgp_vpnv4_unicast_neighbor(network_device, neighbor_id)
    netconf_configuration_payload = network_device.baseline_configuration.bgp.vpnv4_unicast_neighbors[neighbor_id].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.bgp.vpnv4_unicast_neighbors[neighbor_id]
        save_network_device(network_device_name)
        return
    else:
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_bgp_vpnv4_unicast_neighbor: {resalt}")
        raise IncorrectConfiguration


## NetworkDevice - BGP IPv4 Unicast VRF
def get_network_device_bgp_ipv4_unicast_vrf(network_device: NetworkDevice, vrf_name: str):
    if vrf_name not in network_device.baseline_configuration.bgp.ipv4_unicast_vrfs.keys():
        raise BgpIpv4UnicastVrfNotFound(vrf_name=vrf_name)
    return network_device.baseline_configuration.bgp.ipv4_unicast_vrfs[vrf_name]

def get_network_device_bgp_ipv4_unicast_vrf_configuration(network_device_name: str, vrf_name: str) -> dict:
    network_device: NetworkDevice = get_network_device(network_device_name)
    ipv4_unicast_vrf = get_network_device_bgp_ipv4_unicast_vrf(network_device, vrf_name)

    configuration = ipv4_unicast_vrf.model_dump()

    if network_device.platform == CISCO_XE:
        configuration = remove_all_key_from_dict(configuration, "asn")

    configuration = remove_all_key_from_dict(configuration, "render_args")
    return configuration

def prepare_network_device_bgp_ipv4_unicast_vrf_configuration(network_device: NetworkDevice, bgp_vrf_configuration: dict) -> tuple:
    bgp_ipv4_unicast_vrf_conf, netconf_configuration_payload = None, None
    
    bgp_vrf_configuration["asn"] = network_device.baseline_configuration.bgp.asn 
    
    if check_dict_key(bgp_vrf_configuration, "networks"):
        for network in bgp_vrf_configuration["networks"]:
            network['ipv4_mask'] = str(ipaddress.IPv4Network(f'0.0.0.0/{network['ipv4_mask']}', strict=False).netmask)
    if check_dict_key(bgp_vrf_configuration, "aggregate_addresses"):
        for aggregate_addresse in bgp_vrf_configuration["aggregate_addresses"]:
            aggregate_addresse['ipv4_mask'] = str(ipaddress.IPv4Network(f'0.0.0.0/{aggregate_addresse['ipv4_mask']}', strict=False).netmask)
    
    if network_device.platform == CISCO_XE:
        bgp_ipv4_unicast_vrf_conf = bgp_cisco_xe.ConfigBgpIpv4UnicastVrf(**bgp_vrf_configuration)
        netconf_configuration_payload = bgp_ipv4_unicast_vrf_conf.get_config_netconf()
    return bgp_ipv4_unicast_vrf_conf, netconf_configuration_payload

def configure_network_device_bgp_ipv4_unicast_vrf(network_device_name: str, bgp_vrf_configuration: dict, operation: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    get_network_device_vrf(network_device, bgp_vrf_configuration['vrf_name'])

    if operation == ConfigurationOperation.NEW:
        if bgp_vrf_configuration['vrf_name'] in network_device.baseline_configuration.bgp.ipv4_unicast_vrfs.keys():
            raise BgpIpv4UnicastVrfAlreadyExists(bgp_vrf_configuration['vrf_name'])
    elif operation == ConfigurationOperation.UPDATE:
        get_network_device_bgp_ipv4_unicast_vrf(network_device, bgp_vrf_configuration['vrf_name'])

    if check_dict_key(bgp_vrf_configuration, "neighbors") and bgp_vrf_configuration["neighbors"] is not None:
        for neighbor in bgp_vrf_configuration["neighbors"]:
            if check_dict_key(neighbor, "peer_template") and neighbor["peer_template"] is not None:
                if check_dict_key(neighbor["peer_template"], "session_name") and neighbor["peer_template"]["session_name"] is not None:
                    get_network_device_bgp_peer_session_template(network_device, neighbor["peer_template"]["session_name"])
                if check_dict_key(neighbor["peer_template"], "policy_name") and neighbor["peer_template"]["policy_name"] is not None:
                    get_network_device_bgp_peer_policy_template(network_device, neighbor["peer_template"]["policy_name"])
            if check_dict_key(neighbor, "update_source_interface_fullname") and neighbor["update_source_interface_fullname"] is not None:
                interface = get_network_device_interface(network_device, neighbor["update_source_interface_fullname"])
                neighbor["update_source_interface"] = base.Interface(name=interface.name, id=interface.id)
        bgp_vrf_configuration = remove_all_key_from_dict(bgp_vrf_configuration,"update_source_interface_fullname")

    bgp_ipv4_unicast_vrf_conf, netconf_configuration_payload = prepare_network_device_bgp_ipv4_unicast_vrf_configuration(network_device, bgp_vrf_configuration)

    if netconf_configuration_payload is not None and bgp_ipv4_unicast_vrf_conf is not None:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
        if resalt[network_device.name] is None:
            network_device.baseline_configuration.bgp.ipv4_unicast_vrfs[bgp_ipv4_unicast_vrf_conf.vrf_name] = bgp_ipv4_unicast_vrf_conf
            save_network_device(network_device_name)
            return
        else:
            DeveloperLogger().log_error(f"NORNIR NETCONF: configure_network_device_bgp_ipv4_unicast_vrf: {resalt}")
            raise IncorrectConfiguration

def delete_network_device_configuration_bgp_ipv4_unicast_vrf(network_device_name: str, vrf_name: str):
    network_device: NetworkDevice = get_network_device(network_device_name)
    bgp_ipv4_unicast_vrf = get_network_device_bgp_ipv4_unicast_vrf(network_device, vrf_name)
    netconf_configuration_payload = network_device.baseline_configuration.bgp.ipv4_unicast_vrfs[vrf_name].delete_config_netconf()
    resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}, netconf_payloads=[netconf_configuration_payload]).send_configs_netconf()
    if resalt[network_device.name] is None:
        del network_device.baseline_configuration.bgp.ipv4_unicast_vrfs[vrf_name]
        save_network_device(network_device_name)
        return
    else:
        DeveloperLogger().log_error(f"NORNIR NETCONF: delete_network_device_configuration_bgp_ipv4_unicast_vrf: {resalt}")
        raise IncorrectConfiguration


## Service - MPLS TE Tunnel
def save_service_mpls_te_tunnel(current_service_mpls_te_tunnel: dict):
    try:
        with open(MPLS_TE_TUNNEL_SERVICES_FILE_PATH, "w", encoding='utf-8') as f:
            yaml.safe_dump(current_service_mpls_te_tunnel, f, sort_keys=False, explicit_start=True)
    except Exception:
        DeveloperLogger().log_error(f"Failed to save mpls te tunnel: {traceback.format_exc()}")
        raise DeviceGroupSaveError

def get_service_mpls_te_tunnels() -> dict:
    try:
        with open(MPLS_TE_TUNNEL_SERVICES_FILE_PATH, "r", encoding='utf-8') as f:
            saved_services_mpls_te_tunnel = yaml.safe_load(f)
    except Exception:
        DeveloperLogger().log_error(f"Failed to read mpls te tunnels file: {traceback.format_exc()}")
        raise DeviceGroupReadError
    if not saved_services_mpls_te_tunnel:
        return {}
    return saved_services_mpls_te_tunnel

def get_service_mpls_te_tunnel(mpls_te_tunnel_service_name: str) -> dict:
    mpls_te_tunnel_services = get_service_mpls_te_tunnels()
    if not check_dict_key(mpls_te_tunnel_services, mpls_te_tunnel_service_name):
        raise ServiceMplsTeTunnelNotFound(mpls_te_tunnel_service_name)
    return mpls_te_tunnel_services[mpls_te_tunnel_service_name]

def create_service_mpls_te_tunnel(mpls_te_tunnel: dict):
    if mpls_te_tunnel['service_name'] in Project().service_mpls_te_tunnel.keys():
        raise ServiceMplsTeTunnelAlreadyExists(mpls_te_tunnel['service_name'])

    main_network_device_name = mpls_te_tunnel["source_device_name"]
    main_network_device: NetworkDevice = get_network_device(main_network_device_name)

    # Eg element of configuration list:
    # {
    #     "device_name": "device1",
    #
    #     "conf_type": "ip_explicit_path",
    #     "conf": ip_explicit_path_cisco_xe.ConfigIpExplicitPath(),
    #     "netconf_payload": "str"
    # }
    configuration: list[dict] = []
    if main_network_device.platform == CISCO_XE:
        main_network_device.get_free_tunnel_id()
        main_tunnel_id: int = main_network_device.get_free_tunnel_id()
        main_tunnel_ip_source_interface: str = MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME
        main_tunnel_description: str = mpls_te_tunnel["description"]
        main_tunnel_destination_ip_address: str | None = None
        if mpls_te_tunnel["destination"]["configuration_method"] == ServiceMplsTeTunnelDestinationConfigurationMethod.IPV4_ADDRESS:
            main_tunnel_destination_ip_address = mpls_te_tunnel["destination"]["configuration"]["ipv4_address"]
        elif mpls_te_tunnel["destination"]["configuration_method"] == ServiceMplsTeTunnelDestinationConfigurationMethod.NETWORK_DEVICE_NAME:
            destination_network_device: NetworkDevice = get_network_device(mpls_te_tunnel["destination"]["configuration"]["device_name"])
            destination_network_device_loopback_interface: base.InterfaceDetails = get_network_device_interface(destination_network_device, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME)
            main_tunnel_destination_ip_address = destination_network_device_loopback_interface.ipv4_address
        else:
            raise ServiceMplsTeTunnelDestinationConfigurationMethodError

        main_tunnel_bandwidth: int = 1000 * mpls_te_tunnel["bandwidth_Mb"]
        main_tunnel_autoroute_announce: bool = False
        if check_dict_key(mpls_te_tunnel, "autoroute_announce"):
            main_tunnel_autoroute_announce = mpls_te_tunnel["autoroute_announce"]

        main_tunnel_path_selection_metric: str | None = None
        if check_dict_key(mpls_te_tunnel, "path_selection_metric"):
            main_tunnel_path_selection_metric = mpls_te_tunnel["path_selection_metric"]

        main_tunnel_affinity: mpls_te_tunnel_cisco_xe.TunnelAffinity | None = None
        if check_dict_key(mpls_te_tunnel, "affinity"):
            affinity_value = mpls_te_tunnel["affinity"]["value"]
            affinity_mask = mpls_te_tunnel["affinity"]["mask"]
            main_tunnel_affinity = mpls_te_tunnel_cisco_xe.TunnelAffinity(value=affinity_value, mask=affinity_mask)

        main_tunnel_priority: mpls_te_tunnel_cisco_xe.TunnelPriority | None = None
        if check_dict_key(mpls_te_tunnel, "priority"):
            setup_priority = mpls_te_tunnel["priority"]["setup"]
            hold_priority = mpls_te_tunnel["priority"]["hold"]
            main_tunnel_priority = mpls_te_tunnel_cisco_xe.TunnelPriority(setup=setup_priority, hold=hold_priority)

        main_tunnel_path_option_paths: list[mpls_te_tunnel_cisco_xe.TunnelPathExplicit | mpls_te_tunnel_cisco_xe.TunnelPathDynamic] | None = []
        main_tunnel_path_option_protect_paths: list[mpls_te_tunnel_cisco_xe.ProtectPath] | None = []
        if check_dict_key(mpls_te_tunnel["path_options"], "paths") and not len(mpls_te_tunnel["path_options"]["paths"]) == 0:
            main_network_device_current_ipv4_explicit_paths = _get_ip_explicit_paths(main_network_device)
            path_id: int = 10
            for path in mpls_te_tunnel["path_options"]["paths"]:
                path_is_lockdown: bool = False
                if check_dict_key(path, "lockdown"):
                    path_is_lockdown = path["lockdown"]
                ipv4_explicit_path_name = path["ipv4_explicit_path"]["name"]
                if ipv4_explicit_path_name not in main_network_device_current_ipv4_explicit_paths.keys() and check_dict_key(
                        path["ipv4_explicit_path"], "type") and check_dict_key(path["ipv4_explicit_path"],
                                                                               "configuration_method") and check_dict_key(
                        path["ipv4_explicit_path"], "data"):
                    ip_explicit_path_conf, netconf_configuration_payload = prepare_ip_explicit_path_configuration(main_network_device, path["ipv4_explicit_path"], ConfigurationOperation.NEW)
                    configuration_element = {
                        "device_name": main_network_device_name,
                        "conf_type": "ip_explicit_path",
                        "conf": ip_explicit_path_conf,
                        "netconf_payload": netconf_configuration_payload
                    }
                    configuration.append(configuration_element)
                elif ipv4_explicit_path_name not in main_network_device_current_ipv4_explicit_paths.keys():
                    raise IpExplicitPathNotFound(ip_explicit_path_name=ipv4_explicit_path_name)

                main_tunnel_path_option_paths.append(mpls_te_tunnel_cisco_xe.TunnelPathExplicit(id=path_id, is_lockdown=path_is_lockdown, name=ipv4_explicit_path_name))

                if check_dict_key(path, "protection"):
                    protection_path = path["protection"]
                    protection_ipv4_explicit_path_name = protection_path["ipv4_explicit_path"]["name"]
                    if protection_ipv4_explicit_path_name not in main_network_device_current_ipv4_explicit_paths.keys() and check_dict_key(
                            protection_path["ipv4_explicit_path"], "type") and check_dict_key(
                            protection_path["ipv4_explicit_path"], "configuration_method") and check_dict_key(
                            protection_path["ipv4_explicit_path"], "data"):
                        ip_explicit_path_conf, netconf_configuration_payload = prepare_ip_explicit_path_configuration(main_network_device, protection_path["ipv4_explicit_path"], ConfigurationOperation.NEW)
                        configuration_element = {
                            "device_name": main_network_device_name,
                            "conf_type": "ip_explicit_path",
                            "conf": ip_explicit_path_conf,
                            "netconf_payload": netconf_configuration_payload
                        }
                        configuration.append(configuration_element)
                    elif protection_ipv4_explicit_path_name not in main_network_device_current_ipv4_explicit_paths.keys():
                        raise IpExplicitPathNotFound(ip_explicit_path_name=protection_ipv4_explicit_path_name)

                    main_tunnel_path_option_protect_paths.append(mpls_te_tunnel_cisco_xe.ProtectPath(id=path_id, name=protection_ipv4_explicit_path_name))
                path_id = path_id + 5

            if check_dict_key(mpls_te_tunnel["path_options"], "add_dynamic") and mpls_te_tunnel["path_options"]["add_dynamic"]:
                main_tunnel_path_option_paths.append(mpls_te_tunnel_cisco_xe.TunnelPathDynamic(id=1000))

        if not main_tunnel_path_option_paths:
            main_tunnel_path_option_protect_paths = None
        if not main_tunnel_path_option_protect_paths:
            main_tunnel_path_option_protect_paths = None
        main_tunnel_path_option: mpls_te_tunnel_cisco_xe.TunnelPathOption = mpls_te_tunnel_cisco_xe.TunnelPathOption(paths=main_tunnel_path_option_paths, protect_paths=main_tunnel_path_option_protect_paths)

        # NOT SUPPORTED ON CISCO IOS-XE
        main_tunnel_fast_reroute_enabled, main_tunnel_fast_reroute_node_protect = False, False
        # if check_dict_key(mpls_te_tunnel, "fast_reroute"):
        #     if check_dict_key(mpls_te_tunnel["fast_reroute"], "link_protection"):
        #         for link_protection in mpls_te_tunnel["fast_reroute"]["link_protection"]:
        #             network_device_name_to_configure_backup_tunnel = link_protection["link_to_node"]["device_name"]
        #             network_device_interface_fullname_to_configure_backup_tunnel = link_protection["link_to_node"]["interface_fullname"]
        #             network_device_interface_configuration_to_configure_backup_tunnel = get_network_device_configuration_interface_mpls_te(network_device_name_to_configure_backup_tunnel, network_device_interface_fullname_to_configure_backup_tunnel)
        #             if network_device_interface_configuration_to_configure_backup_tunnel["backup_path_tunnel_id"] is not None:
        #                 mpls_te_tunnel_fullname = "Tunnel" + str(network_device_interface_configuration_to_configure_backup_tunnel["backup_path_tunnel_id"])
        #                 config_mpls_te_tunnel = get_mpls_te_tunnel_configuration(network_device_name_to_configure_backup_tunnel, mpls_te_tunnel_fullname)
        #                 if int(config_mpls_te_tunnel["bandwidth"]) < link_protection["protected_tunnel_min_bandwidth_Mb"] * 1000:
        #                     raise FunctionalityNotImplemented(message="Cannot change existing link protection tunnel bandwidth.")
        #                 # Tunnel meets requirement no action needed
        #                 main_tunnel_fast_reroute_enabled = True
        #             else:
        #                 network_device_to_configure_backup_tunnel: NetworkDevice = get_network_device(network_device_name_to_configure_backup_tunnel)
        #
        #                 end_network_device_name = link_protection["end_device_name"]
        #                 end_network_device: NetworkDevice = get_network_device(end_network_device_name)
        #                 end_network_device_loopback_interface: base.InterfaceDetails = get_network_device_interface(end_network_device, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME)
        #                 backup_tunnel_destination_ip_address = end_network_device_loopback_interface.ipv4_address
        #
        #                 ip_explicit_path_data: list = []
        #                 for net_dev_name in link_protection["through_devices"]:
        #                     net_dev: NetworkDevice = get_network_device(net_dev_name)
        #                     net_dev_loopback_interface: base.InterfaceDetails = get_network_device_interface(net_dev, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME)
        #                     ip_explicit_path_data_element = {
        #                         "ipv4_address": net_dev_loopback_interface.ipv4_address,
        #                         "loose": False
        #                     }
        #                     ip_explicit_path_data.append(ip_explicit_path_data_element)
        #
        #                 ip_explicit_path_configuration: dict = {
        #                     "name": f"LP-{main_network_device_name}-Tunnel{main_tunnel_id}",
        #                     "type": IpExplicitPathConfigurationType.NEXT_IP_ADDRESS,
        #                     "configuration_method": IpExplicitPathConfigurationMethod.EXPLICIT,
        #                     "data": ip_explicit_path_data
        #                 }
        #
        #                 ip_explicit_path_conf, netconf_configuration_payload = prepare_ip_explicit_path_configuration(network_device_to_configure_backup_tunnel, ip_explicit_path_configuration, ConfigurationOperation.NEW)
        #                 configuration_element = {
        #                     "device_name": network_device_name_to_configure_backup_tunnel,
        #                     "conf_type": "ip_explicit_path",
        #                     "conf": ip_explicit_path_conf,
        #                     "netconf_payload": netconf_configuration_payload
        #                 }
        #                 configuration.append(configuration_element)
        #
        #                 backup_tunnel_path_explicit = mpls_te_tunnel_cisco_xe.TunnelPathExplicit(id=10, name=ip_explicit_path_conf.name)
        #                 backup_tunnel_path_option = mpls_te_tunnel_cisco_xe.TunnelPathOption(paths=[backup_tunnel_path_explicit])
        #
        #                 backup_tunnel_id: int = None
        #                 if network_device_name_to_configure_backup_tunnel == main_network_device_name:
        #                     backup_tunnel_id = main_network_device.get_free_tunnel_id()
        #                 else:
        #                     backup_tunnel_id = network_device_to_configure_backup_tunnel.get_free_tunnel_id()
        #
        #                 backup_tunnel_bandwidth = 1000 * link_protection["protected_tunnel_min_bandwidth_Mb"]
        #                 backup_tunnel_conf = mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel(tunnel_id=backup_tunnel_id, description=f"LP-{main_network_device_name}-Tunnel{main_tunnel_id}", ip_source_interface=MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME, destination_ip_address=backup_tunnel_destination_ip_address, bandwidth=backup_tunnel_bandwidth, path_option=backup_tunnel_path_option)
        #                 backup_tunnel_netconf_configuration_payload = backup_tunnel_conf.get_config_netconf()
        #
        #                 configuration_element = {
        #                     "device_name": network_device_name_to_configure_backup_tunnel,
        #                     "conf_type": "mpls_te_tunnel",
        #                     "conf": backup_tunnel_conf,
        #                     "netconf_payload": backup_tunnel_netconf_configuration_payload
        #                 }
        #                 configuration.append(configuration_element)
        #
        #                 network_device_interface_to_configure_backup_tunnel = get_network_device_interface(network_device_to_configure_backup_tunnel, network_device_interface_fullname_to_configure_backup_tunnel)
        #                 mpls_te_configuration = {
        #                     "enable": network_device_interface_configuration_to_configure_backup_tunnel["enable"],
        #                     "attribute_flags": network_device_interface_configuration_to_configure_backup_tunnel["attribute_flags"],
        #                     "administrative_weight": network_device_interface_configuration_to_configure_backup_tunnel["administrative_weight"],
        #                     "backup_path_tunnel_id": backup_tunnel_id
        #                 }
        #                 interface_mpls_te_conf, netconf_configuration_payload = prepare_network_device_interface_mpls_te_configuration(network_device_to_configure_backup_tunnel, network_device_interface_to_configure_backup_tunnel, mpls_te_configuration)
        #
        #                 configuration_element = {
        #                     "device_name": network_device_name_to_configure_backup_tunnel,
        #                     "conf_type": "interface_mpls_te",
        #                     "conf": interface_mpls_te_conf,
        #                     "netconf_payload": netconf_configuration_payload
        #                 }
        #                 configuration.append(configuration_element)
        #                 main_tunnel_fast_reroute_enabled = True
        #     if check_dict_key(mpls_te_tunnel["fast_reroute"], "node_protection"):
        #         for node_protection in mpls_te_tunnel["fast_reroute"]["node_protection"]:
        #             network_device_name_to_configure_backup_tunnel = node_protection["link_to_node"]["device_name"]
        #             network_device_interface_fullname_to_configure_backup_tunnel = node_protection["link_to_node"][
        #                 "interface_fullname"]
        #             network_device_interface_configuration_to_configure_backup_tunnel = get_network_device_configuration_interface_mpls_te(
        #                 network_device_name_to_configure_backup_tunnel,
        #                 network_device_interface_fullname_to_configure_backup_tunnel)
        #             if network_device_interface_configuration_to_configure_backup_tunnel[
        #                 "backup_path_tunnel_id"] is not None:
        #                 mpls_te_tunnel_fullname = "Tunnel" + str(
        #                     network_device_interface_configuration_to_configure_backup_tunnel["backup_path_tunnel_id"])
        #                 config_mpls_te_tunnel = get_mpls_te_tunnel_configuration(
        #                     network_device_name_to_configure_backup_tunnel, mpls_te_tunnel_fullname)
        #                 if int(config_mpls_te_tunnel["bandwidth"]) < node_protection[
        #                     "protected_tunnel_min_bandwidth_Mb"] * 1000:
        #                     raise FunctionalityNotImplemented(
        #                         message="Cannot change existing link protection tunnel bandwidth.")
        #                 # Tunnel meets requirement no action needed
        #                 main_tunnel_fast_reroute_node_protect = True
        #             else:
        #                 network_device_to_configure_backup_tunnel: NetworkDevice = get_network_device(
        #                     network_device_name_to_configure_backup_tunnel)
        #
        #                 end_network_device_name = node_protection["end_device_name"]
        #                 end_network_device: NetworkDevice = get_network_device(end_network_device_name)
        #                 end_network_device_loopback_interface: base.InterfaceDetails = get_network_device_interface(
        #                     end_network_device, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME)
        #                 backup_tunnel_destination_ip_address = end_network_device_loopback_interface.ipv4_address
        #
        #                 ip_explicit_path_data: list = []
        #                 for net_dev_name in node_protection["through_devices"]:
        #                     net_dev: NetworkDevice = get_network_device(net_dev_name)
        #                     net_dev_loopback_interface: base.InterfaceDetails = get_network_device_interface(net_dev, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME)
        #                     ip_explicit_path_data_element = {
        #                         "ipv4_address": net_dev_loopback_interface.ipv4_address,
        #                         "loose": False
        #                     }
        #                     ip_explicit_path_data.append(ip_explicit_path_data_element)
        #
        #                 ip_explicit_path_configuration: dict = {
        #                     "name": f"NP-{main_network_device_name}-Tunnel{main_tunnel_id}",
        #                     "type": IpExplicitPathConfigurationType.NEXT_IP_ADDRESS,
        #                     "configuration_method": IpExplicitPathConfigurationMethod.EXPLICIT,
        #                     "data": ip_explicit_path_data
        #                 }
        #
        #                 ip_explicit_path_conf, netconf_configuration_payload = prepare_ip_explicit_path_configuration(
        #                     network_device_to_configure_backup_tunnel, ip_explicit_path_configuration,
        #                     ConfigurationOperation.NEW)
        #                 configuration_element = {
        #                     "device_name": network_device_name_to_configure_backup_tunnel,
        #                     "conf_type": "ip_explicit_path",
        #                     "conf": ip_explicit_path_conf,
        #                     "netconf_payload": netconf_configuration_payload
        #                 }
        #                 configuration.append(configuration_element)
        #
        #                 backup_tunnel_path_explicit = mpls_te_tunnel_cisco_xe.TunnelPathExplicit(id=10, name=ip_explicit_path_conf.name)
        #                 backup_tunnel_path_option = mpls_te_tunnel_cisco_xe.TunnelPathOption(
        #                     paths=[backup_tunnel_path_explicit])
        #
        #                 backup_tunnel_id: int = None
        #                 if network_device_name_to_configure_backup_tunnel == main_network_device_name:
        #                     backup_tunnel_id = main_network_device.get_free_tunnel_id()
        #                 else:
        #                     backup_tunnel_id = network_device_to_configure_backup_tunnel.get_free_tunnel_id()
        #
        #                 backup_tunnel_bandwidth = 1000 * node_protection["protected_tunnel_min_bandwidth_Mb"]
        #                 backup_tunnel_conf = mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel(tunnel_id=backup_tunnel_id,
        #                                                                                 description=f"NP-{main_network_device_name}-Tunnel{main_tunnel_id}",
        #                                                                                 ip_source_interface=MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME,
        #                                                                                 destination_ip_address=backup_tunnel_destination_ip_address,
        #                                                                                 bandwidth=backup_tunnel_bandwidth,
        #                                                                                 path_option=backup_tunnel_path_option)
        #                 backup_tunnel_netconf_configuration_payload = backup_tunnel_conf.get_config_netconf()
        #
        #                 configuration_element = {
        #                     "device_name": network_device_name_to_configure_backup_tunnel,
        #                     "conf_type": "mpls_te_tunnel",
        #                     "conf": backup_tunnel_conf,
        #                     "netconf_payload": backup_tunnel_netconf_configuration_payload
        #                 }
        #                 configuration.append(configuration_element)
        #
        #                 network_device_interface_to_configure_backup_tunnel = get_network_device_interface(
        #                     network_device_to_configure_backup_tunnel,
        #                     network_device_interface_fullname_to_configure_backup_tunnel)
        #                 mpls_te_configuration = {
        #                     "enable": network_device_interface_configuration_to_configure_backup_tunnel["enable"],
        #                     "attribute_flags": network_device_interface_configuration_to_configure_backup_tunnel[
        #                         "attribute_flags"],
        #                     "administrative_weight": network_device_interface_configuration_to_configure_backup_tunnel[
        #                         "administrative_weight"],
        #                     "backup_path_tunnel_id": backup_tunnel_id
        #                 }
        #                 interface_mpls_te_conf, netconf_configuration_payload = prepare_network_device_interface_mpls_te_configuration(
        #                     network_device_to_configure_backup_tunnel,
        #                     network_device_interface_to_configure_backup_tunnel, mpls_te_configuration)
        #
        #                 configuration_element = {
        #                     "device_name": network_device_name_to_configure_backup_tunnel,
        #                     "conf_type": "interface_mpls_te",
        #                     "conf": interface_mpls_te_conf,
        #                     "netconf_payload": netconf_configuration_payload
        #                 }
        #                 configuration.append(configuration_element)
        #                 main_tunnel_fast_reroute_node_protect = True

        main_tunnel_fast_reroute: mpls_te_tunnel_cisco_xe.FastReroute = mpls_te_tunnel_cisco_xe.FastReroute(enabled=main_tunnel_fast_reroute_enabled, node_protect=main_tunnel_fast_reroute_node_protect)

        main_tunnel_conf = mpls_te_tunnel_cisco_xe.ConfigMplsTeTunnel(tunnel_id=main_tunnel_id, description=main_tunnel_description, ip_source_interface=main_tunnel_ip_source_interface, destination_ip_address=main_tunnel_destination_ip_address, bandwidth=main_tunnel_bandwidth, affinity=main_tunnel_affinity, autoroute_announce=main_tunnel_autoroute_announce, fast_reroute=main_tunnel_fast_reroute, path_option=main_tunnel_path_option, priority=main_tunnel_priority, path_selection_metric=main_tunnel_path_selection_metric, record_route_enable=True)
        main_tunnel_netconf_payload = main_tunnel_conf.get_config_netconf()

        configuration_element = {
            "device_name": main_network_device_name,
            "conf_type": "mpls_te_tunnel",
            "conf": main_tunnel_conf,
            "netconf_payload": main_tunnel_netconf_payload
        }
        configuration.append(configuration_element)

        configs_for_nornir_per_host_name = {}
        for conf_element in configuration:
            if not check_dict_key(configs_for_nornir_per_host_name, conf_element["device_name"]):
                configs_for_nornir_per_host_name[conf_element["device_name"]] = [conf_element["netconf_payload"]]
            else:
                configs_for_nornir_per_host_name[conf_element["device_name"]].append(conf_element["netconf_payload"])

        success = NornirEngine().send_configs_wide_transaction_netconf(configs_for_nornir_per_host_name)

        if success:
            net_dev_name_unique = set()
            for conf_element in configuration:
                net_dev_name = conf_element["device_name"]
                net_dev: NetworkDevice = get_network_device(net_dev_name)
                if conf_element["conf_type"] == "ip_explicit_path":
                    conf = conf_element["conf"]
                    net_dev.baseline_configuration.ipv4_explicit_paths[conf.name] = conf
                elif conf_element["conf_type"] == "interface_mpls_te":
                    conf = conf_element["conf"]
                    net_dev.baseline_configuration.mpls_te_interfaces[conf.interface.full_name] = conf
                elif conf_element["conf_type"] == "mpls_te_tunnel":
                    conf = conf_element["conf"]
                    net_dev.baseline_configuration.mpls_te_tunnels[f"Tunnel{conf.tunnel_id}"] = conf
                net_dev_name_unique.add(net_dev_name)
            for net_dev_name in net_dev_name_unique:
                save_network_device(net_dev_name)

            mpls_te_tunnel['tunnel_fullname'] = f"Tunnel{main_tunnel_id}"
            Project().service_mpls_te_tunnel[mpls_te_tunnel['service_name']] = mpls_te_tunnel
            save_service_mpls_te_tunnel(Project().service_mpls_te_tunnel)
            return mpls_te_tunnel

def get_service_mpls_te_tunnel_path(mpls_te_tunnel_service_name: str) -> list[dict]:
    service_mpls_te_tunnel = get_service_mpls_te_tunnel(mpls_te_tunnel_service_name)
    network_device_name = service_mpls_te_tunnel['source_device_name']
    network_device = get_network_device(network_device_name)
    mpls_te_tunnel = get_mpls_te_tunnel(network_device, service_mpls_te_tunnel['tunnel_fullname'])
    return get_mpls_te_tunnel_path(network_device, service_mpls_te_tunnel['tunnel_fullname'])


## Service - MPLS L3 VPN
def save_service_mpls_l3_vpn(current_service_mpls_l3_vpn: dict):
    try:
        with open(MPLS_L3_VPN_SERVICES_FILE_PATH, "w", encoding='utf-8') as f:
            yaml.safe_dump(current_service_mpls_l3_vpn, f, sort_keys=False, explicit_start=True)
    except Exception:
        DeveloperLogger().log_error(f"Failed to save mpls l3 vpn: {traceback.format_exc()}")
        raise DeviceGroupSaveError

def get_service_mpls_l3_vpns() -> dict:
    try:
        with open(MPLS_L3_VPN_SERVICES_FILE_PATH, "r", encoding='utf-8') as f:
            saved_services_mpls_l3_vpn = yaml.safe_load(f)
    except Exception:
        DeveloperLogger().log_error(f"Failed to read mpls l3 vpns file: {traceback.format_exc()}")
        raise DeviceGroupReadError
    if not saved_services_mpls_l3_vpn:
        return {}
    return saved_services_mpls_l3_vpn

def get_service_mpls_l3_vpn(mpls_l3_vpn_service_name: str) -> dict:
    mpls_l3_vpn_services = get_service_mpls_l3_vpns()
    if not check_dict_key(mpls_l3_vpn_services, mpls_l3_vpn_service_name):
        raise ServiceMplsL3VpnNotFound(mpls_l3_vpn_service_name)
    return mpls_l3_vpn_services[mpls_l3_vpn_service_name]

def create_service_mpls_l3_vpn(mpls_l3_vpn: dict):
    if mpls_l3_vpn['service_name'] in Project().service_mpls_l3_vpn.keys():
        raise ServiceMplsL3VpnAlreadyExists(mpls_l3_vpn['service_name'])

    vrf_name = mpls_l3_vpn["vrf_name"]
    if vrf_name in Project().vrf_name_in_use:
        raise VrfAlreadyExists(vrf_name)

    client_rd: int = Project().get_free_client_rd()
    mpls_l3_vpn["client_rd"] = client_rd

    as_override: bool = False
    asns = []
    pes = mpls_l3_vpn["pes"]
    for pe in pes:
        for ce_neighbor in pe["ce_neighbors"]:
            if ce_neighbor["bgp_asn"] in asns:
                as_override = True
                break
            asns.append(ce_neighbor["bgp_asn"])
        if as_override:
            break

    # Eg element of configuration dict:
    # {
    #     "PE3": ["1.1.1.1:300", "2.2.2.2:300"],
    # }
    route_targets_import = {}
    for allowed_communication in mpls_l3_vpn["allowed_communications"]:
        rt = []
        for pe_device_name in allowed_communication["allowed_routes_from_pe"]:
            net_dev = get_network_device(pe_device_name)
            ipv4_address = get_network_device_interface(net_dev, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME).ipv4_address
            rt.append(f"{ipv4_address}:{client_rd}")
        route_targets_import[allowed_communication["pe_device_name"]] = rt

    # Eg element of configuration list:
    # {
    #     "device_name": "device1",
    #     "conf_type": "ip_explicit_path",
    #     "conf": ip_explicit_path_cisco_xe.ConfigIpExplicitPath(),
    #     "netconf_payload": "str"
    # }
    configuration: list[dict] = []
    for pe in pes:
        network_device = get_network_device(pe["pe_device_name"])
        network_device_bgp_asn = network_device.baseline_configuration.bgp.asn
        bgp_ipv4_unicast_vrf_neighbors = []
        soo = None
        if len(pe["ce_neighbors"]) > 1:
            soo = f"{network_device_bgp_asn}:{client_rd}"
        for ce_neighbor in pe["ce_neighbors"]:
            vrf_interface = vrf_interface_cisco_xe.ConfigInterfaceVrf(interface=base.Interface(name=ce_neighbor["interface_to_ce_name"], id=ce_neighbor["interface_to_ce_id"]), vrf_name=vrf_name, ipv4_address=ce_neighbor["interface_to_ce_ipv4_address"], ipv4_mask=ce_neighbor["interface_to_ce_ipv4_mask"])
            configuration.append({
                "device_name": network_device.name,
                "conf_type": "vrf_interface",
                "conf": vrf_interface,
                "netconf_payload": vrf_interface.get_config_netconf()
            })

            max_prefixes_from_bgp_neighbor: int | None = None
            keepalive_interval = None
            holdtime = None
            minimum_neighbor_holdtime = None
            if check_dict_key(ce_neighbor, "special_requirements"):
                if check_dict_key(ce_neighbor["special_requirements"], "max_prefixes_from_bgp_neighbor"):
                    max_prefixes_from_bgp_neighbor = int(ce_neighbor["special_requirements"]["max_prefixes_from_bgp_neighbor"])
                if check_dict_key(ce_neighbor["special_requirements"], "bgp_neighbor_timers") and check_dict_key(
                        ce_neighbor["special_requirements"]["bgp_neighbor_timers"],
                        "keepalive_interval") and check_dict_key(
                        ce_neighbor["special_requirements"]["bgp_neighbor_timers"], "holdtime"):
                    keepalive_interval = ce_neighbor["special_requirements"]["bgp_neighbor_timers"]["keepalive_interval"]
                    holdtime = ce_neighbor["special_requirements"]["bgp_neighbor_timers"]["holdtime"]
                    if check_dict_key(ce_neighbor["special_requirements"]["bgp_neighbor_timers"],
                                      "minimum_neighbor_holdtime"):
                        minimum_neighbor_holdtime = ce_neighbor["special_requirements"]["bgp_neighbor_timers"]["minimum_neighbor_holdtime"]
            if network_device.platform == CISCO_XE:
                timers = None
                if keepalive_interval is not None:
                    timers = bgp_cisco_xe.BgpNeighborTimers(keepalive_interval=keepalive_interval, holdtime=holdtime, minimum_neighbor_holdtime=minimum_neighbor_holdtime)
                peer_session_template = None
                peer_session_template_name = None
                if vrf_name not in network_device.baseline_configuration.bgp.peer_session_templates.keys():
                    peer_session_template = bgp_cisco_xe.ConfigBgpTemplatePeerSession(asn=network_device_bgp_asn, name=vrf_name, remote_asn=ce_neighbor['bgp_asn'], timers=timers)
                    peer_session_template_name = vrf_name
                    configuration.append({
                        "device_name": network_device.name,
                        "conf_type": "peer_session_template",
                        "conf": peer_session_template,
                        "netconf_payload": peer_session_template.get_config_netconf()
                    })
                peer_policy_template = None
                peer_policy_template_name = None
                if vrf_name not in network_device.baseline_configuration.bgp.peer_session_templates.keys():
                    peer_policy_template = bgp_cisco_xe.ConfigBgpTemplatePeerPolicy(asn=network_device_bgp_asn, name=vrf_name, as_override=as_override, maximum_prefix=max_prefixes_from_bgp_neighbor, soo=soo)
                    peer_policy_template_name = vrf_name
                    configuration.append({
                        "device_name": network_device.name,
                        "conf_type": "peer_policy_template",
                        "conf": peer_policy_template,
                        "netconf_payload": peer_policy_template.get_config_netconf()
                    })

                if peer_session_template is not None and peer_policy_template is not None:
                    bgp_ipv4_unicast_vrf_neighbors.append(bgp_cisco_xe.BgpNeighbor(ipv4_address=ce_neighbor['ipv4_address'], peer_template=bgp_cisco_xe.BgpNeighborPeerTemplate(session_name=peer_session_template_name, policy_name=peer_policy_template_name), remote_asn=ce_neighbor['bgp_asn']))
                elif peer_policy_template is not None:
                    bgp_ipv4_unicast_vrf_neighbors.append(bgp_cisco_xe.BgpNeighbor(ipv4_address=ce_neighbor['ipv4_address'], peer_template=bgp_cisco_xe.BgpNeighborPeerTemplate(policy_name=peer_policy_template_name), remote_asn=ce_neighbor['bgp_asn'], timers=timers))
                elif peer_session_template is not None:
                    bgp_ipv4_unicast_vrf_neighbors.append(bgp_cisco_xe.BgpNeighbor(ipv4_address=ce_neighbor['ipv4_address'], peer_template=bgp_cisco_xe.BgpNeighborPeerTemplate(session_name=peer_session_template_name), as_override=as_override, maximum_prefix=max_prefixes_from_bgp_neighbor, soo=soo, remote_asn=ce_neighbor['bgp_asn']))
                else:
                    bgp_ipv4_unicast_vrf_neighbors.append(bgp_cisco_xe.BgpNeighbor(ipv4_address=ce_neighbor['ipv4_address'], remote_asn=ce_neighbor['bgp_asn'], timers=timers, as_override=as_override, maximum_prefix=max_prefixes_from_bgp_neighbor, soo=soo))

        max_vrf_routes = None
        if check_dict_key(pe, "max_vrf_routes"):
            max_vrf_routes = vrf_cisco_xe.VrfMaximumRoutes(max_routes=pe["max_vrf_routes"], warning_threshold=80)


        if network_device.platform == CISCO_XE:
            ipv4_address = get_network_device_interface(network_device, MPLS_TE_ROUTER_ID_INTERFACE_FULLNAME).ipv4_address
            import_tr = None
            if check_dict_key(route_targets_import, network_device.name):
                import_tr =route_targets_import[network_device.name]
            vrf = vrf_cisco_xe.ConfigVrf(name=vrf_name, rd=f"{ipv4_address}:{client_rd}", route_target=vrf_cisco_xe.VrfRouteTarget(export=[f"{ipv4_address}:{client_rd}"], import_=import_tr), maximum_routes=max_vrf_routes)
            configuration.insert(0, {
                "device_name": network_device.name,
                "conf_type": "vrf",
                "conf": vrf,
                "netconf_payload": vrf.get_config_netconf()
            })

            bgp_ipv4_uni_vrf = bgp_cisco_xe.ConfigBgpIpv4UnicastVrf(asn=network_device_bgp_asn, vrf_name=vrf_name, neighbors=bgp_ipv4_unicast_vrf_neighbors)
            configuration.append({
                "device_name": network_device.name,
                "conf_type": "ipv4_unicast_vrf",
                "conf": bgp_ipv4_uni_vrf,
                "netconf_payload": bgp_ipv4_uni_vrf.get_config_netconf()
            })

    configs_for_nornir_per_host_name = {}
    for conf_element in configuration:
        if not check_dict_key(configs_for_nornir_per_host_name, conf_element["device_name"]):
            configs_for_nornir_per_host_name[conf_element["device_name"]] = [conf_element["netconf_payload"]]
        else:
            configs_for_nornir_per_host_name[conf_element["device_name"]].append(conf_element["netconf_payload"])

    success = NornirEngine().send_configs_wide_transaction_netconf(configs_for_nornir_per_host_name)

    if success:
        net_dev_name_unique = set()
        for conf_element in configuration:
            net_dev_name = conf_element["device_name"]
            net_dev: NetworkDevice = get_network_device(net_dev_name)
            if conf_element["conf_type"] == "vrf_interface":
                conf = conf_element["conf"]
                net_dev.baseline_configuration.vrf_interfaces[conf.interface.full_name] = conf
            elif conf_element["conf_type"] == "peer_session_template":
                conf = conf_element["conf"]
                net_dev.baseline_configuration.bgp.peer_session_templates[conf.name] = conf
            elif conf_element["conf_type"] == "peer_policy_template":
                conf = conf_element["conf"]
                net_dev.baseline_configuration.bgp.peer_policy_templates[conf.name] = conf
            elif conf_element["conf_type"] == "vrf":
                conf = conf_element["conf"]
                net_dev.baseline_configuration.vrfs[conf.name] = conf
            elif conf_element["conf_type"] == "ipv4_unicast_vrf":
                conf = conf_element["conf"]
                net_dev.baseline_configuration.bgp.ipv4_unicast_vrfs[conf.vrf_name] = conf
            net_dev_name_unique.add(net_dev_name)
        for net_dev_name in net_dev_name_unique:
            save_network_device(net_dev_name)

        Project().service_mpls_l3_vpn[mpls_l3_vpn['service_name']] = mpls_l3_vpn
        save_service_mpls_l3_vpn(Project().service_mpls_l3_vpn)
        Project().client_rd_in_use.add(client_rd)
        return mpls_l3_vpn

def get_ip_route_vrf(network_device: NetworkDevice, vrf_name: str) -> list:
    routes = []
    if network_device.platform == CISCO_XE:
        resalt = NornirEngine(filter_parameter={"hostname": network_device.hostname}).get_show_command_output(
            f"show ip route vrf {vrf_name}")
        if resalt[network_device.name] is None:
            return []
        resalt = resalt[network_device.name]

        route_entry_pattern = re.compile(
            r"^\s*(?:[A-Za-z\s]{1,5})\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)"
            r"(?:"
            r"\s*\[.*?\]\s+via\s+([\d.]+),\s+[\d\w]+"  # Next Hop IP
            r"|" # OR
            r"\s+is\s+directly\s+connected,\s+([A-Za-z0-9/.-]+)" # Interface Name
            r")"
            r".*?$",
            re.MULTILINE
        )

        matches = route_entry_pattern.findall(resalt)

        for match in matches:
            prefix = match[0].strip()
            next_hop = match[1].strip() if match[1] else None
            interface = match[2].strip() if match[2] else None
            routes.append({
                "prefix": prefix,
                "next_hop": next_hop,
                "interface": interface
            })

    return routes

def get_service_mpls_l3_vpn_routes(mpls_l3_vpn_service_name: str) -> list[dict]:
    service_mpls_l3_vpn = get_service_mpls_l3_vpn(mpls_l3_vpn_service_name)
    vrf_name = service_mpls_l3_vpn['vrf_name']
    pes = service_mpls_l3_vpn['pes']

    routes_on_pes = []
    for pe in pes:
        network_device_name = pe['pe_device_name']
        network_device = get_network_device(network_device_name)
        routes = get_ip_route_vrf(network_device, vrf_name)
        _ = {
            'pe_device_name': network_device_name,
            'routes': routes
        }
        routes_on_pes.append(_)

    return routes_on_pes


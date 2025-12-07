from fastapi import APIRouter, HTTPException, Depends
from fastapi.concurrency import run_in_threadpool
from starlette import status
from app.api.auth.models import AccessTokenPrivilegeLevel3, AccessTokenPrivilegeLevel2, AccessTokenPrivilegeLevel1
from app.api.device_operation.models import ConfigMplsTeInterfaceAPIResponse, ConfigMplsTeInterfaceAPI, \
    ConfigIpExplicitPathAPI, ConfigIpExplicitPathAPIResponse, IpExplicitPathsAPIResponse, ConfigVrfInterfaceAPI, \
    ConfigVrfInterfaceAPIResponse, ConfigVrfAPI, ConfigVrfAPIResponse, VrfsAPIResponse, \
    BgpPeerSessionTemplatesAPIResponse, BgpPeerPolicyTemplatesAPIResponse, ConfigBgpPeerSessionTemplateAPI, \
    ConfigBgpPeerPolicyTemplateAPI, ConfigBgpPeerSessionTemplateAPIResponse, ConfigBgpPeerPolicyTemplateAPIResponse, \
    BgpIpv4UnicastNeighborsAPIResponse, \
    ConfigBgpIpv4UnicastNeighborAPI, ConfigBgpIpv4UnicastNeighborAPIResponse, BgpVpnv4UnicastNeighborsAPIResponse, \
    ConfigBgpVpnv4UnicastNeighborAPI, \
    ConfigBgpVpnv4UnicastNeighborAPIResponse, ConfigBgpIpv4UnicastVrfAPI, ConfigBgpIpv4UnicastVrfAPIResponse, \
    BgpIpv4UnicastVrfsAPIResponse, MplsTeTunnelsAPIResponse, ConfigMplsTeTunnelAPIResponse
from app.api.project.models import CheckProjectInit
from app.heplers.constants import ConfigurationOperation
from app.heplers.exepctions import DeviceSaveError, NetworkDeviceInterfaceNotFound, \
    NetworkDeviceNotFound, IpExplicitPathAlreadyExists, IpExplicitPathNotFound, VrfNotFound, VrfAlreadyExists, \
    BgpPeerSessionTemplateNotFound, BgpPeerSessionTemplateAlreadyExists, BgpPeerPolicyTemplateAlreadyExists, \
    BgpPeerPolicyTemplateNotFound, BgpIPv4UnicastNeighborNotFound, BgpIPv4UnicastNeighborAlreadyExists, \
    BgpVpnv4UnicastNeighborNotFound, \
    BgpVpnv4UnicastNeighborAlreadyExists, BgpIpv4UnicastVrfNotFound, BgpIpv4UnicastVrfAlreadyExists, \
    BgpPeerSessionTemplateInUse, BgpPeerPolicyTemplateInUse, MplsTeTunnelNotFound, IncorrectConfiguration
from app.heplers.functions import format_value_error_msg
from app.logs.logger import UserActionLogger
import app.controller.controller as controller

project_device_operation_router = APIRouter()
access_token_privilege_level_3_dependency = AccessTokenPrivilegeLevel3()
access_token_privilege_level_2_dependency = AccessTokenPrivilegeLevel2()
access_token_privilege_level_1_dependency = AccessTokenPrivilegeLevel1()

@project_device_operation_router.get("/device/{device_name}/conf_drift")
async def get_device_configuration_drift(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.check_network_device_configuration_drift, device_name)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_router.get("/device/{device_name}/running_configuration")
async def get_device_running_configuration(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.get_network_device_running_configuration, device_name)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_router.get("/device/{device_name}/baseline_configuration")
async def get_device_baseline_configuration(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_router.put("/device/{device_name}/save_running_configuration_as_baseline_configuration", status_code=status.HTTP_204_NO_CONTENT)
async def save_running_configuration_as_baseline_configuration(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.save_network_device_running_configuration, device_name)
        UserActionLogger().log_info(f"Device: {device_name} forced new baseline configuration by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_router.put("/device/{device_name}/load_baseline_configuration", status_code=status.HTTP_204_NO_CONTENT)
async def load_baseline_configuration(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.push_network_device_baseline_configuration, device_name)
        UserActionLogger().log_info(f"Device: {device_name} loaded baseline configuration by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

## Interface MPLS TE Configuration
project_device_operation_interface_mpls_te_router = APIRouter()
@project_device_operation_interface_mpls_te_router.get("/device/{device_name}/interface/{interface_name}/mpls_te", response_model=ConfigMplsTeInterfaceAPIResponse)
async def get_device_interface_mpls_te_configuration(device_name: str, interface_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_configuration_interface_mpls_te,device_name, interface_name)
        return ConfigMplsTeInterfaceAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")

@project_device_operation_interface_mpls_te_router.put("/device/{device_name}/interface/{interface_name}/mpls_te", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_interface_mpls_te_configuration(mpls_te: ConfigMplsTeInterfaceAPI, device_name: str, interface_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_interface_mpls_te, device_name, interface_name, mpls_te.config)
        UserActionLogger().log_info(f"Configuration of MPLS TE was changed on device {device_name} interface {interface_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_interface_mpls_te_router.delete("/device/{device_name}/interface/{interface_name}/mpls_te", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_interface_mpls_te_configuration(device_name: str, interface_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_interface_mpls_te, device_name, interface_name)
        UserActionLogger().log_info(f"Configuration of MPLS TE was deleted on device {device_name} interface {interface_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

##  MPLS TE Global Configuration
project_device_operation_mpls_te_router = APIRouter()
@project_device_operation_mpls_te_router.get("/device/{device_name}/mpls_te")
async def get_device_mpls_te_configuration(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.is_network_device_mpls_te_enabled, device_name)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_mpls_te_router.post("/device/{device_name}/mpls_te", status_code=status.HTTP_204_NO_CONTENT)
async def configure_device_mpls_te(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_mpls_te, device_name)
        UserActionLogger().log_info(f"MPLS TE was configure on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_mpls_te_router.delete("/device/{device_name}/mpls_te", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_mpls_te_configuration(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_mpls_te, device_name)
        UserActionLogger().log_info(f"Configuration of MPLS TE was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

## IP Explicit List
project_device_operation_explicit_path_router = APIRouter()
@project_device_operation_explicit_path_router.get("/device/{device_name}/ip_explicit_path", response_model=IpExplicitPathsAPIResponse)
async def get_device_ip_explicit_paths(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return IpExplicitPathsAPIResponse(ipv4_explicit_paths=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_explicit_path_router.post("/device/{device_name}/ip_explicit_path", status_code=status.HTTP_204_NO_CONTENT)
async def configure_device_ip_explicit_path(ip_explicit_path: ConfigIpExplicitPathAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_ip_explicit_path, device_name, ip_explicit_path.config, ConfigurationOperation.NEW)
        UserActionLogger().log_info(f"IP explicit path {ip_explicit_path.config['name']} configured on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except IpExplicitPathAlreadyExists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ip explicit path already exists")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_explicit_path_router.put("/device/{device_name}/ip_explicit_path", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_ip_explicit_path_configuration(ip_explicit_path: ConfigIpExplicitPathAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_ip_explicit_path, device_name, ip_explicit_path.config, ConfigurationOperation.UPDATE)
        UserActionLogger().log_info(f"IP explicit path {ip_explicit_path.config['name']} updated on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except IpExplicitPathNotFound:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ip explicit path not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_explicit_path_router.get("/device/{device_name}/ip_explicit_path/{ip_explicit_path_name}", response_model=ConfigIpExplicitPathAPIResponse)
async def get_device_ip_explicit_path_configuration(device_name: str, ip_explicit_path_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_ip_explicit_path_configuration, device_name, ip_explicit_path_name)
        return ConfigIpExplicitPathAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except IpExplicitPathNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"IP Explict path {ip_explicit_path_name } not found on device {device_name}")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_explicit_path_router.delete("/device/{device_name}/ip_explicit_path/{ip_explicit_path_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_ip_explicit_path_configuration(device_name: str, ip_explicit_path_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_ip_explicit_path, device_name, ip_explicit_path_name)
        UserActionLogger().log_info(f"Configuration of IP Explicit Path {ip_explicit_path_name} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except IpExplicitPathNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"IP Explict path {ip_explicit_path_name } not found on device {device_name}")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

## MPLS TE Tunnel
project_device_operation_mpls_te_tunnel_router = APIRouter()
@project_device_operation_mpls_te_tunnel_router.get("/device/{device_name}/mpls_te/tunnel", response_model=MplsTeTunnelsAPIResponse)
async def get_device_mpls_te_tunnels(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return MplsTeTunnelsAPIResponse(mpls_te_tunnels=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_mpls_te_tunnel_router.get("/device/{device_name}/mpls_te/tunnel/{tunnel_interface_fullname}", response_model=ConfigMplsTeTunnelAPIResponse)
async def get_device_mpls_te_tunnel_configuration(device_name: str, tunnel_interface_fullname: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_mpls_te_tunnel_configuration, device_name, tunnel_interface_fullname)
        return ConfigMplsTeTunnelAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except MplsTeTunnelNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Mpls Te Tunnel {e.mpls_te_tunnel_fullname} not found")

@project_device_operation_mpls_te_tunnel_router.get("/device/{device_name}/mpls_te/tunnel/{tunnel_interface_fullname}/path")
async def get_device_mpls_te_tunnel_path(device_name: str, tunnel_interface_fullname: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        tunnel_path = await run_in_threadpool(controller.get_network_device_mpls_te_tunnel_path, device_name, tunnel_interface_fullname)
        return tunnel_path
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except MplsTeTunnelNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Mpls Te Tunnel {e.mpls_te_tunnel_fullname} not found")


@project_device_operation_mpls_te_tunnel_router.delete("/device/{device_name}/mpls_te/tunnel/{tunnel_interface_fullname}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_mpls_te_tunnel_configuration(device_name: str, tunnel_interface_fullname: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_mpls_te_tunnel, device_name, tunnel_interface_fullname)
        UserActionLogger().log_info(f"Configuration of MPLS TE Tunnel {tunnel_interface_fullname} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except MplsTeTunnelNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Mpls Te Tunnel {e.mpls_te_tunnel_fullname} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


## VRF Configuration
project_device_operation_vrf_router = APIRouter()
@project_device_operation_vrf_router.get("/device/{device_name}/vrf", response_model=VrfsAPIResponse)
async def get_device_vrfs(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return VrfsAPIResponse(vrfs=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_vrf_router.post("/device/{device_name}/vrf", status_code=status.HTTP_204_NO_CONTENT)
async def create_device_vrf_configuration(vrf: ConfigVrfAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_vrf, device_name, vrf.config, ConfigurationOperation.NEW)
        UserActionLogger().log_info(f"Configuration of VRF {vrf.config['name']} was created on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except VrfAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"VRF {e.vrf_name} already exists")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except IncorrectConfiguration:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"RD {vrf.config["rd"]} already exists")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_vrf_router.put("/device/{device_name}/vrf", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_vrf_configuration(vrf: ConfigVrfAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_vrf, device_name, vrf.config, ConfigurationOperation.UPDATE)
        UserActionLogger().log_info(f"Configuration of VRF {vrf.config['name']} was changed on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except VrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"VRF {e.vrf_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except IncorrectConfiguration:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"RD {vrf.config["rd"]} already exists")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_vrf_router.get("/device/{device_name}/vrf/{vrf_name}", response_model=ConfigVrfAPIResponse)
async def get_device_vrf_configuration(device_name: str, vrf_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_vrf_configuration, device_name, vrf_name)
        return ConfigVrfAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except VrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"VRF {e.vrf_name} not found")

@project_device_operation_vrf_router.delete("/device/{device_name}/vrf/{vrf_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_vrf_configuration(device_name: str, vrf_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_vrf, device_name, vrf_name)
        UserActionLogger().log_info(f"Configuration of VRF {vrf_name} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except VrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"VRF {e.vrf_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


## Interface VRF Configuration
project_device_operation_interface_vrf_router = APIRouter()
@project_device_operation_interface_vrf_router.get("/device/{device_name}/interface/{interface_name}/vrf", response_model=ConfigVrfInterfaceAPIResponse)
async def get_device_interface_vrf_configuration(device_name: str, interface_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_configuration_interface_vrf, device_name, interface_name)
        return ConfigVrfInterfaceAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")

@project_device_operation_interface_vrf_router.put("/device/{device_name}/interface/{interface_name}/vrf", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_interface_vrf_configuration(vrf: ConfigVrfInterfaceAPI, device_name: str, interface_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_interface_vrf, device_name, interface_name, vrf.config)
        UserActionLogger().log_info(f"Configuration of VRF was changed on device {device_name} interface {interface_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except VrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"VRF {e.vrf_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_interface_vrf_router.delete("/device/{device_name}/interface/{interface_name}/vrf", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_interface_vrf_configuration(device_name: str, interface_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_interface_vrf, device_name, interface_name)
        UserActionLogger().log_info(f"Configuration of VRF was deleted on device {device_name} interface {interface_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


## BGP Peer Session Template Configuration
project_device_operation_bgp_peer_session_template_router = APIRouter()
@project_device_operation_bgp_peer_session_template_router.get("/device/{device_name}/bgp/template/peer_session", response_model=BgpPeerSessionTemplatesAPIResponse)
async def get_device_bgp_peer_session_templates(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return BgpPeerSessionTemplatesAPIResponse(peer_session_templates=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_bgp_peer_session_template_router.post("/device/{device_name}/bgp/template/peer_session", status_code=status.HTTP_204_NO_CONTENT)
async def create_device_bgp_peer_session_template_configuration(bgp_peer_session_template: ConfigBgpPeerSessionTemplateAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_peer_session_template, device_name, bgp_peer_session_template.config, ConfigurationOperation.NEW)
        UserActionLogger().log_info(f"Configuration of BGP Peer Session Template {bgp_peer_session_template.config['name']} was created on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerSessionTemplateAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"BGP Peer Session Template {e.template_name} already exists")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_peer_session_template_router.put("/device/{device_name}/bgp/template/peer_session", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_bgp_peer_session_template_configuration(bgp_peer_session_template: ConfigBgpPeerSessionTemplateAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_peer_session_template, device_name, bgp_peer_session_template.config, ConfigurationOperation.UPDATE)
        UserActionLogger().log_info(f"Configuration of BGP Peer Session Template {bgp_peer_session_template.config['name']} was changed on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerSessionTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Session Template {e.template_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_peer_session_template_router.get("/device/{device_name}/bgp/template/peer_session/{template_name}", response_model=ConfigBgpPeerSessionTemplateAPIResponse)
async def get_device_bgp_peer_session_template_configuration(device_name: str, template_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_bgp_peer_session_template_configuration, device_name, template_name)
        return ConfigBgpPeerSessionTemplateAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerSessionTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Session Template {e.template_name} not found")
    
@project_device_operation_bgp_peer_session_template_router.delete("/device/{device_name}/bgp/template/peer_session/{template_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_bgp_peer_session_template_configuration(device_name: str, template_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_bgp_peer_session_template, device_name, template_name)
        UserActionLogger().log_info(f"Configuration of BGP Peer Session Template {template_name} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerSessionTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Session Template {e.template_name} not found")
    except BgpPeerSessionTemplateInUse as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"BGP Peer Session Template {e.template_name} is in use. Remove Template form neighbor first")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


## BGP Peer Policy Template Configuration
project_device_operation_bgp_peer_policy_template_router = APIRouter()
@project_device_operation_bgp_peer_policy_template_router.get("/device/{device_name}/bgp/template/peer_policy", response_model=BgpPeerPolicyTemplatesAPIResponse)
async def get_device_bgp_peer_policy_templates(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return BgpPeerPolicyTemplatesAPIResponse(peer_policy_templates=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_bgp_peer_policy_template_router.post("/device/{device_name}/bgp/template/peer_policy", status_code=status.HTTP_204_NO_CONTENT)
async def create_device_bgp_peer_policy_template_configuration(bgp_peer_policy_template: ConfigBgpPeerPolicyTemplateAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_peer_policy_template, device_name, bgp_peer_policy_template.config, ConfigurationOperation.NEW)
        UserActionLogger().log_info(f"Configuration of BGP Peer Policy Template {bgp_peer_policy_template.config['name']} was created on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerPolicyTemplateAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"BGP Peer Policy Template {e.template_name} already exists")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_peer_policy_template_router.put("/device/{device_name}/bgp/template/peer_policy", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_bgp_peer_policy_template_configuration(bgp_peer_policy_template: ConfigBgpPeerPolicyTemplateAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_peer_policy_template, device_name, bgp_peer_policy_template.config, ConfigurationOperation.UPDATE)
        UserActionLogger().log_info(f"Configuration of BGP Peer Policy Template {bgp_peer_policy_template.config['name']} was changed on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_peer_policy_template_router.get("/device/{device_name}/bgp/template/peer_policy/{template_name}", response_model=ConfigBgpPeerPolicyTemplateAPIResponse)
async def get_device_bgp_peer_policy_template_configuration(device_name: str, template_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_bgp_peer_policy_template_configuration, device_name, template_name)
        return ConfigBgpPeerPolicyTemplateAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")

@project_device_operation_bgp_peer_policy_template_router.delete("/device/{device_name}/bgp/template/peer_policy/{template_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_bgp_peer_policy_template_configuration(device_name: str, template_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_bgp_peer_policy_template, device_name, template_name)
        UserActionLogger().log_info(f"Configuration of BGP Peer Policy Template {template_name} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except BgpPeerPolicyTemplateInUse as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"BGP Peer Policy Template {e.template_name} is in use. Remove Template form neighbor first")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


## BGP IPv4 Unicast Neighbor Configuration
project_device_operation_bgp_ipv4_unicast_neighbor_router = APIRouter()
@project_device_operation_bgp_ipv4_unicast_neighbor_router.get("/device/{device_name}/bgp/ipv4_uni_neighbor", response_model=BgpIpv4UnicastNeighborsAPIResponse)
async def get_device_bgp_ipv4_unicast_neighbors(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return BgpIpv4UnicastNeighborsAPIResponse(ipv4_unicast_neighbors=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_bgp_ipv4_unicast_neighbor_router.post("/device/{device_name}/bgp/ipv4_uni_neighbor", status_code=status.HTTP_204_NO_CONTENT)
async def create_device_bgp_ipv4_unicast_neighbor_configuration(bgp_ipv4_unicast_neighbor: ConfigBgpIpv4UnicastNeighborAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_ipv4_unicast_neighbor, device_name, bgp_ipv4_unicast_neighbor.config, ConfigurationOperation.NEW)
        UserActionLogger().log_info(f"Configuration of BGP IPv4 Unicast Neighbor {bgp_ipv4_unicast_neighbor.config['ipv4_address']} was created on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIPv4UnicastNeighborAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"BGP IPv4 Unicast Neighbor {e.id} already exists")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except BgpPeerSessionTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Session Template {e.template_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_ipv4_unicast_neighbor_router.put("/device/{device_name}/bgp/ipv4_uni_neighbor", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_bgp_ipv4_unicast_neighbor_configuration(bgp_ipv4_unicast_neighbor: ConfigBgpIpv4UnicastNeighborAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_ipv4_unicast_neighbor, device_name, bgp_ipv4_unicast_neighbor.config, ConfigurationOperation.UPDATE)
        UserActionLogger().log_info(f"Configuration of BGP IPv4 Unicast Neighbor {bgp_ipv4_unicast_neighbor.config['ipv4_address']} was changed on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIPv4UnicastNeighborNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP IPv4 Unicast Neighbor {e.id} not found")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except BgpPeerSessionTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Session Template {e.template_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_ipv4_unicast_neighbor_router.get("/device/{device_name}/bgp/ipv4_uni_neighbor/{id}", response_model=ConfigBgpIpv4UnicastNeighborAPIResponse)
async def get_device_bgp_ipv4_unicast_neighbor_configuration(device_name: str, id: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_bgp_ipv4_unicast_neighbor_configuration, device_name, id)
        return ConfigBgpIpv4UnicastNeighborAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIPv4UnicastNeighborNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP IPv4 Unicast Neighbor {e.id} not found")
    
@project_device_operation_bgp_ipv4_unicast_neighbor_router.delete("/device/{device_name}/bgp/ipv4_uni_neighbor/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_bgp_ipv4_unicast_neighbor_configuration(device_name: str, id: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_bgp_ipv4_unicast_neighbor, device_name, id)
        UserActionLogger().log_info(f"Configuration of BGP IPv4 Unicast Neighbor {id} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIPv4UnicastNeighborNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP IPv4 Unicast Neighbor {e.id} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


## BGP VPNv4 Unicast Neighbor Configuration
project_device_operation_bgp_vpnv4_unicast_neighbor_router = APIRouter()
@project_device_operation_bgp_vpnv4_unicast_neighbor_router.get("/device/{device_name}/bgp/vpnv4_uni_neighbor", response_model=BgpVpnv4UnicastNeighborsAPIResponse)
async def get_device_bgp_vpnv4_unicast_neighbors(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return BgpVpnv4UnicastNeighborsAPIResponse(vpnv4_unicast_neighbors=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_bgp_vpnv4_unicast_neighbor_router.post("/device/{device_name}/bgp/vpnv4_uni_neighbor", status_code=status.HTTP_204_NO_CONTENT)
async def create_device_bgp_vpnv4_unicast_neighbor_configuration(bgp_vpnv4_unicast_neighbor: ConfigBgpVpnv4UnicastNeighborAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_vpnv4_unicast_neighbor, device_name, bgp_vpnv4_unicast_neighbor.config, ConfigurationOperation.NEW)
        UserActionLogger().log_info(f"Configuration of BGP VPNv4 Unicast Neighbor {bgp_vpnv4_unicast_neighbor.config['ipv4_address']} was created on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpVpnv4UnicastNeighborAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"BGP VPNv4 Unicast Neighbor {e.id} already exists")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_vpnv4_unicast_neighbor_router.put("/device/{device_name}/bgp/vpnv4_uni_neighbor", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_bgp_vpnv4_unicast_neighbor_configuration(bgp_vpnv4_unicast_neighbor: ConfigBgpVpnv4UnicastNeighborAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_vpnv4_unicast_neighbor, device_name, bgp_vpnv4_unicast_neighbor.config, ConfigurationOperation.UPDATE)
        UserActionLogger().log_info(f"Configuration of BGP VPNv4 Unicast Neighbor {bgp_vpnv4_unicast_neighbor.config['ipv4_address']} was changed on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpVpnv4UnicastNeighborNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP VPNv4 Unicast Neighbor {e.id} not found")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_vpnv4_unicast_neighbor_router.get("/device/{device_name}/bgp/vpnv4_uni_neighbor/{id}", response_model=ConfigBgpVpnv4UnicastNeighborAPIResponse)
async def get_device_bgp_vpnv4_unicast_neighbor_configuration(device_name: str, id: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_bgp_vpnv4_unicast_neighbor_configuration, device_name, id)
        return ConfigBgpVpnv4UnicastNeighborAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpVpnv4UnicastNeighborNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP VPNv4 Unicast Neighbor {e.id} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")

@project_device_operation_bgp_vpnv4_unicast_neighbor_router.delete("/device/{device_name}/bgp/vpnv4_uni_neighbor/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_bgp_vpnv4_unicast_neighbor_configuration(device_name: str, id: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_bgp_vpnv4_unicast_neighbor, device_name, id)
        UserActionLogger().log_info(f"Configuration of BGP VPNv4 Unicast Neighbor {id} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpVpnv4UnicastNeighborNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP VPNv4 Unicast Neighbor {e.id} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


## BGP IPv4 Unicast VRF Configuration
project_device_operation_bgp_ipv4_unicast_vrf_router = APIRouter()
@project_device_operation_bgp_ipv4_unicast_vrf_router.get("/device/{device_name}/bgp/ipv4_uni_vrf", response_model=BgpIpv4UnicastVrfsAPIResponse)
async def get_device_bgp_ipv4_unicast_vrfs(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_baseline_configuration, device_name)
        return BgpIpv4UnicastVrfsAPIResponse(ipv4_unicast_vrfs=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")

@project_device_operation_bgp_ipv4_unicast_vrf_router.post("/device/{device_name}/bgp/ipv4_uni_vrf", status_code=status.HTTP_204_NO_CONTENT)
async def create_device_bgp_ipv4_unicast_vrf_configuration(bgp_ipv4_unicast_vrf: ConfigBgpIpv4UnicastVrfAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_ipv4_unicast_vrf, device_name, bgp_ipv4_unicast_vrf.config, ConfigurationOperation.NEW)
        UserActionLogger().log_info(f"Configuration of BGP IPv4 Unicast VRF {bgp_ipv4_unicast_vrf.config['vrf_name']} was created on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIpv4UnicastVrfAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"BGP IPv4 Unicast VRF {e.vrf_name} already exists")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except BgpPeerSessionTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Session Template {e.template_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except VrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"VRF {e.vrf_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_ipv4_unicast_vrf_router.put("/device/{device_name}/bgp/ipv4_uni_vrf", status_code=status.HTTP_204_NO_CONTENT)
async def change_device_bgp_ipv4_unicast_vrf_configuration(bgp_ipv4_unicast_vrf: ConfigBgpIpv4UnicastVrfAPI, device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.configure_network_device_bgp_ipv4_unicast_vrf, device_name, bgp_ipv4_unicast_vrf.config, ConfigurationOperation.UPDATE)
        UserActionLogger().log_info(f"Configuration of BGP IPv4 Unicast VRF {bgp_ipv4_unicast_vrf.config['vrf_name']} was changed on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIpv4UnicastVrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP IPv4 Unicast VRF {e.vrf_name} not found")
    except BgpPeerPolicyTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Policy Template {e.template_name} not found")
    except BgpPeerSessionTemplateNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP Peer Session Template {e.template_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except VrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"VRF {e.vrf_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_operation_bgp_ipv4_unicast_vrf_router.get("/device/{device_name}/bgp/ipv4_uni_vrf/{vrf_name}", response_model=ConfigBgpIpv4UnicastVrfAPIResponse)
async def get_device_bgp_ipv4_unicast_vrf_configuration(device_name: str, vrf_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        config = await run_in_threadpool(controller.get_network_device_bgp_ipv4_unicast_vrf_configuration, device_name, vrf_name)
        return ConfigBgpIpv4UnicastVrfAPIResponse(config=config)
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIpv4UnicastVrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP IPv4 Unicast VRF {e.vrf_name} not found")

@project_device_operation_bgp_ipv4_unicast_vrf_router.delete("/device/{device_name}/bgp/ipv4_uni_vrf/{vrf_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_bgp_ipv4_unicast_vrf_configuration(device_name: str, vrf_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        await run_in_threadpool(controller.delete_network_device_configuration_bgp_ipv4_unicast_vrf, device_name, vrf_name)
        UserActionLogger().log_info(f"Configuration of BGP IPv4 Unicast VRF {vrf_name} was deleted on device {device_name} by {access_token_payload.get('user').get('username')}")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except BgpIpv4UnicastVrfNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP IPv4 Unicast VRF {e.vrf_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

from fastapi import APIRouter, HTTPException, Depends
from fastapi.concurrency import run_in_threadpool
from starlette import status
import app.controller.controller as controller
from app.api.auth.models import AccessTokenPrivilegeLevel3, AccessTokenPrivilegeLevel2, AccessTokenPrivilegeLevel1
from app.api.project.models import CheckProjectInit
from app.api.service.models import ServiceMplsTeTunnelAPI, ServiceMplsL3VpnAPI
from app.heplers.exepctions import NetworkDeviceNotFound, NetworkDeviceInterfaceNotFound, IpExplicitPathNotFound, \
    DeviceSaveError, ServiceMplsTeTunnelDestinationConfigurationMethodError, VrfAlreadyExists, \
    ServiceMplsTeTunnelNotFound, ServiceMplsTeTunnelAlreadyExists, ServiceMplsL3VpnNotFound, \
    ServiceMplsL3VpnAlreadyExists
from app.heplers.functions import format_value_error_msg
from app.logs.logger import UserActionLogger

access_token_privilege_level_3_dependency = AccessTokenPrivilegeLevel3()
access_token_privilege_level_2_dependency = AccessTokenPrivilegeLevel2()
access_token_privilege_level_1_dependency = AccessTokenPrivilegeLevel1()

service_mpls_te_tunnel_router = APIRouter()
@service_mpls_te_tunnel_router.post("/mpls_te_tunnel")
async def new_service_mpls_te_tunnel(mpls_te_tunnel: ServiceMplsTeTunnelAPI, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        service_tunnel = await run_in_threadpool(controller.create_service_mpls_te_tunnel, mpls_te_tunnel.mpls_te_tunnel)
        UserActionLogger().log_info(f"New service: {mpls_te_tunnel.mpls_te_tunnel["service_name"]} mpls te tunnel created")
        return service_tunnel
    except ServiceMplsTeTunnelAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"MPLS TE Tunnel Service {e.mpls_te_tunnel_service_name} already exists")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except ServiceMplsTeTunnelDestinationConfigurationMethodError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect destination configuration method")
    except IpExplicitPathNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Ip explicit path {e.ip_explicit_path_name} not found")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@service_mpls_te_tunnel_router.get("/mpls_te_tunnel/{service_name}")
async def get_service_mpls_te_tunnel(service_name, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.get_service_mpls_te_tunnel, service_name)
    except ServiceMplsTeTunnelNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"MPLS TE Tunnel service {e.mpls_te_tunnel_service_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@service_mpls_te_tunnel_router.get("/mpls_te_tunnel/{service_name}/path")
async def get_service_mpls_te_tunnel(service_name, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.get_service_mpls_te_tunnel_path, service_name)
    except ServiceMplsTeTunnelNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"MPLS TE Tunnel service {e.mpls_te_tunnel_service_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")


service_l3_vpn_router = APIRouter()
@service_l3_vpn_router.post("/mpls_l3_vpn")
async def new_service_mpls_l3_vpn(mpls_l3_vpn: ServiceMplsL3VpnAPI, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        service_l3_vpn = await run_in_threadpool(controller.create_service_mpls_l3_vpn, mpls_l3_vpn.mpls_l3_vpn)
        UserActionLogger().log_info(f"New service: {mpls_l3_vpn.mpls_l3_vpn["service_name"]} MPLS L3 VPN created")
        return service_l3_vpn
    except ServiceMplsL3VpnAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail=f"MPLS L3 VPN Service {e.mpls_l3_vpn_service_name} already exists")
    except NetworkDeviceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {e.network_device_name} not found")
    except NetworkDeviceInterfaceNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Interface {e.network_device_interface_fullname} not found on device {e.network_device_name}")
    except VrfAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"VFR {e.vrf_name} already exists")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=format_value_error_msg(str(e)))
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@service_l3_vpn_router.get("/mpls_l3_vpn/{service_name}")
async def get_service_mpls_l3_vpn(service_name, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.get_service_mpls_l3_vpn, service_name)
    except ServiceMplsL3VpnNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"MPLS L3 VPN service {e.mpls_l3_vpn_service_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@service_l3_vpn_router.get("/mpls_l3_vpn/{service_name}/routes")
async def get_service_mpls_l3_vpn_routes(service_name, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency), validate: CheckProjectInit = Depends(CheckProjectInit())):
    try:
        return await run_in_threadpool(controller.get_service_mpls_l3_vpn_routes, service_name)
    except ServiceMplsL3VpnNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"MPLS L3 VPN service {e.mpls_l3_vpn_service_name} not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

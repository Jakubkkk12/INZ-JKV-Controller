from fastapi import APIRouter, HTTPException, Depends
from starlette import status
from fastapi.concurrency import run_in_threadpool
from app.api.auth.models import AccessTokenPrivilegeLevel3, AccessTokenPrivilegeLevel2, AccessTokenPrivilegeLevel1
from app.api.project.models import DeviceGroupAPI, DeviceAPI, DeviceGroupAPIResponse, DevicesAPIResponse, DeviceAPIResponse
from app.heplers.exepctions import ProjectAlreadyExists, ProjectCreationError, ProjectFailedToLoad, \
    ProjectDeletionError, DeviceGroupReadError, DeviceGroupSaveError, DeviceGroupAlreadyExists, DeviceGroupNotFound, \
    DeviceAlreadyExists, DeviceNotFound, DeviceReadError, DeviceSaveError, \
    DeviceGroupMandatoryDeleteError, DeviceUnsupportedPlatform
from app.logs.logger import UserActionLogger
import app.controller.controller as controller

project_router = APIRouter()
access_token_privilege_level_3_dependency = AccessTokenPrivilegeLevel3()
access_token_privilege_level_2_dependency = AccessTokenPrivilegeLevel2()
access_token_privilege_level_1_dependency = AccessTokenPrivilegeLevel1()

@project_router.post("/", status_code=status.HTTP_201_CREATED)
async def new_project(access_token_payload: dict = Depends(access_token_privilege_level_3_dependency)):
    try:
        await run_in_threadpool(controller.create_project, access_token_payload.get('user').get('username'))
        UserActionLogger().log_info(f"Project created by {access_token_payload.get('user').get('username')}")
    except ProjectAlreadyExists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Project already exists")
    except ProjectCreationError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_router.get("/start")
async def start(access_token_payload: dict = Depends(access_token_privilege_level_3_dependency)):
    try:
        general_info = await run_in_threadpool(controller.start_project, access_token_payload.get('user').get('username'))
        UserActionLogger().log_info(f"Project started by {access_token_payload.get('user').get('username')}")
        return general_info
    except ProjectFailedToLoad:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_router.delete("/")
async def delete_project(access_token_payload: dict = Depends(access_token_privilege_level_3_dependency)):
    try:
        await run_in_threadpool(controller.delete_project)
        UserActionLogger().log_info(f"Project deleted by {access_token_payload.get('user').get('username')}")
    except ProjectDeletionError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

## Group
project_group_router = APIRouter()
@project_group_router.get("/groups", response_model=DeviceGroupAPIResponse)
async def get_project_groups(access_token_payload: dict = Depends(access_token_privilege_level_1_dependency)):
    try:
        groups = await run_in_threadpool(controller.get_device_groups)
        return DeviceGroupAPIResponse(groups=groups)
    except DeviceGroupReadError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_group_router.get("/group/{group_name}", response_model=DeviceGroupAPI)
async def get_project_groups(group_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency)):
    try:
        name, value = await run_in_threadpool(controller.get_device_group, group_name)
        return DeviceGroupAPI(name=name, value=value)
    except DeviceGroupNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    except DeviceGroupReadError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_group_router.post("/group", status_code=status.HTTP_201_CREATED)
async def new_project_group(group: DeviceGroupAPI, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency)):
    try:
        await run_in_threadpool(controller.add_device_group, group)
        UserActionLogger().log_info(f"Group {group.name} created by {access_token_payload.get('user').get('username')}")
    except DeviceGroupAlreadyExists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Group already exists")
    except DeviceGroupSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_group_router.put("/group", status_code=status.HTTP_204_NO_CONTENT)
async def update_project_group(group: DeviceGroupAPI, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency)):
    try:
        await run_in_threadpool(controller.edit_device_group, group)
        UserActionLogger().log_info(f"Group {group.name} updated by {access_token_payload.get('user').get('username')}")
    except DeviceGroupNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    except DeviceGroupReadError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_group_router.delete("/group/{group_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project_group(group_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency)):
    try:
        await run_in_threadpool(controller.delete_device_group, group_name)
        UserActionLogger().log_info(f"Group {group_name} deleted by {access_token_payload.get('user').get('username')}")
    except DeviceGroupNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    except DeviceGroupMandatoryDeleteError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Group is mandatory")
    except DeviceGroupReadError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

## Device
project_device_router = APIRouter()
@project_device_router.get("/devices", response_model=DevicesAPIResponse)
async def get_project_devices(access_token_payload: dict = Depends(access_token_privilege_level_1_dependency)):
    try:
        devices = await run_in_threadpool(controller.get_devices)
        return DevicesAPIResponse(devices=devices)
    except DeviceReadError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_router.get("/device/{device_name}", response_model=DeviceAPIResponse)
async def get_project_devices(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_1_dependency)):
    try:
        name, value = await run_in_threadpool(controller.get_device, device_name)
        return DeviceAPIResponse(name=name, value=value)
    except DeviceNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_router.post("/device", status_code=status.HTTP_201_CREATED)
async def new_project_device(device: DeviceAPI, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency)):
    try:
        await run_in_threadpool(controller.add_device, device)
        UserActionLogger().log_info(f"Device {device.name} created by {access_token_payload.get('user').get('username')}")
    except DeviceAlreadyExists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device already exists")
    except DeviceUnsupportedPlatform:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device with unsupported platform")
    except DeviceGroupNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_router.put("/device", status_code=status.HTTP_204_NO_CONTENT)
async def edit_project_device(device: DeviceAPI, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency)):
    try:
        await run_in_threadpool(controller.edit_device, device)
        UserActionLogger().log_info(f"Device {device.name} updated by {access_token_payload.get('user').get('username')}")
    except DeviceNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    except DeviceUnsupportedPlatform:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device with unsupported platform")
    except DeviceGroupNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

@project_device_router.delete("/device/{device_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project_device(device_name: str, access_token_payload: dict = Depends(access_token_privilege_level_2_dependency)):
    try:
        await run_in_threadpool(controller.delete_device, device_name)
        UserActionLogger().log_info(f"Device {device_name} deleted by {access_token_payload.get('user').get('username')}")
    except DeviceNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    except DeviceSaveError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Controller Error")

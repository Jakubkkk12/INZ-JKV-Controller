from fastapi import HTTPException
from pydantic import BaseModel, model_validator
from starlette import status
from app.controller.nornir_engine.nornir_utils import DeviceGroup, Device
from app.heplers.exepctions import ProjectNotInitialized
from app.heplers.functions import remove_all_key_from_dict
from app.manage_project.manage_project import Project


class CheckProjectInit:
    async def __call__(self):
        try:
            Project()
        except ProjectNotInitialized:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not started")
        return None


class DeviceGroupAPI(DeviceGroup):
    class Config:
        json_schema_extra = {
            "example": {
                "name": "group1",
                "value": {
                    "data": {
                        "key1": "value1",
                        "key2": "value2"
                    }
                }
            }
        }


class DeviceGroupAPIResponse(BaseModel):
    groups: dict

    class Config:
        json_schema_extra = {
            "example": {
                "groups": {
                    "group_name_1": {
                        "data": {
                            "key1": "value1",
                            "key2": "value2"
                        }
                    }
                }
            }
        }


class DeviceAPI(Device):
    class Config:
        json_schema_extra = {
            "example": {
                "name": "device1",
                "value": {
                    "hostname": "192.167.34.1",
                    "platform": "cisco_xe",
                    "username": "admin",
                    "password": "admin",
                    "groups": [
                        "additional_group_name1",
                        "additional_group_name2"
                    ],
                    "data": {
                        "additional_key1": "additional_key_value1",
                        "additional_key2": "additional_key_value2"
                    }
                }
            }
        }


class DeviceAPIResponse(Device):
    @model_validator(mode='after')
    def prepare_devices(self):
        self.value['username'] = ''
        self.value['password'] = ''
        value = self.value
        value = remove_all_key_from_dict(value, 'configuration')
        self.value = remove_all_key_from_dict(value, 'ncclient_platform')
        return self

    class Config:
        json_schema_extra = {
            "example": {
                "name": "device1",
                "value": {
                    "hostname": "192.167.34.1",
                    "platform": "cisco_xe",
                    "username": "",
                    "password": "",
                    "groups": [
                        "additional_group_name1",
                        "additional_group_name2"
                    ],
                    "data": {
                        "additional_key1": "additional_key_value1",
                        "additional_key2": "additional_key_value2"
                    }
                }
            }
        }


class DevicesAPIResponse(BaseModel):
    devices: dict

    @model_validator(mode='after')
    def prepare_devices(self):
        devices = self.devices
        devices = remove_all_key_from_dict(devices, 'username')
        devices = remove_all_key_from_dict(devices, 'password')
        devices = remove_all_key_from_dict(devices, 'configuration')
        self.devices = remove_all_key_from_dict(devices, 'ncclient_platform')
        return self

    class Config:
        json_schema_extra = {
            "example": {
                "devices": {
                    "device_name_1": {
                        "hostname": "device_hostname",
                        "platform": "device_platform",
                        "groups": [
                            "ssh_conf",
                            "netconf_port",
                            "additional_group_name1",
                            "additional_group_name2"
                        ],
                        "data": {
                            "additional_key1": "additional_key_value1",
                            "additional_key2": "additional_key_value2"
                        }
                    }
                }
            }
        }

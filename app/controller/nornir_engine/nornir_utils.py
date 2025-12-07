from pydantic import BaseModel, field_validator, model_validator
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from app.heplers.constants import SUPPORTED_PLATFORMS, SSH_GROUP, SSH_PORT_CONF_KEY, NETCONF_GROUP, \
    NETCONF_PORT_CONF_KEY, MANDATORY_GROUPS, CISCO_XE, NCCLIENT_PLATFORM, NCCLIENT_CISCO_XE
from app.heplers.exepctions import DeviceUnsupportedPlatform


class DeviceGroup(BaseModel):
    name: str
    value: dict

    @field_validator('value')
    def validate_value(cls, v):
        value_schema = {
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "description": "Holds custom data",
                    "properties": {
                    },
                    "additionalProperties": True
                },
            },
            "required": ["data"],
            "additionalProperties": False
        }
        try:
            validate(v, value_schema)
        except ValidationError:
            raise ValueError('incorrect required data')
        return v

    @model_validator(mode='after')
    def check_mandatory_group(self):
        if self.name == SSH_GROUP:
            ssh_port = self.value["data"][SSH_PORT_CONF_KEY]
            if not isinstance(ssh_port, int) or not (1 <= ssh_port <= 65535):
                raise ValueError('SSH port not supported')
        elif self.name == NETCONF_GROUP:
            netconf_port = self.value["data"][NETCONF_PORT_CONF_KEY]
            if not isinstance(netconf_port, int) or not (1 <= netconf_port <= 65535):
                raise ValueError('NETCONF port not supported')
        return self

class Device(BaseModel):
    name: str
    value: dict

    @field_validator('value')
    def validate_value(cls, v):
        value_schema = {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "The IP address or hostname of the device."
                },
                "platform": {
                    "type": "string",
                    "description": "Device platform."
                },
                "username": {
                    "type": "string",
                    "description": "Username for login."
                },
                "password": {
                    "type": "string",
                    "description": "Login password."
                },
                "groups": {
                    "type": "array",
                    "description": "List of group names."
                },
                "data": {
                    "type": "object",
                    "description": "Holds custom data"
                }
            },
            "required": ["hostname", "platform", "username", "password"],
            "additionalProperties": True
        }
        try:
            validate(v, value_schema)
        except ValidationError:
            raise ValueError('incorrect required data')
        if v["platform"] not in SUPPORTED_PLATFORMS:
            raise DeviceUnsupportedPlatform
        return v

    @model_validator(mode='after')
    def add_mandatory_fields(self):
        if "groups" in self.value.keys():
            if SSH_GROUP not in self.value["groups"]:
                self.value["groups"].append(SSH_GROUP)
            if NETCONF_GROUP not in self.value["groups"]:
                self.value["groups"].append(NETCONF_GROUP)
        else:
            self.value["groups"] = MANDATORY_GROUPS

        if "data" not in self.value.keys():
            self.value["data"] = {}

        if self.value["platform"] == CISCO_XE:
            self.value["data"][NCCLIENT_PLATFORM] = NCCLIENT_CISCO_XE
        return self



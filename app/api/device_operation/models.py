import ipaddress
from jsonschema import validate, ValidationError
from pydantic import BaseModel, field_validator
from app.heplers.constants import IpExplicitPathConfigurationMethod, IpExplicitPathConfigurationType
from app.heplers.functions import remove_all_key_from_dict


class ConfigMplsTeInterfaceAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "enable": {
                    "type": "boolean"
                },
                "attribute_flags": {
                    "type": "string"
                },
                "administrative_weight": {
                    "type": "integer"
                },
                "backup_path_tunnel_id": {
                    "type": "integer"
                }
            },
            "required": ["enable"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "enable": True,
                    "attribute_flags": "0x0000FFFF",
                    "administrative_weight": 150,
                    "backup_path_tunnel_id": None
                    }
                }
            }


class ConfigMplsTeInterfaceAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        self.config = remove_all_key_from_dict(self.config, "interface")


class ConfigIpExplicitPathAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                },
                "configuration_method": {
                    "type": "string"
                },
                "data": {
                    "type": "array",
                    "minItems": 1,
                }
            },
            "required": ["name", "type", "configuration_method", "data"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "name": "PATH_135",
                    "type": IpExplicitPathConfigurationType.EXCLUDE,
                    "configuration_method": IpExplicitPathConfigurationMethod.EXPLICIT,
                    "data": [
                        {
                            "ipv4_address": "21.34.65.2"
                        },
                        {
                            "ipv4_address": "67.43.132.34"
                        }
                    ]
                }
            }
        }


class ConfigIpExplicitPathAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        data_e = self.config["path_exclude_address"]
        data_n = self.config["path_next_address"]
        data = []
        if data_e is not None:
            self.config["type"] = IpExplicitPathConfigurationType.EXCLUDE
            for entry in data_e:
                data.append(entry)
        elif data_n is not None:
            self.config["type"] = IpExplicitPathConfigurationType.NEXT_IP_ADDRESS
            for entry in data_n:
                data.append(entry)

        self.config["configuration_method"] = IpExplicitPathConfigurationMethod.EXPLICIT
        self.config["data"] = data
        self.config = remove_all_key_from_dict(self.config, "path_next_address")
        self.config = remove_all_key_from_dict(self.config, "path_exclude_address")
        self.config = remove_all_key_from_dict(self.config, "index")


class IpExplicitPathsAPIResponse(BaseModel):
    ipv4_explicit_paths: dict

    def model_post_init(self, context):
        ipv4_explicit_paths = self.ipv4_explicit_paths["ipv4_explicit_paths"]
        for name, details in ipv4_explicit_paths.items():
            if details["path_next_address"] is None:
                del details["path_next_address"]
            if details["path_exclude_address"] is None:
                del details["path_exclude_address"]
        ipv4_explicit_paths = remove_all_key_from_dict(ipv4_explicit_paths, "name")
        self.ipv4_explicit_paths = ipv4_explicit_paths
    pass

class ConfigMplsTeTunnelAPIResponse(BaseModel):
    config: dict


class MplsTeTunnelsAPIResponse(BaseModel):
    mpls_te_tunnels: dict

    def model_post_init(self, context):
        mpls_te_tunnels = self.vrfs["mpls_te_tunnels"]
        self.mpls_te_tunnels = mpls_te_tunnels


class ConfigVrfAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "rd": {
                    "type": "string"
                },
                "route_target": {
                    "type": "object",
                    "properties": {
                        "export": {
                            "type": "array"
                        },
                        "import": {
                            "type": "array"
                        }
                    },
                    "required": ["export", "import"],
                    "additionalProperties": False
                },
                "maximum_routes": {
                    "type": "object",
                    "properties": {
                        "max_routes": {
                            "type": "integer"
                        },
                        "warning_only": {
                            "type": "boolean"
                        },
                        "warning_threshold": {
                            "type": "integer"
                        },
                        "reinstall_threshold": {
                            "type": "integer"
                        }
                    },
                    "required": ["max_routes"],
                    "additionalProperties": False
                }
            },
            "required": ["name"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "name": "Customer-Orange",
                    "rd": "5065:111",
                    "route_target": {
                        "export": ["5065:111"],
                        "import": ["5065:222", "5065:333"]
                    },
                    "maximum_routes": {
                        "max_routes": 10000,
                        "warning_only": False,
                        "warning_threshold": 80,
                        "reinstall_threshold": 90
                    }
                }
            }
        }


class ConfigVrfAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        self.config['route_target']['import'] = self.config['route_target']['import_']
        self.config = remove_all_key_from_dict(self.config, "import_")


class VrfsAPIResponse(BaseModel):
    vrfs: dict

    def model_post_init(self, context):
        vrfs = self.vrfs["vrfs"]
        for vrf_name in vrfs:
            vrfs[vrf_name]['route_target']['import'] = vrfs[vrf_name]['route_target']['import_']
        vrfs = remove_all_key_from_dict(vrfs, "import_")
        self.vrfs = vrfs


class ConfigVrfInterfaceAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "vrf_name": {
                    "type": "string"
                },
                "ipv4_address": {
                    "type": "string"
                },
                "ipv4_mask": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 32
                }
            },
            "required": ["vrf_name", "ipv4_address", "ipv4_mask"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "vrf_name": "Customer-Orange",
                    "ipv4_address": "192.168.60.25",
                    "ipv4_mask": 24
                    }
                }
            }


class ConfigVrfInterfaceAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        self.config = remove_all_key_from_dict(self.config, "interface")
        self.config['ipv4_mask'] = ipaddress.IPv4Network(f'0.0.0.0/{self.config['ipv4_mask']}', strict=False).prefixlen


class ConfigBgpPeerSessionTemplateAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "remote_asn": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "ebgp_multihop": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "update_source_interface_fullname": {
                    "type": [
                        "string",
                        "null"
                    ]
                },
                "timers": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "properties": {
                        "keepalive_interval": {
                            "type": "integer"
                        },
                        "holdtime": {
                            "type": "integer"
                        },
                        "minimum_neighbor_holdtime": {
                            "type": [
                                "integer",
                                "null"
                            ]
                        }
                    },
                    "required": ["keepalive_interval", "holdtime"],
                    "additionalProperties": False
                }
            },
            "required": ["name"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "name": "TEST",
                    "remote_asn": 5001,
                    "ebgp_multihop": 5,
                    "update_source_interface_fullname": "GigabitEthernet4",
                    "timers": {
                        "keepalive_interval": 20,
                        "holdtime": 200,
                        "minimum_neighbor_holdtime": 60
                    }
                }
            }
        }


class ConfigBgpPeerSessionTemplateAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        if self.config['update_source_interface'] is not None:
            self.config['update_source_interface_fullname'] = self.config['update_source_interface']['full_name']
        else:
            self.config['update_source_interface_fullname'] = None
        self.config = remove_all_key_from_dict(self.config, "asn")
        self.config = remove_all_key_from_dict(self.config, "update_source_interface")


class BgpPeerSessionTemplatesAPIResponse(BaseModel):
    peer_session_templates: dict

    def model_post_init(self, context):
        peer_session_templates = self.peer_session_templates["bgp"]["peer_session_templates"]
        peer_session_templates = remove_all_key_from_dict(peer_session_templates, "asn")
        self.peer_session_templates = peer_session_templates


class ConfigBgpPeerPolicyTemplateAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "route_reflector_client": {
                    "type": "boolean"
                },
                "send_community_extended": {
                    "type": "boolean"
                },
                "send_community_both": {
                    "type": "boolean"
                },
                "as_override": {
                    "type": "boolean"
                },
                "next_hop_self": {
                    "type": "boolean"
                },
                "remove_private_as": {
                    "type": "boolean"
                },
                "soft_reconfiguration_inbound": {
                    "type": "boolean"
                },
                "maximum_prefix": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "allowas_in": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "soo": {
                    "type": [
                        "string",
                        "null"
                    ]
                }
            },
            "required": ["name"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "name": "TEST",
                    "route_reflector_client": True,
                    "send_community_extended": True,
                    "send_community_both": False,
                    "as_override": False,
                    "next_hop_self": False,
                    "remove_private_as": False,
                    "soft_reconfiguration_inbound": False,
                    "maximum_prefix": None,
                    "allowas_in": None,
                    "soo": None
                }
            }
        }


class ConfigBgpPeerPolicyTemplateAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        self.config = remove_all_key_from_dict(self.config, "asn")


class BgpPeerPolicyTemplatesAPIResponse(BaseModel):
    peer_policy_templates: dict

    def model_post_init(self, context):
        peer_policy_templates = self.peer_policy_templates["bgp"]["peer_policy_templates"]
        peer_policy_templates = remove_all_key_from_dict(peer_policy_templates, "asn")
        self.peer_policy_templates = peer_policy_templates


class ConfigBgpIpv4UnicastNeighborAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "ipv4_address": {
                    "type": "string"
                },
                "peer_template": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "properties": {
                        "session_name": {
                            "type": [
                                "string",
                                "null"
                            ],
                        },
                        "policy_name": {
                            "type": [
                                "string",
                                "null"
                            ],
                        }
                    },
                    "required": ["session_name", "policy_name"],
                    "additionalProperties": False
                },
                "remote_asn": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "ebgp_multihop": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "update_source_interface_fullname": {
                    "type": [
                        "string",
                        "null"
                    ]
                },
                "timers": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "properties": {
                        "keepalive_interval": {
                            "type": "integer"
                        },
                        "holdtime": {
                            "type": "integer"
                        },
                        "minimum_neighbor_holdtime": {
                            "type": [
                                "integer",
                                "null"
                            ]
                        }
                    },
                    "required": ["keepalive_interval", "holdtime"],
                    "additionalProperties": False
                },
                "route_reflector_client": {
                    "type": "boolean"
                },
                "send_community_extended": {
                    "type": "boolean"
                },
                "send_community_both": {
                    "type": "boolean"
                },
                "as_override": {
                    "type": "boolean"
                },
                "next_hop_self": {
                    "type": "boolean"
                },
                "remove_private_as": {
                    "type": "boolean"
                },
                "soft_reconfiguration_inbound": {
                    "type": "boolean"
                },
                "maximum_prefix": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "allowas_in": {
                    "type": [
                        "integer",
                        "null"
                    ]
                },
                "soo": {
                    "type": [
                        "string",
                        "null"
                    ]
                }
            },
            "required": ["ipv4_address"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "ipv4_address": "1.1.1.1",
                    "peer_template": {
                        "session_name": "TEST",
                        "policy_name": "TEST"
                    },
                    "remote_asn": 5001,
                    "ebgp_multihop": 5,
                    "update_source_interface_fullname": "GigabitEthernet4",
                    "timers": {
                        "keepalive_interval": 20,
                        "holdtime": 200,
                        "minimum_neighbor_holdtime": 60
                    },
                    "route_reflector_client": True,
                    "send_community_extended": True,
                    "send_community_both": False,
                    "as_override": False,
                    "next_hop_self": False,
                    "remove_private_as": False,
                    "soft_reconfiguration_inbound": False,
                    "maximum_prefix": None,
                    "allowas_in": None,
                    "soo": None
                }
            }
        }


class ConfigBgpIpv4UnicastNeighborAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        if self.config['update_source_interface'] is not None:
            self.config['update_source_interface_fullname'] = self.config['update_source_interface']['full_name']
        else:
            self.config['update_source_interface_fullname'] = None
        self.config = remove_all_key_from_dict(self.config, "update_source_interface")


class BgpIpv4UnicastNeighborsAPIResponse(BaseModel):
    ipv4_unicast_neighbors: dict

    def model_post_init(self, context):
        ipv4_unicast_neighbors = self.ipv4_unicast_neighbors["bgp"]["ipv4_unicast_neighbors"]
        ipv4_unicast_neighbors = remove_all_key_from_dict(ipv4_unicast_neighbors, "asn")
        self.ipv4_unicast_neighbors = ipv4_unicast_neighbors


class ConfigBgpVpnv4UnicastNeighborAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "ipv4_address": {
                    "type": "string"
                },
                "peer_template": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "properties": {
                        "policy_name": {
                            "type": "string"
                        }
                    },
                    "required": ["policy_name"],
                    "additionalProperties": False
                },
                "route_reflector_client": {
                    "type": "boolean"
                },
                "send_community_extended": {
                    "type": "boolean"
                },
                "send_community_both": {
                    "type": "boolean"
                }
            },
            "required": ["ipv4_address"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "ipv4_address": "1.1.1.1",
                    "peer_template": {
                        "policy_name": "TEST-RR"
                    },
                    "route_reflector_client": True,
                    "send_community_extended": True,
                    "send_community_both": False
                }
            }
        }


class ConfigBgpVpnv4UnicastNeighborAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        self.config = remove_all_key_from_dict(self.config, "session_name")
        self.config = remove_all_key_from_dict(self.config, "remote_asn")
        self.config = remove_all_key_from_dict(self.config, "ebgp_multihop")
        self.config = remove_all_key_from_dict(self.config, "update_source_interface")
        self.config = remove_all_key_from_dict(self.config, "timers")
        self.config = remove_all_key_from_dict(self.config, "as_override")
        self.config = remove_all_key_from_dict(self.config, "next_hop_self")
        self.config = remove_all_key_from_dict(self.config, "remove_private_as")
        self.config = remove_all_key_from_dict(self.config, "soft_reconfiguration_inbound")
        self.config = remove_all_key_from_dict(self.config, "maximum_prefix")
        self.config = remove_all_key_from_dict(self.config, "soo")
        self.config = remove_all_key_from_dict(self.config, "allowas_in")


class BgpVpnv4UnicastNeighborsAPIResponse(BaseModel):
    vpnv4_unicast_neighbors: dict

    def model_post_init(self, context):
        vpnv4_unicast_neighbors = self.vpnv4_unicast_neighbors["bgp"]["vpnv4_unicast_neighbors"]
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "asn")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "session_name")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "remote_asn")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "ebgp_multihop")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "update_source_interface")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "timers")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "as_override")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "next_hop_self")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "remove_private_as")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "soft_reconfiguration_inbound")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "maximum_prefix")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "soo")
        vpnv4_unicast_neighbors = remove_all_key_from_dict(vpnv4_unicast_neighbors, "allowas_in")
        self.vpnv4_unicast_neighbors = vpnv4_unicast_neighbors


class ConfigBgpIpv4UnicastVrfAPI(BaseModel):
    config: dict

    @field_validator("config")
    def check_config_schema(cls, v):
        schema = {
            "type": "object",
            "properties": {
                "vrf_name": {
                    "type": "string"
                },
                "neighbors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ipv4_address": {
                                "type": "string"
                            },
                            "peer_template": {
                                "type": [
                                    "object",
                                    "null"
                                ],
                                "properties": {
                                    "session_name": {
                                        "type": [
                                            "string",
                                            "null"
                                        ],
                                    },
                                    "policy_name": {
                                        "type": [
                                            "string",
                                            "null"
                                        ],
                                    }
                                },
                                "required": ["session_name", "policy_name"],
                                "additionalProperties": False
                            },
                            "remote_asn": {
                                "type": [
                                    "integer",
                                    "null"
                                ]
                            },
                            "ebgp_multihop": {
                                "type": [
                                    "integer",
                                    "null"
                                ]
                            },
                            "update_source_interface_fullname": {
                                "type": [
                                    "string",
                                    "null"
                                ]
                            },
                            "timers": {
                                "type": [
                                    "object",
                                    "null"
                                ],
                                "properties": {
                                    "keepalive_interval": {
                                        "type": "integer"
                                    },
                                    "holdtime": {
                                        "type": "integer"
                                    },
                                    "minimum_neighbor_holdtime": {
                                        "type": [
                                            "integer",
                                            "null"
                                        ]
                                    }
                                },
                                "required": ["keepalive_interval", "holdtime"],
                                "additionalProperties": False
                            },
                            "route_reflector_client": {
                                "type": "boolean"
                            },
                            "send_community_extended": {
                                "type": "boolean"
                            },
                            "send_community_both": {
                                "type": "boolean"
                            },
                            "as_override": {
                                "type": "boolean"
                            },
                            "next_hop_self": {
                                "type": "boolean"
                            },
                            "remove_private_as": {
                                "type": "boolean"
                            },
                            "soft_reconfiguration_inbound": {
                                "type": "boolean"
                            },
                            "maximum_prefix": {
                                "type": [
                                    "integer",
                                    "null"
                                ]
                            },
                            "allowas_in": {
                                "type": [
                                    "integer",
                                    "null"
                                ]
                            },
                            "soo": {
                                "type": [
                                    "string",
                                    "null"
                                ]
                            }
                        },
                        "required": ["ipv4_address"],
                        "additionalProperties": False
                    }
                },
                "networks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ipv4_address": {
                                "type": "string"
                            },
                            "ipv4_mask": {
                                "type": "integer"
                            }
                        },
                        "required": ["ipv4_address", "ipv4_mask"],
                        "additionalProperties": False
                    }
                },
                "aggregate_addresses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ipv4_address": {
                                "type": "string"
                            },
                            "ipv4_mask": {
                                "type": "integer"
                            },
                            "summary_only": {
                                "type": "boolean"
                            }
                        },
                        "required": ["ipv4_address", "ipv4_mask"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["vrf_name"],
            "additionalProperties": False
        }
        try:
            validate(instance=v, schema=schema)
        except ValidationError as e:
            raise ValueError(f"Invalid configuration")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "config": {
                    "vrf_name": "CustABC",
                    "neighbors": [
                        {
                            "ipv4_address": "1.1.1.1",
                            "peer_template": {
                                "session_name": "TEST-VRF-CustABC",
                                "policy_name": "TEST-VRF-CustABC"
                            },
                            "remote_asn": 6005,
                            "ebgp_multihop": 5,
                            "update_source_interface_fullname": "GigabitEthernet4",
                            "timers": {
                                "keepalive_interval": 20,
                                "holdtime": 200,
                                "minimum_neighbor_holdtime": 60
                            },
                            "route_reflector_client": True,
                            "send_community_extended": True,
                            "send_community_both": False,
                            "as_override": False,
                            "next_hop_self": False,
                            "remove_private_as": False,
                            "soft_reconfiguration_inbound": False,
                            "maximum_prefix": None,
                            "allowas_in": None,
                            "soo": None
                        }
                    ],
                    "networks": [
                        {
                            "ipv4_address": "10.150.0.0",
                            "ipv4_mask": 16
                        }
                    ],
                    "aggregate_addresses": [
                        {
                            "ipv4_address": "10.0.0.0",
                            "ipv4_mask": 8,
                            "summary_only": True
                        }
                    ]
                }
            }
        }


class ConfigBgpIpv4UnicastVrfAPIResponse(BaseModel):
    config: dict

    def model_post_init(self, context):
        self.config = remove_all_key_from_dict(self.config, "asn")
        if self.config["neighbors"] is not None:
            for neighbor in self.config["neighbors"]:
                if neighbor['update_source_interface'] is not None:
                    neighbor['update_source_interface_fullname'] = neighbor['update_source_interface']['full_name']
                else:
                    neighbor['update_source_interface'] = None
        self.config = remove_all_key_from_dict(self.config, "update_source_interface")
        if self.config["networks"] is not None:
            for network in self.config["networks"]:
                network['ipv4_mask'] = ipaddress.IPv4Network(f'0.0.0.0/{network['ipv4_mask']}', strict=False).prefixlen
        if self.config["aggregate_addresses"] is not None:
            for aggregate_addresse in self.config["aggregate_addresses"]:
                aggregate_addresse['ipv4_mask'] = ipaddress.IPv4Network(f'0.0.0.0/{aggregate_addresse['ipv4_mask']}',strict=False).prefixlen


class BgpIpv4UnicastVrfsAPIResponse(BaseModel):
    ipv4_unicast_vrfs: dict

    def model_post_init(self, context):
        if not self.ipv4_unicast_vrfs:
            return
        ipv4_unicast_vrfs = self.ipv4_unicast_vrfs['bgp']['ipv4_unicast_vrfs']
        ipv4_unicast_vrfs = remove_all_key_from_dict(ipv4_unicast_vrfs, "asn")
        self.ipv4_unicast_vrfs = ipv4_unicast_vrfs


from pydantic import BaseModel
from app.heplers.constants import ServiceMplsTeTunnelDestinationConfigurationMethod, IpExplicitPathConfigurationMethod, \
    IpExplicitPathConfigurationType


class ServiceMplsTeTunnelAPI(BaseModel):
    mpls_te_tunnel: dict

    class Config:
        json_schema_extra = {
            "example": {
                "mpls_te_tunnel": {
                    "service_name": "OrangeENS3452",
                    "description": "Orange contract ENS3452",
                    "source_device_name": "device1",
                    "destination": {
                        "configuration_method": ServiceMplsTeTunnelDestinationConfigurationMethod.IPV4_ADDRESS,
                        "configuration": {
                            "ipv4_address": "2.2.2.2",
                            "device_name": "device1"
                        }
                    },
                    "bandwidth_Mb": 100,
                    "autoroute_announce": True,
                    "path_selection_metric": "te",
                    "affinity": {
                        "value": "0x00000001",
                        "mask": "0x000000FF"
                    },
                    "priority": {
                        "setup": 6,
                        "hold": 6,
                    },
                    "path_options": {
                        "add_dynamic": True,
                        "paths": [
                            {
                                "lockdown": False,
                                "ipv4_explicit_path": {
                                    "name": "PATH_555",
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
                                },
                                "protection": {
                                    "ipv4_explicit_path": {
                                        "name": "PATH_555",
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
                        ]
                    },
                    "fast_reroute": {
                        "link_protection": [
                            {
                                "link_to_node": {
                                    "device_name": "device1",
                                    "interface_fullname": "GigabitEthernet2",
                                },
                                "end_device_name": "device3",
                                "through_devices": [
                                    "device2"
                                ],
                                "protected_tunnel_min_bandwidth_Mb": 400,
                            }
                        ],
                        "node_protection": [
                            {
                                "link_to_node": {
                                    "device_name": "device1",
                                    "interface_fullname": "GigabitEthernet2",
                                },
                                "end_device_name": "device4",
                                "through_devices": [
                                    "device2",
                                    "device3"
                                ],
                                "protected_tunnel_min_bandwidth_Mb": 400,
                            }
                        ]
                    }
                }
            }
        }


class ServiceMplsTeTunnelQosAPI(BaseModel):
    mpls_te_tunnel_qos: dict

    class Config:
        json_schema_extra = {
            "example": {
                "mpls_te_tunnel_qos": {
                    "name": "Orange contract ENS3452",
                    "description": "Orange contract ENS3452",
                    "source_device_name": "device1",
                    "destination": {
                        "configuration_method": ServiceMplsTeTunnelDestinationConfigurationMethod.IPV4_ADDRESS,
                        "configuration": {
                            "ipv4_address": "2.2.2.2",
                            "device_name": "device1"
                        }
                    },
                    "autoroute_announce": True,
                    "qos": [
                        {
                            "exp": [
                                5,
                                6,
                                7,
                            ],
                            "bandwidth_Mb": 100,
                            "path_selection_metric": "te",
                            "affinity": {
                                "value": "0x00000001",
                                "mask": "0x000000FF"
                            },
                            "priority": {
                                "setup": 6,
                                "hold": 6,
                            },
                            "path_options": {
                                "add_dynamic": True,
                                "paths": [
                                    {
                                        "lockdown": False,
                                        "ipv4_explicit_path": {
                                            "name": "PATH_555",
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
                                        },
                                        "protection": {
                                            "ipv4_explicit_path": {
                                                "name": "PATH_555",
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
                                ]
                            },
                            "fast_reroute": {
                                "link_protection": [
                                    {
                                        "link_to_node": {
                                            "device_name": "device1",
                                            "interface_fullname": "GigabitEthernet2",
                                        },
                                        "end_device_name": "device3",
                                        "through_devices": [
                                            "device2"
                                        ],
                                        "protected_tunnel_min_bandwidth_Mb": 400,
                                    }
                                ],
                                "node_protection": [
                                    {
                                        "link_to_node": {
                                            "device_name": "device1",
                                            "interface_fullname": "GigabitEthernet2",
                                        },
                                        "end_device_name": "device4",
                                        "through_devices": [
                                            "device2",
                                            "device3"
                                        ],
                                        "protected_tunnel_min_bandwidth_Mb": 400,
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }


class ServiceMplsL3VpnAPI(BaseModel):
    mpls_l3_vpn: dict

    class Config:
        json_schema_extra = {
            "example": {
                "mpls_l3_vpn": {
                    "service_name": "OrangeENS3452",
                    "vrf_name": "Orange",
                    "pes": [
                        {
                            "pe_device_name": "PE1",
                            "max_vrf_routes": 200,
                            "ce_neighbors": [
                                {
                                    "bgp_asn": 65200,
                                    "ipv4_address": "10.255.0.2",
                                    "interface_to_ce_name": "GigabitEthernet",
                                    "interface_to_ce_id": 2,
                                    "interface_to_ce_ipv4_address": "10.255.0.1",
                                    "interface_to_ce_ipv4_mask": "255.255.255.0",
                                    "special_requirements": {
                                        "max_prefixes_from_bgp_neighbor": 30,
                                        "bgp_neighbor_timers": {
                                            "keepalive_interval": 20,
                                            "holdtime": 200,
                                            "minimum_neighbor_holdtime": 60
                                        }
                                    }
                                }
                            ]
                        },
                        {
                            "pe_device_name": "PE2",
                            "max_vrf_routes": 200,
                            "ce_neighbors": [
                                {
                                    "bgp_asn": 65200,
                                    "ipv4_address": "10.255.0.2",
                                    "interface_to_ce_name": "GigabitEthernet",
                                    "interface_to_ce_id": 2,
                                    "interface_to_ce_ipv4_address": "10.255.0.1",
                                    "interface_to_ce_ipv4_mask": "255.255.255.0",
                                    "special_requirements": {
                                        "max_prefixes_from_bgp_neighbor": 30,
                                        "bgp_neighbor_timers": {
                                            "keepalive_interval": 20,
                                            "holdtime": 200,
                                            "minimum_neighbor_holdtime": 60
                                        }
                                    }
                                }
                            ]
                        },
                        {
                            "pe_device_name": "PE3",
                            "max_vrf_routes": 200,
                            "ce_neighbors": [
                                {
                                    "bgp_asn": 2000,
                                    "neighbor_ipv4_address": "10.255.0.2",
                                    "interface_to_ce_name": "GigabitEthernet",
                                    "interface_to_ce_id": 2,
                                    "interface_to_ce_ipv4_address": "10.255.0.1",
                                    "interface_to_ce_ipv4_mask": "255.255.255.0",
                                    "special_requirements": {
                                        "max_prefixes_from_bgp_neighbor": 30,
                                        "bgp_neighbor_timers": {
                                            "keepalive_interval": 20,
                                            "holdtime": 200,
                                            "minimum_neighbor_holdtime": 60
                                        }
                                    }
                                }
                            ]
                        }
                    ],
                    "allowed_communications": [
                        {
                            "pe_device_name": "PE1",
                            "allowed_routes_from_pe": ["PE2", "PE3"]
                        },
                        {
                            "pe_device_name": "PE2",
                            "allowed_routes_from_pe": ["PE1"]
                        },
                        {
                            "pe_device_name": "PE3",
                            "allowed_routes_from_pe": ["PE1", "PE2"]
                        },
                    ]
                }
            }
        }
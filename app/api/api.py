from fastapi import FastAPI
from app.api.service.router import service_mpls_te_tunnel_router, service_l3_vpn_router
from app.heplers.constants import API_VERSION_V1
from app.api.auth.router import auth_router
from app.api.user.router import user_router
from app.api.project.router import project_router, project_group_router, project_device_router
from app.api.device_operation.router import project_device_operation_router, \
    project_device_operation_mpls_te_router, project_device_operation_explicit_path_router, \
    project_device_operation_interface_vrf_router, project_device_operation_interface_mpls_te_router, \
    project_device_operation_vrf_router, project_device_operation_bgp_peer_session_template_router, \
    project_device_operation_bgp_peer_policy_template_router, project_device_operation_bgp_ipv4_unicast_neighbor_router, \
    project_device_operation_bgp_vpnv4_unicast_neighbor_router, project_device_operation_bgp_ipv4_unicast_vrf_router, \
    project_device_operation_mpls_te_tunnel_router

app = FastAPI(title="JKV", version="1.0")

app.include_router(
    auth_router,
    prefix=f"{API_VERSION_V1}/auth",
    tags=["Authentication"]
)

app.include_router(
    user_router,
    prefix=f"{API_VERSION_V1}/user",
    tags=["User"]
)

app.include_router(
    project_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Project"]
)

app.include_router(
    project_group_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Project Group"]
)


app.include_router(
    project_device_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Project Device"]
)

app.include_router(
    project_device_operation_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device Operation"]
)

app.include_router(
    project_device_operation_interface_mpls_te_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device Interface - MPLS TE"]
)

app.include_router(
    project_device_operation_interface_vrf_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device Interface -  VRF"]
)

app.include_router(
    project_device_operation_mpls_te_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device MPLS TE Global"]
)


app.include_router(
    project_device_operation_mpls_te_tunnel_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device MPLS TE Tunnel"]
)

app.include_router(
    project_device_operation_explicit_path_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device IPv4 Explicit Path"]
)

app.include_router(
    project_device_operation_vrf_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device VRF"]
)

app.include_router(
    project_device_operation_bgp_peer_session_template_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device BGP - Peer Session Template"]
)

app.include_router(
    project_device_operation_bgp_peer_policy_template_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device BGP - Peer Policy Template"]
)

app.include_router(
    project_device_operation_bgp_ipv4_unicast_neighbor_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device BGP - IPv4 Unicast Neighbor"]
)

app.include_router(
    project_device_operation_bgp_vpnv4_unicast_neighbor_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device BGP - VPNv4 Unicast Neighbor"]
)

app.include_router(
    project_device_operation_bgp_ipv4_unicast_vrf_router,
    prefix=f"{API_VERSION_V1}/project",
    tags=["Device BGP - IPv4 Unicast VRF"]
)

app.include_router(
    service_mpls_te_tunnel_router,
    prefix=f"{API_VERSION_V1}/service",
    tags=["Service - IP MPLS TE Tunnel"]
)

app.include_router(
    service_l3_vpn_router,
    prefix=f"{API_VERSION_V1}/service",
    tags=["Service - MPLS L3 VPN"]
)

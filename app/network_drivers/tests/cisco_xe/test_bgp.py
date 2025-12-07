from app.network_drivers.cisco_xe.bgp.bgp import BgpNeighborTimers, BgpIpv4AggregateAddress, BgpIpv4Network, \
    BgpNeighborPeerTemplate, BgpNeighbor
import pytest


class TestBgpNeighborTimers:
    @pytest.mark.parametrize(
        "keepalive_interval, holdtime, minimum_neighbor_holdtime",
        [
            (60, 300, 180),
            (150, 900, None),
            (1, 600, 10),
        ],
    )
    def test_correct_values(self, keepalive_interval, holdtime, minimum_neighbor_holdtime):
        BgpNeighborTimers(keepalive_interval=keepalive_interval, holdtime=holdtime, minimum_neighbor_holdtime=minimum_neighbor_holdtime)

    @pytest.mark.parametrize(
        "keepalive_interval, holdtime, minimum_neighbor_holdtime",
        [
            (-1, 300, 180),
            (60, None, None),
            (60, 300, 600),
            (60, 30, None),
            (60, 3066666660, 180),
            ("6oo", 300, 180),
        ],
    )
    def test_incorrect_values(self, keepalive_interval, holdtime, minimum_neighbor_holdtime):
        with pytest.raises(ValueError):
            BgpNeighborTimers(keepalive_interval=keepalive_interval, holdtime=holdtime,
                              minimum_neighbor_holdtime=minimum_neighbor_holdtime)


class TestBgpIpv4AggregateAddress:
    @pytest.mark.parametrize(
        "ipv4_address, ipv4_mask, summary_only",
        [
            ("200.0.0.0", "255.0.0.0", True),
            ("192.16.0.4", "255.255.255.252", False),
            ("167.234.56.0", "255.255.255.128", True),
        ],
    )
    def test_correct_values(self, ipv4_address, ipv4_mask, summary_only):
        BgpIpv4AggregateAddress(ipv4_address=ipv4_address, ipv4_mask=ipv4_mask, summary_only=summary_only)

    @pytest.mark.parametrize(
        "ipv4_address, ipv4_mask, summary_only",
        [
            ("200.255.255.255", "255.0.0.0", True),
            ("192.16.0.1", "255.255.255.252", False),
            ("167.234.56.0", "255.250.255.128", True),
            ("1675.234.56.0", "255.250.255.128", True),
            ("1675.234.56.0", "/24", True),
            ("1675.234.56.0", "/24", None),
        ],
    )
    def test_incorrect_values(self, ipv4_address, ipv4_mask, summary_only):
        with pytest.raises(ValueError):
            BgpIpv4AggregateAddress(ipv4_address=ipv4_address, ipv4_mask=ipv4_mask, summary_only=summary_only)


class TestBgpIpv4Network:
    @pytest.mark.parametrize(
        "ipv4_address, ipv4_mask",
        [
            ("200.0.0.0", "255.0.0.0"),
            ("192.16.0.4", "255.255.255.252"),
            ("167.234.56.0", "255.255.255.128"),
        ],
    )
    def test_correct_values(self, ipv4_address, ipv4_mask):
        BgpIpv4Network(ipv4_address=ipv4_address, ipv4_mask=ipv4_mask)

    @pytest.mark.parametrize(
        "ipv4_address, ipv4_mask",
        [
            ("200.255.255.255", "255.0.0.0"),
            ("192.16.0.1", "255.255.255.252"),
            ("167.234.56.0", "255.250.255.128"),
            ("1675.234.56.0", "255.250.255.128"),
            ("1675.234.56.0", "/24"),
        ],
    )
    def test_incorrect_values(self, ipv4_address, ipv4_mask):
        with pytest.raises(ValueError):
            BgpIpv4AggregateAddress(ipv4_address=ipv4_address, ipv4_mask=ipv4_mask)


class TestBgpNeighborPeerTemplate:
    @pytest.mark.parametrize(
        "session_name, policy_name",
        [
            (None, None),
            ("SES123", None),
            ("AS123-S", "AS123-P"),
        ],
    )
    def test_correct_values(self, session_name, policy_name):
        BgpNeighborPeerTemplate(session_name=session_name, policy_name=policy_name)

    @pytest.mark.parametrize(
        "session_name, policy_name",
        [
            ("", None),
            ("ToLONG-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None),
        ],
    )
    def test_incorrect_values(self,session_name, policy_name):
        with pytest.raises(ValueError):
            BgpNeighborPeerTemplate(session_name=session_name, policy_name=policy_name)


class TestBgpNeighbor:
    @pytest.mark.parametrize(
        "ipv4_address, remote_asn, ebgp_multihop, route_reflector_client, send_community_extended, send_community_both, as_override, next_hop_self, remove_private_as, soft_reconfiguration_inbound, maximum_prefix, soo, allowas_in",
        [
            ("123.45.32.5", 5673, 1, False, False, True, True, False, True, False, 1000, "50:6000", 3),
            ("43.45.35.89", 65001, None, True, True, True, False, True, False, True, None, None, None),
        ],
    )
    def test_correct_values(self, ipv4_address, remote_asn, ebgp_multihop, route_reflector_client, send_community_extended, send_community_both, as_override, next_hop_self, remove_private_as, soft_reconfiguration_inbound, maximum_prefix, soo, allowas_in):
        BgpNeighbor(ipv4_address=ipv4_address, remote_asn=remote_asn, ebgp_multihop=ebgp_multihop, route_reflector_client=route_reflector_client, send_community_extended=send_community_extended, send_community_both=send_community_both, as_override=as_override, next_hop_self=next_hop_self, remove_private_as=remove_private_as, soft_reconfiguration_inbound=soft_reconfiguration_inbound, maximum_prefix=maximum_prefix, soo=soo, allowas_in=allowas_in)

    @pytest.mark.parametrize(
        "ipv4_address, remote_asn, ebgp_multihop, route_reflector_client, send_community_extended, send_community_both, as_override, next_hop_self, remove_private_as, soft_reconfiguration_inbound, maximum_prefix, soo, allowas_in",
        [
            ("123.485.32.5", 5673, 1, False, False, True, True, False, True, True, 1000, "50:6000", 3),
            ("43.45.35.89", 65001, None, True, True, True, False, True, False, False, None, None, 90),
            ("43.45.35.89", 0, None, True, True, True, False, True, False, False, None, None, None),
            ("43.45.35.89", 70, None, True, True, True, False, True, False, True, 10, None, None),
            ("43.45.35.89", 65001, None, True, True, True, False, True, False, True, None, "123.456.43.2:6785", None),
        ],
    )
    def test_incorrect_values(self, ipv4_address, remote_asn, ebgp_multihop, route_reflector_client, send_community_extended, send_community_both, as_override, next_hop_self, remove_private_as, soft_reconfiguration_inbound, maximum_prefix, soo, allowas_in):
        with pytest.raises(ValueError):
            BgpNeighbor(ipv4_address=ipv4_address, remote_asn=remote_asn, ebgp_multihop=ebgp_multihop,
                        route_reflector_client=route_reflector_client, send_community_extended=send_community_extended,
                        send_community_both=send_community_both, as_override=as_override, next_hop_self=next_hop_self,
                        remove_private_as=remove_private_as, soft_reconfiguration_inbound=soft_reconfiguration_inbound,
                        maximum_prefix=maximum_prefix, soo=soo, allowas_in=allowas_in)



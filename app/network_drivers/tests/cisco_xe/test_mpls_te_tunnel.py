import pytest
from app.network_drivers.cisco_xe.mpls.mpls_te_tunnel.mpls_te_tunnel import FastReroute, TunnelPath, \
    TunnelPathExplicit, TunnelPathDynamic, ProtectPath, TunnelPathOption, TunnelPriority, ConfigMplsTeTunnel, \
    TunnelAffinity


class TestFastReroute:
    @pytest.mark.parametrize(
        "enabled, node_protect",
        [
            (True, False),
            ('true', 'false'),
            (True, 'true'),
            ('yes', 'no')
        ],
    )
    def test_correct_values(self, enabled, node_protect):
        FastReroute(enabled=enabled, node_protect=node_protect)

    @pytest.mark.parametrize(
        "enabled, node_protect",
        [
            (False, True),
            ('Si', False),
        ],
    )
    def test_incorrect_values(self, enabled, node_protect):
        with pytest.raises(ValueError):
            FastReroute(enabled=enabled, node_protect=node_protect)

class TestTunnelPath:
    @pytest.mark.parametrize(
        "id, bandwidth, is_lockdown",
        [
            (1, 5000, False),
            (2, 10000, 'false'),
            (3, None, None),
            (1000, None, 'yes'),
        ],
    )
    def test_correct_values(self, id, bandwidth, is_lockdown):
        TunnelPath(id=id, bandwidth=bandwidth, is_lockdown=is_lockdown)

    @pytest.mark.parametrize(
        "id, bandwidth, is_lockdown",
        [
            (0, 5000, False),
            (2000, 1000, 'false'),
            (3, -500, None),
            (None, None, None),
        ],
    )
    def test_incorrect_values(self, id, bandwidth, is_lockdown):
        with pytest.raises(ValueError):
            TunnelPath(id=id, bandwidth=bandwidth, is_lockdown=is_lockdown)

class TestTunnelPathExplicit:
    correct_id = 1
    correct_bandwidth = 1000
    correct_is_lockdown = False

    @pytest.mark.parametrize(
        "name, is_explicit",
        [
            ('PATH-TO-R4', True),
            ('IS-ok-path', True),
        ],
    )
    def test_correct_values(self, name, is_explicit):
        TunnelPathExplicit(id=self.correct_id, bandwidth=self.correct_bandwidth, is_lockdown=self.correct_is_lockdown, name=name, is_explicit=is_explicit)

    @pytest.mark.parametrize(
        "name, is_explicit",
        [
            ('PATH-TO-R4', False),
            ('TO-LONG-NAME-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', True),
            (None, None),
            ('', True),
        ],
    )
    def test_incorrect_values(self, name, is_explicit):
        with pytest.raises(ValueError):
            TunnelPathExplicit(id=self.correct_id, bandwidth=self.correct_bandwidth,
                               is_lockdown=self.correct_is_lockdown, name=name, is_explicit=is_explicit)

class TestTunnelPathDynamic:
    correct_id = 1
    correct_bandwidth = 1000
    correct_is_lockdown = False

    @pytest.mark.parametrize(
        "is_dynamic",
        [
            (True),
            ('yes'),
        ],
    )
    def test_correct_values(self, is_dynamic):
        TunnelPathDynamic(id=self.correct_id, bandwidth=self.correct_bandwidth, is_lockdown=self.correct_is_lockdown, is_dynamic=is_dynamic)

    @pytest.mark.parametrize(
        "is_dynamic",
        [
            (False),
            (None),
            ('no'),
        ],
    )
    def test_incorrect_values(self, is_dynamic):
        with pytest.raises(ValueError):
            TunnelPathDynamic(id=self.correct_id, bandwidth=self.correct_bandwidth,
                              is_lockdown=self.correct_is_lockdown, is_dynamic=is_dynamic)

class TestProtectPath:
    @pytest.mark.parametrize(
        "id, name",
        [
            (1, "BACKUP-PATH-TO-R4"),
            (1000, "PATH-TO-R7"),
        ],
    )
    def test_correct_values(self, id, name):
        ProtectPath(id=id, name=name)

    @pytest.mark.parametrize(
        "id, name",
        [
            (0, "Path-BACKUP"),
            (2000, "Path-TO-R4"),
            (3, "TO-LONG-NAME-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            (None, None),
            (8, '')
        ],
    )
    def test_incorrect_values(self, id, name):
        with pytest.raises(ValueError):
            ProtectPath(id=id, name=name)

class TestTunnelPathOption:
    @pytest.mark.parametrize(
        "paths, protect_paths",
        [
            ([TunnelPathExplicit(id=1, name="PATH-TO-R7"), TunnelPathExplicit(id=2, name="PATH-TO-R4"), TunnelPathDynamic(id=200, bandwidth=1000)], [ProtectPath(id=1, name="BC-PATH-TO-R4"), ProtectPath(id=2, name="BACKUP-2")]),
            (None, [ProtectPath(id=1, name="BC-PATH-TO-R4"), ProtectPath(id=2, name="BACKUP-2")]),
            ([TunnelPathExplicit(id=1, name="PATH-TO-R7"), TunnelPathExplicit(id=2, name="PATH-TO-R4"), TunnelPathDynamic(id=200, bandwidth=1000)], None),
            (None, None)
        ],
    )
    def test_correct_values(self, paths, protect_paths):
        TunnelPathOption(paths=paths, protect_paths=protect_paths)

    @pytest.mark.parametrize(
        "paths, protect_paths",
        [
            ([1,3,44], ['is_ok', 'bc-path', 7]),
            (None, ['is_ok', 'bc-path', 7]),
            ([TunnelPathExplicit(id=1, name="PATH-TO-R7"), 1, 3, 44, 'exp-patt'], None)
        ],
    )
    def test_incorrect_values(self, paths, protect_paths):
        with pytest.raises(ValueError):
            TunnelPathOption(paths=paths, protect_paths=protect_paths)

class TestTunnelPriority:
    @pytest.mark.parametrize(
        "setup, hold",
        [
            (1, 1),
            (5, 1),
            (7, 7),
        ],
    )
    def test_correct_values(self, setup, hold):
        TunnelPriority(setup=setup, hold=hold)

    @pytest.mark.parametrize(
        "setup, hold",
        [
            (-1, 1),
            (5, 7),
            (7, 8),
        ],
    )
    def test_incorrect_values(self, setup, hold):
        with pytest.raises(ValueError):
            TunnelPriority(setup=setup, hold=hold)

class TestTTunnelAffinity:
    @pytest.mark.parametrize(
        "value, mask",
        [
            ("0x00012300", "0x000FFF00"),
            ("0x00000008", "0x00000008"),
        ],
    )
    def test_correct_values(self, value, mask):
        TunnelAffinity(value=value, mask=mask)

    @pytest.mark.parametrize(
        "value, mask",
        [
            ("0x00012303", "0x000FFF00"),
            ("0x00000008", "0x000G0008"),
        ],
    )
    def test_incorrect_values(self, value, mask):
        with pytest.raises(ValueError):
            TunnelAffinity(value=value, mask=mask)

class TestConfigMplsTeTunnel:
    correct_fast_reroute = FastReroute(enabled=True, node_protect=True)
    correct_path_option = TunnelPathOption(paths=[TunnelPathExplicit(id=1, name="PATH-TO-R4-Primary"), TunnelPathDynamic(id=200)])
    correct_priority = TunnelPriority(setup=6, hold=6)
    correct_affinity = TunnelAffinity(value="0x0000FF00", mask="0x00FFFFFF")

    @pytest.mark.parametrize(
        "tunnel_id, description, ip_source_interface, destination_ip_address, bandwidth, autoroute_announce, exp_values, exp_bundle_master, exp_bundle_member_tunnel_id, path_selection_metric, record_route_enable",
        [
            (10, "Lama Corp LSA 3453", 'Loopback0', '10.0.0.22', 100000, True, [0, 1, 7], False, 5, 'te', True),
            (10, "Mata Corp LSA 999", 'Loopback0', '10.0.0.22', 600000, True, None, True, None, 'te', True),
            (0, "", 'Loopback1', '200.12.2.1', 900000, True, [0, 1, 7], False, 5, 'igp', True),
        ],
    )
    def test_correct_values(self, tunnel_id, description, ip_source_interface, destination_ip_address, bandwidth, autoroute_announce, exp_values, exp_bundle_master, exp_bundle_member_tunnel_id, path_selection_metric, record_route_enable):
        ConfigMplsTeTunnel(tunnel_id=tunnel_id, description=description, ip_source_interface=ip_source_interface, destination_ip_address=destination_ip_address, bandwidth=bandwidth, autoroute_announce=autoroute_announce, exp_values=exp_values, exp_bundle_master=exp_bundle_master, exp_bundle_member_tunnel_id=exp_bundle_member_tunnel_id, path_selection_metric=path_selection_metric, record_route_enable=record_route_enable, affinity=self.correct_affinity, fast_reroute=self.correct_fast_reroute, path_option=self.correct_path_option, priority=self.correct_priority)

    @pytest.mark.parametrize(
        "tunnel_id, description, ip_source_interface, destination_ip_address, bandwidth, autoroute_announce, exp_values, exp_bundle_master, exp_bundle_member_tunnel_id, path_selection_metric, record_route_enable",
        [
            (10, "Mata Corp LSA 999", 'Loopback0', '10.0.0.22', 100000, True, [0, 1, 7], False, 5, 'mpls', True),
            (50, "Mata Corp LSA 999", 'Loopback0', '10.0.0.22', 600000, True, None, True, 5, 'te', True),
            (5, "Mata Corp LSA 999", 'Loopback1', '200.12.2.1', 900000, True, [0, 1, 7], False, 6, 'igp', True),
            (70, "Mata Corp LSA 999", 'Loopback1', '200.12.2.1', 900000, True, [0, 1, 7], False, 16, 'igp', True),
            (80, "Mata Corp LSA 999", 'Loopback1', '250.12.2.1', 900000, True, [0, 1, 7], False, 6, 'igp', True),
            (10, "To long description above 200 characters xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 'Loopback0', '10.0.0.22', 600000, True, None, True, None, 'te', True),
        ],
    )
    def test_incorrect_values(self, tunnel_id, description, ip_source_interface, destination_ip_address, bandwidth, autoroute_announce, exp_values, exp_bundle_master, exp_bundle_member_tunnel_id, path_selection_metric, record_route_enable):
        with pytest.raises(ValueError):
            ConfigMplsTeTunnel(tunnel_id=tunnel_id, description=description, ip_source_interface=ip_source_interface, destination_ip_address=destination_ip_address, bandwidth=bandwidth, autoroute_announce=autoroute_announce, exp_values=exp_values, exp_bundle_master=exp_bundle_master, exp_bundle_member_tunnel_id=exp_bundle_member_tunnel_id, path_selection_metric=path_selection_metric, record_route_enable=record_route_enable, affinity=self.correct_affinity, fast_reroute=self.correct_fast_reroute, path_option=self.correct_path_option, priority=self.correct_priority)

    def test_template(self):
        c = ConfigMplsTeTunnel(tunnel_id=10, description="Mata Corp LSA 999", ip_source_interface='Loopback0', destination_ip_address='10.0.0.22', bandwidth=100, autoroute_announce=True, exp_values=[0, 4], exp_bundle_master=False, exp_bundle_member_tunnel_id=5, path_selection_metric='igp', record_route_enable=True, affinity=self.correct_affinity, fast_reroute=self.correct_fast_reroute, path_option=self.correct_path_option, priority=self.correct_priority)
        c.get_config_netconf()
        c.delete_config_netconf()

    def test_load_from_dict(self):
        c = ConfigMplsTeTunnel(tunnel_id=10, description="Mata Corp LSA 999", ip_source_interface='Loopback0', destination_ip_address='10.0.0.22', bandwidth=100, autoroute_announce=True, exp_values=[0, 4], exp_bundle_master=False, exp_bundle_member_tunnel_id=5, path_selection_metric='igp', record_route_enable=True, affinity=self.correct_affinity, fast_reroute=self.correct_fast_reroute, path_option=self.correct_path_option, priority=self.correct_priority)
        d = c.model_dump()
        c = ConfigMplsTeTunnel(**d)

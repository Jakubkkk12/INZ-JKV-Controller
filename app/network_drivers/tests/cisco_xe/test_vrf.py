from app.network_drivers.cisco_xe.vrf.vrf import VrfRouteTarget, ConfigVrf, VrfMaximumRoutes
import pytest


class TestVrfRouteTarget:
    @pytest.mark.parametrize(
        "export, import_",
        [
            (["3.3.3.3:567", "567:32"], ["34.7.6.3:567", "567:3452"]),
            (None, ["34.7.6.3:567", "567:3452"]),
            (None, None),
        ],
    )
    def test_correct_values(self, export, import_):
        VrfRouteTarget(export=export, import_=import_)

    @pytest.mark.parametrize(
        "export, import_",
        [
            (["3.3.783.3:567", "567:32"], ["34.7.6.3:567", "567:3452"]),
            (["3.3.3.3:5444444", "567:32"], ["-3:567", "567:3452"]),
            (["3.3.3.3:567", "567:32"], ["-3:567", "567:3452"]),
            (["3.3gv.3.3:567", "567:32"], ["34.7.6.3:567", "567:3452"]),
            (["adcf", "567:32"], ["34.7.6.3:567", "567:3452"]),
        ],
    )
    def test_incorrect_values(self, export, import_):
        with pytest.raises(ValueError):
            VrfRouteTarget(export=export, import_=import_)


class TestVrfMaximumRoutes:
    @pytest.mark.parametrize(
        "max_routes, warning_only, warning_threshold, reinstall_threshold",
        [
            (100, False, 80, None),
            (700, False, 90, 95),
            (700, True, None, None),
        ],
    )
    def test_correct_values(self, max_routes, warning_only, warning_threshold, reinstall_threshold):
        VrfMaximumRoutes(max_routes=max_routes, warning_only=warning_only, warning_threshold=warning_threshold, reinstall_threshold=reinstall_threshold)

    @pytest.mark.parametrize(
        "max_routes, warning_only, warning_threshold, reinstall_threshold",
        [
            ("fgt", False, 80, None),
            (0, False, 90, 95),
            (50, False, 90, 120),
            (55, False, 455, None),
            (4294967295, False, 50, None),
            (4294967295, False, None, None),
        ],
    )
    def test_incorrect_values(self, max_routes, warning_only, warning_threshold, reinstall_threshold):
        with pytest.raises(ValueError):
            VrfMaximumRoutes(max_routes=max_routes, warning_only=warning_only, warning_threshold=warning_threshold, reinstall_threshold=reinstall_threshold)


class TestConfigVrf:
    route_target: VrfRouteTarget | None
    name: str | None
    rd: str | None

    def setup_method(self, method):
        self.route_target = VrfRouteTarget(export=["3.3.3.3:567", "567:32"], import_=["34.7.6.3:567", "567:3452"])
        self.name = "Cust-1"
        self.rd = "3.3.3.3:567"
        self.maximum_routes = VrfMaximumRoutes(max_routes=100, warning_only=False, warning_threshold=50, reinstall_threshold=50)

    @pytest.mark.parametrize(
        "name, rd",
        [
            ("Cust_LAMA", "195.245.12.78:4567"),
            ("CMC", "56789:1500"),
        ],
    )
    def test_correct_values(self, name, rd):
        ConfigVrf(name=name, rd=rd, route_target=self.route_target)

    @pytest.mark.parametrize(
        "name, rd",
        [
            (None, None),
            ("TEST-1", "127.0.0.1"),
            (5, "137.0.0.1:567"),
            ("ToLONGmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm", None),
            ("", None),
        ]
    )
    def test_incorrect_values(self, name, rd):
        with pytest.raises(ValueError):
            ConfigVrf(name=name, rd=rd, route_target=self.route_target)

    def test_template(self):
        c = ConfigVrf(name=self.name, rd=self.rd, route_target=self.route_target)
        c.get_config_netconf()
        c.delete_config_netconf()

    def test_load_from_dict(self):
        c = ConfigVrf(name=self.name, rd=self.rd, route_target=self.route_target)
        d = c.model_dump()
        c = ConfigVrf(**d)

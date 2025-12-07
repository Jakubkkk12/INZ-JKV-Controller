from app.network_drivers.cisco_xe.mpls.mpls_te.mpls_te import ConfigMplsTeTunnels
import pytest


class TestConfigMplsTeTunnels:
    @pytest.mark.parametrize(
        "enable",
        [
            (True),
            (False),
            ('true'),
            ("True"),
            (1),
            (0),
        ],
    )
    def test_correct_values(self, enable):
        ConfigMplsTeTunnels(enable=enable)

    @pytest.mark.parametrize(
        "enable",
        [
            ("value1"),
            (None),
            (5),
            (-5),
        ],
    )
    def test_incorrect_values(self, enable):
        with pytest.raises(ValueError):
            ConfigMplsTeTunnels(enable=enable)

    def test_template(self):
        c = ConfigMplsTeTunnels(enable=True)
        c.get_config_netconf()
        c.delete_config_netconf()

    def test_load_from_dict(self):
        c = ConfigMplsTeTunnels(enable=True)
        d = c.model_dump()
        c = ConfigMplsTeTunnels(**d)

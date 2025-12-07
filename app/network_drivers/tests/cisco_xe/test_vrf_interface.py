from app.network_drivers.base_configuration import Interface
from app.network_drivers.cisco_xe.vrf.vrf_interface.vrf_interface import ConfigInterfaceVrf
import pytest


class TestConfigInterfaceVrf:
    correct_interface = Interface(name='GigabitEthernet', id='2')
    correct_vrf_name = "Cust-A"
    correct_ipv4_address = "192.168.123.128"
    correct_ipv4_mask = '255.255.255.0'

    @pytest.mark.parametrize(
        "interface, vrf_name, ipv4_address, ipv4_mask",
        [
            (correct_interface, correct_vrf_name, correct_ipv4_address, correct_ipv4_mask),
            (Interface(name='FastEthernet', id='3'), "Cust-B", "10.10.0.234", '255.255.0.0'),
            (correct_interface, "VRFNAME", "220.0.0.1", '255.255.128.0'),
        ],
    )
    def test_correct_values(self, interface, vrf_name, ipv4_address, ipv4_mask):
        ConfigInterfaceVrf(interface=interface, vrf_name=vrf_name, ipv4_address=ipv4_address, ipv4_mask=ipv4_mask)

    @pytest.mark.parametrize(
        "interface, vrf_name, ipv4_address, ipv4_mask",
        [
            (correct_interface, correct_vrf_name, None, correct_ipv4_mask),
            (correct_interface, correct_vrf_name, correct_ipv4_address, "255.255.255.128"),
            (correct_interface, correct_vrf_name, "correct_ipv4_address", "255.0.0.0"),
            (correct_interface, correct_vrf_name, correct_ipv4_address, "255.zsx.0"),
            (correct_interface, "ToLONGNAMExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", correct_ipv4_address, correct_ipv4_mask),
        ],
    )
    def test_incorrect_values(self, interface, vrf_name, ipv4_address, ipv4_mask):
        with pytest.raises(ValueError):
            ConfigInterfaceVrf(interface=interface, vrf_name=vrf_name, ipv4_address=ipv4_address, ipv4_mask=ipv4_mask)

    def test_template(self):
        c = ConfigInterfaceVrf(interface=self.correct_interface, vrf_name=self.correct_vrf_name, ipv4_address=self.correct_ipv4_address, ipv4_mask=self.correct_ipv4_mask)
        c.get_config_netconf()
        c.delete_config_netconf()

    def test_load_from_dict(self):
        c = ConfigInterfaceVrf(interface=self.correct_interface, vrf_name=self.correct_vrf_name, ipv4_address=self.correct_ipv4_address, ipv4_mask=self.correct_ipv4_mask)
        d = c.model_dump()
        c = ConfigInterfaceVrf(**d)

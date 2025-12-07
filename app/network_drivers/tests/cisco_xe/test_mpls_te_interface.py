from app.network_drivers.base_configuration import Interface
from app.network_drivers.cisco_xe.mpls.mpls_te_interface.mpls_te_interface import ConfigMplsTeInterface
import pytest


class TestConfigMplsTeInterface:
    correct_interface = Interface(name='GigabitEthernet', id='2')
    correct_enable = True
    correct_backup_path_tunnel_id = 1
    correct_attribute_flags = '0xFFFF00FF'
    correct_administrative_weight = 200

    @pytest.mark.parametrize(
        "interface, enable, backup_path_tunnel_id, attribute_flags, administrative_weight",
        [
            (correct_interface, correct_enable, correct_backup_path_tunnel_id, correct_attribute_flags, correct_administrative_weight),
            (Interface(name='FastEthernet', id='3'), False, 100, '0x00000000', 1),
            (correct_interface, correct_enable, 0, '0x00FF0000', 125),
        ],
    )
    def test_correct_values(self, interface, enable, backup_path_tunnel_id, attribute_flags, administrative_weight):
        ConfigMplsTeInterface(interface=interface, enable=enable, backup_path_tunnel_id=backup_path_tunnel_id, attribute_flags=attribute_flags, administrative_weight=administrative_weight)

    @pytest.mark.parametrize(
        "interface, enable, backup_path_tunnel_id, attribute_flags, administrative_weight",
        [
            (None, None, correct_backup_path_tunnel_id, correct_attribute_flags, correct_administrative_weight),
            (Interface(name='FastEthernet', id='3'), False, 100, '0x00ASD0000', 10000),
            (Interface(name='FastEthernet', id='3'), False, 100, '0x00000000', 100000000000000),
            (correct_interface, correct_enable, -10, '0x00FF0000', 125),
            (correct_interface, 'no', 10, '0x000000FF', -125),
            (correct_interface, correct_enable, 10, '0x00FF', 125),
        ],
    )
    def test_incorrect_values(self, interface, enable, backup_path_tunnel_id, attribute_flags, administrative_weight):
        with pytest.raises(ValueError):
            ConfigMplsTeInterface(interface=interface, enable=enable, backup_path_tunnel_id=backup_path_tunnel_id, attribute_flags=attribute_flags, administrative_weight=administrative_weight)

    def test_template(self):
        c = ConfigMplsTeInterface(interface=self.correct_interface, enable=self.correct_enable, backup_path_tunnel_id=self.correct_backup_path_tunnel_id, attribute_flags=self.correct_attribute_flags, administrative_weight=self.correct_administrative_weight)
        c.get_config_netconf()
        c.delete_config_netconf()

    def test_load_from_dict(self):
        c = ConfigMplsTeInterface(interface=self.correct_interface, enable=self.correct_enable, backup_path_tunnel_id=self.correct_backup_path_tunnel_id, attribute_flags=self.correct_attribute_flags, administrative_weight=self.correct_administrative_weight)
        d = c.model_dump()
        c = ConfigMplsTeInterface(**d)

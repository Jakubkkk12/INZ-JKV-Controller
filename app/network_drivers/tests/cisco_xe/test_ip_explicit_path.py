from app.network_drivers.cisco_xe.ip.explicit_path.explicit_path import ConfigIpExplicitPath, IpExplicitPathEntryNextAddress, IpExplicitPathEntryExcludeAddress, IpExplicitPathEntry
import pytest


class TestIpExplicitPathEntry:
    @pytest.mark.parametrize(
        "index, ip_address",
        [
            (1, "10.10.10.100"),
            (45, "195.245.12.78"),
            (65535, "223.56.23.17"),
        ],
    )
    def test_correct_values(self, index, ip_address):
        IpExplicitPathEntry(index=index, ipv4_address=ip_address)

    @pytest.mark.parametrize(
        "index, ip_address",
        [
            ("value1", "value1"),
            (None, None),
            (5, "127.0.0.1"),
            (-5, "167.0.0.1"),
            (1000000, "137.0.0.1"),
            (5, "250.0.23.5"),
            (5, "224.0.0.1"),
            (5, "ae.v.aa.xs"),
            (5, "10.000.0.1"),
            (5, "0.0.0.0"),
            (5, "123.0.0."),
        ],
    )
    def test_incorrect_values(self, index, ip_address):
        with pytest.raises(ValueError):
            IpExplicitPathEntry(index=index, ipv4_address=ip_address)


class TestIpExplicitPathEntryExcludeAddress:
    @pytest.mark.parametrize(
        "index, ip_address",
        [
            (45, "195.245.12.78"),
        ],
    )
    def test_correct_values(self, index, ip_address):
        IpExplicitPathEntryExcludeAddress(index=index, ipv4_address=ip_address)

    @pytest.mark.parametrize(
        "index, ip_address",
        [
            (None, None),
            (5, "127.0.0.1"),
            (1000000, "137.0.0.1"),
            (-5, "ae.v.aa.xs"),
        ],
    )
    def test_incorrect_values(self, index, ip_address):
        with pytest.raises(ValueError):
            IpExplicitPathEntryExcludeAddress(index=index, ipv4_address=ip_address)


class TestIpExplicitPathEntryNextAddress:
    @pytest.mark.parametrize(
        "index, ip_address, loose",
        [
            (45, "195.245.12.78", False),
            (45, "195.245.12.78", True),
            (45, "195.245.12.78", 'false'),
            (45, "195.245.12.78", 'true'),
            (45, "195.245.12.78", 'TRUE'),
        ],
    )
    def test_correct_values(self, index, ip_address, loose):
        IpExplicitPathEntryNextAddress(index=index, ipv4_address=ip_address, loose=loose)

    @pytest.mark.parametrize(
        "index, ip_address, loose",
        [
            (None, None, None),
            (5, "123.0.0.1", 56),
            (1, "137.0.0.1", "trues"),
            (5, "3.3.3.3", -1),
        ],
    )
    def test_incorrect_values(self, index, ip_address, loose):
        with pytest.raises(ValueError):
            IpExplicitPathEntryNextAddress(index=index, ipv4_address=ip_address, loose=loose)


class TestConfigIpExplicitPath:
    path_next_address = [IpExplicitPathEntryNextAddress(index=1, ipv4_address="1.2.3.4", loose=False),
                         IpExplicitPathEntryNextAddress(index=2, ipv4_address="1.2.3.5", loose=False),
                         IpExplicitPathEntryNextAddress(index=3, ipv4_address="1.2.3.6", loose=False)]
    path_exclude_address = [IpExplicitPathEntryExcludeAddress(index=1, ipv4_address="2.3.4.2"),
                            IpExplicitPathEntryExcludeAddress(index=2, ipv4_address="43.56.21.44")]

    def setup_method(self, method):
        self.name = "FOR-TEST-TO-R7"
        self.path_next_address = [IpExplicitPathEntryNextAddress(index=1, ipv4_address="1.2.3.4", loose=False), IpExplicitPathEntryNextAddress(index=2, ipv4_address="1.2.3.5", loose=False), IpExplicitPathEntryNextAddress(index=3, ipv4_address="1.2.3.6", loose=False)]
        self.path_exclude_address = [IpExplicitPathEntryExcludeAddress(index=1, ipv4_address="2.3.4.2"), IpExplicitPathEntryExcludeAddress(index=2, ipv4_address="43.56.21.44")]

    @pytest.mark.parametrize(
        "name",
        [
            ("TASK2"),
            ("PATH-TO-R5"),
        ],
    )
    def test_correct_values(self, name):
        ConfigIpExplicitPath(name=name, path_exclude_address=self.path_exclude_address)
        ConfigIpExplicitPath(name=name, path_next_address=self.path_next_address)

    @pytest.mark.parametrize(
        "name, path_next_address, path_exclude_address",
        [
            (None, None, None),
            ("too_long_name_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", path_next_address, None),
            ("NAME", None, None),
            ("NAME", path_next_address, path_exclude_address),
        ],
    )
    def test_incorrect_values(self, name, path_next_address, path_exclude_address):
        with pytest.raises(ValueError):
            ConfigIpExplicitPath(name=name, path_next_address=path_next_address, path_exclude_address=path_exclude_address)

    def test_template(self):
        c = ConfigIpExplicitPath(name=self.name, path_exclude_address=self.path_exclude_address)
        c.get_config_netconf()
        c.delete_config_netconf()

    def test_load_from_dict(self):
        c = ConfigIpExplicitPath(name=self.name, path_exclude_address=self.path_exclude_address)
        d = c.model_dump()
        c = ConfigIpExplicitPath(**d)

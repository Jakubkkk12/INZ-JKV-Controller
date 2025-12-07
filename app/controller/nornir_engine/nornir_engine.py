import traceback
from nornir import InitNornir
from ncclient import manager
from nornir.core import task
from nornir.core.task import Result
from netmiko import ConnectHandler
from app.heplers.constants import NCCLIENT_PLATFORM, NETCONF_PORT_CONF_KEY, NORNIR_CONFIGURATION_FILE_PATH, \
    NORNIR_LOG_FILE_PATH
from app.heplers.exepctions import GetRunningFailed, NetconfConfigurationRejected
from app.logs.logger import DeveloperLogger


class NornirEngine:
    nr = None
    NETCONF_MANAGER = "netconf_manager"
    NETCONF_LOCK = "netconf_lock"
    ERROR_MESSAGE = ""

    def __init__(self, filter_parameter: dict = None, netconf_payloads: list[str] = None):
        """
        Args:
        filter_parameters (dict): Key value pairs of filter to use for filtering.
        netconf_payloads (list[str]): The list of netconf payloads to use.
        """
        self.nr = InitNornir(config_file=str(NORNIR_CONFIGURATION_FILE_PATH), logging={"log_file": NORNIR_LOG_FILE_PATH, "level": "ERROR"})
        if filter_parameter is not None:
            self.nr = self.nr.filter(**filter_parameter)
        if netconf_payloads is not None:
            self.netconf_payloads = netconf_payloads

    def _get_running_config_netconf(self, task):
        host = {
            "host": task.host.hostname,
            "port": task.host[NETCONF_PORT_CONF_KEY],
            "username": task.host.username,
            "password": task.host.password,
            "hostkey_verify": False,
            "device_params": {"name": task.host[NCCLIENT_PLATFORM]},
            "timeout": 120,
        }
        try:
            with manager.connect(**host) as m:
                data = m.get_config(source="running")
                return data.data_xml
        except Exception:
            raise GetRunningFailed

    def get_running_config(self):
        nr_result = self.nr.run(task=self._get_running_config_netconf)
        running = {}
        for k, v in nr_result.items():
            running[k] = v[0].result
        return running

    def _send_configs_netconf(self, task):
        host = {
            "host": task.host.hostname,
            "port": task.host[NETCONF_PORT_CONF_KEY],
            "username": task.host.username,
            "password": task.host.password,
            "hostkey_verify": False,
            "device_params": {"name": task.host[NCCLIENT_PLATFORM]},
            "timeout": 120,
        }
        try:
            with manager.connect(**host) as m:
                with m.locked(target="candidate"):
                    for netconf_payload in self.netconf_payloads:
                        m.edit_config(netconf_payload, target="candidate")
                    replay = m.validate(source="candidate")
                    if not replay.ok:
                        m.discard_changes()
                        raise NetconfConfigurationRejected
                    m.commit()
        except Exception:
            raise GetRunningFailed

    def send_configs_netconf(self):
        nr_result = self.nr.run(self._send_configs_netconf)
        result = {}
        for k, v in nr_result.items():
            result[k] = v[0].result
        return result

    def _start_wide_transaction_netconf(self, task, configs_per_host_name: dict):
        if task.host.name not in configs_per_host_name.keys():
            return True

        host = {
            "host": task.host.hostname,
            "port": task.host[NETCONF_PORT_CONF_KEY],
            "username": task.host.username,
            "password": task.host.password,
            "hostkey_verify": False,
            "device_params": {"name": task.host[NCCLIENT_PLATFORM]},
            "timeout": 120,
        }
        m = None
        lock = None
        try:
            m = manager.connect(**host)
            lock = m.locked(target="candidate")
            lock.__enter__()

            task.host.data[self.NETCONF_MANAGER] = m
            task.host.data[self.NETCONF_LOCK] = lock

            for netconf_payload in configs_per_host_name[task.host.name]:
                m.edit_config(netconf_payload, target="candidate")

            replay = m.validate(source="candidate")

            if replay.ok:
                return Result(host=task.host, result=True)
            else:
                self.ERROR_MESSAGE = replay.error
                raise Exception
        except Exception:
            if lock:
                try:
                    lock.__exit__(None, None, None)
                except:
                    pass
            if m:
                try:
                    m.close_session()
                except:
                    pass

            task.host.data.pop(self.NETCONF_MANAGER, None)
            task.host.data.pop(self.NETCONF_LOCK, None)
        return Result(host=task.host, result=False)

    def _finish_wide_transaction_netconf(self, task, all_passed: bool):
        lock = task.host.data.pop(self.NETCONF_LOCK, None)
        m = task.host.data.pop(self.NETCONF_MANAGER, None)

        if not m:
            return Result(host=task.host, result=True)

        send_final_rpc = True
        try:
            if all_passed:
                m.commit()
            else:
                m.discard_changes()
        except Exception:
            DeveloperLogger().log_error(f"ncclient cannot commit() or discard_changes(): {traceback.format_exc()}")
            send_final_rpc = False

        try:
            if lock:
                lock.__exit__(None, None, None)
        except Exception:
            pass

        try:
            if m:
                m.close_session()
        except Exception:
            pass

        return Result(host=task.host, result=send_final_rpc)

    def send_configs_wide_transaction_netconf(self, configs_per_host_name: dict):
        result = self.nr.run(task=self._start_wide_transaction_netconf, configs_per_host_name=configs_per_host_name)
        all_passed = True

        for k, v in result.items():
            if not v[0].result:
                all_passed = False
                break

        result = self.nr.run(task=self._finish_wide_transaction_netconf, all_passed=all_passed)
        all_finished = True
        for k, v in result.items():
            if not v[0].result:
                all_finished = False
                break
        if all_passed and all_finished:
            return True
        return False

    def _get_show_command_output(self, task, show_command: str):
        device = {
            "device_type": task.host.platform,
            "host": task.host.hostname,
            "username": task.host.username,
            "password": task.host.password,
            "secret": "password",
        }
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command(show_command)
        connection.disconnect()
        return output

    def get_show_command_output(self, show_command: str):
        nr_result = self.nr.run(task=self._get_show_command_output, show_command=show_command)
        result = {}
        for k, v in nr_result.items():
            result[k] = v[0].result
        return result


# How to use filter_parameter
# filter_parameter: dict[str, str] = {
#     "hostname": "1.1.1.1",
# }
# running = NornirEngine(filter_parameter=filter_parameter).get_running_config()

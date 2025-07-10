from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import socket

class RebooterDiscoveryListener(ServiceListener):
    def __init__(self, on_device_update):
        """
        on_device_update: callback(dict) where dict has keys: ip, port, serial, hostname
        """
        self.on_device_update = on_device_update

    def add_service(self, zeroconf, type_, name):
        info = zeroconf.get_service_info(type_, name)
        if info and name.startswith("Rebooter Pro "):
            device = self._parse_device_info(info, name)
            self.on_device_update(device)

    def update_service(self, zeroconf, type_, name):
        self.add_service(zeroconf, type_, name)

    def remove_service(self, zeroconf, type_, name):
        serial = name.split("._")[0].strip()
        self.on_device_update({"serial": serial, "removed": True})

    def _parse_device_info(self, info, name):
        address = socket.inet_ntoa(info.addresses[0])
        port = info.port
        serial = name.split("._")[0].strip()
        hostname = info.server.rstrip(".")
        return {
            "ip": address,
            "port": port,
            "serial": serial,
            "hostname": hostname,
            "removed": False
        }

class DiscoveryManager:
    def __init__(self, on_device_update):
        self.zeroconf = None
        self.browser = None
        self.listener = RebooterDiscoveryListener(on_device_update)

    def start(self):
        self.zeroconf = Zeroconf()
        self.browser = ServiceBrowser(self.zeroconf, "_https._tcp.local.", self.listener)

    def stop(self):
        if self.zeroconf:
            self.zeroconf.close()
            self.zeroconf = None
            self.browser = None


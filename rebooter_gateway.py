import os
import json
import threading
import http.server
import ssl
from . import rebooter_http_client
from . import rebooter_discovery


def load_config(path="config.json"):
    with open(path, "r") as f:
        return json.load(f)

class RebooterHttpClient:
    def __init__(self, rebooter_host_or_ip, rebooter_port, rebooter_cert_path=None):
        self.rebooter_host_or_ip = rebooter_host_or_ip
        self.rebooter_port = rebooter_port
        self.rebooter_cert_path = rebooter_cert_path

    def post_prov(self, ssid, password, pc_cert_path=None, pc_key_path=None):
        return rebooter_http_client.post_prov(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            ssid=ssid,
            password=password,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )

    def post_notify(self, callback_url, pc_cert_path, pc_key_path, pc_https_port):
        return rebooter_http_client.post_notify(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            callback_url=callback_url,
            callback_port=pc_https_port,
            callback_cert_path=pc_cert_path,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )
    
    def get_config(self, pc_cert_path, pc_key_path):
        return rebooter_http_client.get_config(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )

    def post_config(self, config_dict, pc_cert_path, pc_key_path):
        return rebooter_http_client.post_config(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            config_dict=config_dict,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )
        
    def get_info(self, pc_cert_path, pc_key_path):
        return rebooter_http_client.get_info(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )
        
    def post_info(self, pc_cert_path, pc_key_path):
        return rebooter_http_client.post_info(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )
        
    def get_control(self, pc_cert_path, pc_key_path):
        return rebooter_http_client.get_control(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )

    def post_control(self, command_dict, pc_cert_path, pc_key_path):
        return rebooter_http_client.post_control(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            command_dict=command_dict,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )

    def get_schedules(self, pc_cert_path, pc_key_path):
        return rebooter_http_client.get_schedules(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )

    def post_schedules(self, timezone, schedules, pc_cert_path, pc_key_path):
        return rebooter_http_client.post_schedules(
            rebooter_host_or_ip=self.rebooter_host_or_ip,
            rebooter_port=self.rebooter_port,
            timezone=timezone,
            schedules=schedules,
            rebooter_cert_path=self.rebooter_cert_path,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path
        )



class SimpleNotifyHTTPSHandler(http.server.BaseHTTPRequestHandler):
    notification_callback = None  # NEW

    def do_POST(self):
        if self.path == "/notify":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body)
                if SimpleNotifyHTTPSHandler.notification_callback:
                    SimpleNotifyHTTPSHandler.notification_callback(data)
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid JSON")
                return

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        return  # Suppress default HTTP server logs


class RebooterHttpServer:
    def __init__(self, port, cert_file, key_file, host='0.0.0.0',
                 verify_cert_path=None, notification_callback=None):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.host = host
        self.verify_cert_path = verify_cert_path
        self.notification_callback = notification_callback
        self.thread = None
        self.httpd = None

    def start(self):
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            print("Missing cert.pem or key.pem.")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        context.verify_mode = ssl.CERT_OPTIONAL

        if self.verify_cert_path:
            try:
                context.load_verify_locations(cafile=self.verify_cert_path)
            except Exception as e:
                print(f"Failed to load verify_cert_path: {e}")
                print("Falling back to CERT_NONE (no client verification).")
                context.verify_mode = ssl.CERT_NONE

        SimpleNotifyHTTPSHandler.notification_callback = self.notification_callback
        self.httpd = http.server.HTTPServer((self.host, self.port), SimpleNotifyHTTPSHandler)

        try:
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        except ssl.SSLError as e:
            print(f"SSL handshake failed: {e}")
            return

        def serve():
            print(f"HTTPS server listening on https://{self.host}:{self.port}")
            self.httpd.serve_forever()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()



class RebooterProAPI:
    def __init__(self, cert_path, key_path, port=8443, host='0.0.0.0', verify_cert_path=None, notification_callback=None, discovery_callback=None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.port = port
        self.host = host
        self.verify_cert_path = verify_cert_path
        self.notification_callback = notification_callback
        self.discovery = rebooter_discovery.DiscoveryManager(discovery_callback)
        self.server = None

    def start_discovery(self):
        if self.discovery:
            self.discovery.start()

    def stop_discovery(self):
        if self.discovery:
            self.discovery.stop()

    def start_server(self):
        self.server = RebooterHttpServer(
            port=self.port,
            cert_file=self.cert_path,
            key_file=self.key_path,
            host=self.host,
            verify_cert_path=self.verify_cert_path,
            notification_callback=self.notification_callback
        )
        self.server.start()

    def stop_server(self):
        if self.server:
            self.server.stop()

    def create_client(self, host_or_ip, remote_port=443):
        return RebooterHttpClient(
            rebooter_host_or_ip=host_or_ip,
            rebooter_port=remote_port,
            rebooter_cert_path=self.verify_cert_path
        )


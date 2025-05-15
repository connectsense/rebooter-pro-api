import os
import json
import threading
import http.server
import ssl
from . import rebooter_http_client


def load_config(path="config.json"):
    with open(path, "r") as f:
        return json.load(f)


class RebooterHttpClient:
    def __init__(self, rebooter_host_or_ip, rebooter_port, rebooter_cert_path=None):
        self.rebooter_host_or_ip = rebooter_host_or_ip
        self.rebooter_port = rebooter_port
        self.rebooter_cert_path = rebooter_cert_path

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

class SimpleHTTPSHandler(http.server.BaseHTTPRequestHandler):
    log_callback = None

    def do_POST(self):
        raw_cert = self.connection.getpeercert(binary_form=True)
        print("✅ Received client cert" if raw_cert else "❌ No client cert received")

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        msg = f"\nReceived POST to {self.path}\nBody:\n{body.decode('utf-8')}\n"
        if SimpleHTTPSHandler.log_callback:
            SimpleHTTPSHandler.log_callback(msg)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        return  # Suppress default logging


class RebooterHttpServer:
    def __init__(self, port, cert_file, key_file, host='0.0.0.0', verify_cert_path=None, log_callback=None):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.host = host
        self.verify_cert_path = verify_cert_path
        self.log_callback = log_callback
        self.thread = None
        self.httpd = None

    def start(self):
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            if self.log_callback:
                self.log_callback("Missing cert.pem or key.pem.\n")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        context.verify_mode = ssl.CERT_OPTIONAL

        if self.verify_cert_path:
            try:
                context.load_verify_locations(cafile=self.verify_cert_path)
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"❌ Failed to load verify_cert_path: {e}\n")
                    self.log_callback("⚠️ Falling back to CERT_NONE (no client verification).\n")
                context.verify_mode = ssl.CERT_NONE

        SimpleHTTPSHandler.log_callback = self.log_callback
        self.httpd = http.server.HTTPServer((self.host, self.port), SimpleHTTPSHandler)

        try:
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        except ssl.SSLError as e:
            if self.log_callback:
                self.log_callback(f"❌ SSL handshake failed: {e}\n")
            return

        def serve():
            if self.log_callback:
                self.log_callback(f"HTTPS server listening on https://{self.host}:{self.port}\n")
            self.httpd.serve_forever()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()


class RebooterProAPI:
    def __init__(self, cert_path, key_path, port=8443, host='0.0.0.0', verify_cert_path=None, log_callback=None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.port = port
        self.host = host
        self.verify_cert_path = verify_cert_path
        self.log_callback = log_callback
        self.server = None

    def start_server(self):
        self.server = RebooterHttpServer(
            port=self.port,
            cert_file=self.cert_path,
            key_file=self.key_path,
            host=self.host,
            verify_cert_path=self.verify_cert_path,
            log_callback=self.log_callback
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


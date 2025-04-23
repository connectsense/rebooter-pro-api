#!/usr/bin/env python3
import sys
import socket
import tkinter.scrolledtext as st
from tkinter import *
from tkinter import messagebox
from pathlib import Path
from zeroconf import ServiceBrowser, Zeroconf, ServiceListener
from queue import Queue
from rebooter_pro_api.rebooter_gateway import RebooterProAPI, load_config

# === CONFIG ===
devices = {}
log_queue = Queue()
MAX_LOG_LINES = 1000

def resource_path(relative_path: str) -> Path:
    try:
        base_path = Path(sys._MEIPASS)  # type: ignore
    except AttributeError:
        base_path = Path(__file__).parent.resolve()
    return base_path / relative_path

# === Network helper ===
def get_local_ip_for_target(target_ip_or_host):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((target_ip_or_host, 80))
        return s.getsockname()[0]

# === Zeroconf Service Discovery ===
class MyListener(ServiceListener):
    def __init__(self, listbox):
        self.listbox = listbox

    def _remove_from_listbox(self, serial):
        items = self.listbox.get(0, END)
        for i, item in enumerate(items):
            if item.startswith(serial):
                self.listbox.delete(i)
                break

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info and name.startswith("Rebooter Pro "):
            address = socket.inet_ntoa(info.addresses[0])
            port = info.port
            serial = name.split("._")[0].strip()
            hostname = info.server.rstrip(".")
            label = f"{serial} ({address}:{port}) [{hostname}]"

            devices[serial] = {
                "ip": address,
                "port": port,
                "serial": serial,
                "hostname": hostname
            }

            self._remove_from_listbox(serial)
            self.listbox.insert(END, label)
            log_queue.put(f"Discovered {label}\n")

    def remove_service(self, zeroconf, type, name):
        serial = name.split("._")[0].strip()
        if serial in devices:
            self._remove_from_listbox(serial)
            devices.pop(serial, None)
            log_queue.put(f"Service removed: {serial}\n")

    def update_service(self, zeroconf, service_type, name):
        log_queue.put(f"Service updated: {name}\n")
        self.add_service(zeroconf, service_type, name)


# === Subscribe Action ===
def send_notification_subscription(api, host_or_ip, port, pc_cert_path, pc_key_path, pc_https_port):
    try:
        pc_ip = get_local_ip_for_target(host_or_ip)
        callback_url = f"https://{pc_ip}:{pc_https_port}/notify"
        client = api.create_client(host_or_ip, remote_port=port)
        status, result = client.post_notify(
            callback_url=callback_url,
            pc_cert_path=pc_cert_path,
            pc_key_path=pc_key_path,
            pc_https_port=pc_https_port
        )

        if status == 200:
            log_queue.put(f"✅ Subscribed to notifications from {host_or_ip}\n")
            messagebox.showinfo("Success", f"Subscribed to notifications from {host_or_ip}")
        else:
            log_queue.put(f"⚠️ Subscription failed ({status}): {result}\n")
            messagebox.showerror("Error", f"HTTP {status}: {result}")
    except Exception as e:
        log_queue.put(f"❌ Error sending notification: {e}\n")
        messagebox.showerror("Error", f"Failed to send notification:\n{e}")

def on_subscribe(listbox, api, pc_cert_path, pc_key_path, pc_https_port):
    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Please select a Rebooter device.")
        return
    selected = listbox.get(selection[0])
    device = devices[selected]
    host_or_ip = device.get("hostname") or device["ip"]
    send_notification_subscription(api, host_or_ip, device["port"], pc_cert_path, pc_key_path, pc_https_port)

def on_closing(root, zeroconf, api):
    zeroconf.close()
    api.stop_server()
    root.destroy()
    sys.exit(0)

# === Main GUI ===
def main():
    root = Tk()
    root.title("Rebooter Notifier")

    device_frame = Frame(root)
    device_frame.pack(padx=10, pady=(10, 5), fill=BOTH)

    listbox = Listbox(device_frame, width=80, height=10)
    listbox.pack(side=LEFT, fill=BOTH, expand=True)

    scrollbar = Scrollbar(device_frame, orient=VERTICAL, command=listbox.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    listbox.config(yscrollcommand=scrollbar.set)

    Label(root, text="Console Log").pack()

    console = st.ScrolledText(root, height=12, width=100, state='disabled', wrap=WORD)
    console.configure(font=("Courier", 10))
    console.pack(padx=10, pady=(0, 10), fill=BOTH, expand=True)

    def update_console():
        while not log_queue.empty():
            line = log_queue.get_nowait()
            console.configure(state='normal')
            console.insert(END, line)
            if int(console.index('end-1c').split('.')[0]) > MAX_LOG_LINES:
                console.delete('1.0', '2.0')
            console.see(END)
            console.configure(state='disabled')
        root.after(200, update_console)

    config = load_config(resource_path("config.json"))

    server_cert_path = str(resource_path(config["server_cert_pem"]))
    server_key_path = str(resource_path(config["server_key_pem"]))
    server_host = config.get("server_host", "0.0.0.0")
    server_port = config["server_port"]
    rebooter_cert_path = str(resource_path(config["rebooter_cert_pem"])) if "rebooter_cert_pem" in config else None

    api = RebooterProAPI(
        cert_path=server_cert_path,
        key_path=server_key_path,
        port=server_port,
        host=server_host,
        verify_cert_path=rebooter_cert_path,
        log_callback=log_queue.put
    )
    api.start_server()

    Button(
        root,
        text="Subscribe to Notifications",
        command=lambda: on_subscribe(
            listbox,
            api,
            pc_cert_path=server_cert_path,
            pc_key_path=server_key_path,
            pc_https_port=server_port
        )
    ).pack(pady=5)

    zeroconf = Zeroconf()
    listener = MyListener(listbox)
    ServiceBrowser(zeroconf, "_https._tcp.local.", listener)

    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root, zeroconf, api))
    update_console()
    root.mainloop()

if __name__ == "__main__":
    main()


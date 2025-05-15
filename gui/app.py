#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*found in sys.modules after import.*")
import sys
import socket
import tkinter.scrolledtext as st
from tkinter import *
from tkinter import messagebox
from pathlib import Path
from zeroconf import ServiceBrowser, Zeroconf, ServiceListener
from queue import Queue
from rebooter_pro_api.rebooter_gateway import RebooterProAPI, load_config
from rebooter_pro_api.rebooter_config import parse_config
from PIL import ImageTk, Image

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

    def _remove_all_matching_serial(self, serial):
        items = self.listbox.get(0, END)
        for item in items:
            if item.startswith(serial):
                idx = self.listbox.get(0, END).index(item)
                self.listbox.delete(idx)
                devices.pop(item, None)

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info and name.startswith("Rebooter Pro "):
            address = socket.inet_ntoa(info.addresses[0])
            port = info.port
            serial = name.split("._")[0].strip()
            hostname = info.server.rstrip(".")
            label = f"{serial} ({address}:{port}) [{hostname}]"

            # Remove old entries with the same serial number
            self._remove_all_matching_serial(serial)

            # Store by full label
            devices[label] = {
                "ip": address,
                "port": port,
                "serial": serial,
                "hostname": hostname
            }

            self.listbox.insert(END, label)
            log_queue.put(f"Discovered {label}\n")

    def remove_service(self, zeroconf, type, name):
        serial = name.split("._")[0].strip()
        self._remove_all_matching_serial(serial)
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

# == Rebooter Config Window ===

def set_config_image(image_name):
    global mainimage
    try:
        path = resource_path(f"images/{image_name}")
        img = ImageTk.PhotoImage(Image.open(path))
        mainimage.configure(image=img)
        mainimage.image = img
    except Exception as e:
        print(f"⚠️ Failed to load image {image_name}: {e}")

def timingImage(): return set_config_image("timing.png") or True
def offImage(): return set_config_image("off.png") or True
def odtImage(): return set_config_image("odt.png") or True
def arddImage(): return set_config_image("ardd.png") or True

def refresh_config_fields(listbox, api, pc_cert_path, pc_key_path):
    global enablePowerVar, enablePingVar, offDurVar, triggerTimeVar, detectionDelayVar, rebootAttemptsVal, logicVar
    global url1Var, url2Var, url3Var, url4Var, url5Var, ping_frame

    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Please select a Rebooter device first.")
        return

    selected = listbox.get(selection[0])
    device = devices[selected]
    host_or_ip = device.get("hostname") or device["ip"]

    try:
        client = api.create_client(host_or_ip, remote_port=device["port"])
        status, result = client.get_config(pc_cert_path=pc_cert_path, pc_key_path=pc_key_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch config:\n{e}")
        return

    if status != 200:
        messagebox.showerror("Error", f"Device returned {status}:\n{result}")
        return

    from rebooter_pro_api.rebooter_config import parse_config
    cfg = parse_config(result)

    enablePowerVar.set(1 if cfg["enable_power_fail_reboot"] else 0)
    enablePingVar.set(1 if cfg["enable_ping_fail_reboot"] else 0)
    ping_frame.pack() if cfg["enable_ping_fail_reboot"] else ping_frame.pack_forget()

    offDurVar.delete(0, END)
    offDurVar.insert(0, str(cfg["off_duration"]))

    triggerTimeVar.delete(0, END)
    triggerTimeVar.insert(0, str(cfg["ping_config"]["outage_trigger_time"]))

    detectionDelayVar.delete(0, END)
    detectionDelayVar.insert(0, str(cfg["ping_config"]["detection_delay"]))

    rebootAttemptsVal.delete(0, END)
    rebootAttemptsVal.insert(0, str(cfg["max_auto_reboots"]))

    logicVar.set(0 if cfg["ping_config"]["any_fail_logic"] else 1)

    urls = cfg["ping_config"]["target_addrs"]
    url_vars = [url1Var, url2Var, url3Var, url4Var, url5Var]
    for i, entry in enumerate(url_vars):
        entry.delete(0, END)
        if i < len(urls):
            entry.insert(0, urls[i])

def pingEnableView():
    global enablePingVar, ping_frame
    timingImage()
    if (enablePingVar.get() == 1):
      ping_frame.pack()
    if (enablePingVar.get() == 0):
      ping_frame.pack_forget()

def send_rebooter_config():
    print("Todo Send Rebooter Config")

def launch_rebooter_config_window(root_UI_in, listbox, api, server_cert_path, server_key_path):
    global mainimage
    global ping_frame
    global enablePowerVar, enablePingVar, offDurVar, triggerTimeVar, detectionDelayVar, rebootAttemptsVal, logicVar, url1Var, url2Var, url3Var, url4Var, url5Var
    
    rebooterWindow = Toplevel(root_UI_in)
    rebooterWindow.title("Rebooter Configuration")
    rebooterWindow.geometry("700x750")
    
    Button(rebooterWindow, command=send_rebooter_config, text="Send Config", bg="#008fff").pack()
    
    top_frame = Frame(rebooterWindow)
    top_frame.pack()
    
    mainimage = Label(top_frame)
    mainimage.pack()
    timingImage()
    
    enable_frame = Frame(rebooterWindow)
    enable_frame.pack(pady=10)
    
    
    enablePowerVar = IntVar()
    Checkbutton(enable_frame, text='Enable Power Outage Reboot',variable=enablePowerVar, onvalue=1, offvalue=0).grid(row=0, column=0, sticky="n")
    enablePingVar = IntVar()
    Checkbutton(enable_frame, text='Enable Ping Outage Reboot',variable=enablePingVar, onvalue=1, offvalue=0, command=pingEnableView).grid(row=0, column=1, sticky="n")

    #start common config
    common_frame = Frame(rebooterWindow)
    common_frame.pack()
    Label(common_frame, text="Off Duration (sec)").grid(row=0, column=0, sticky="e")
    offDurVar = Entry(common_frame, width=5, validate="focusin", validatecommand=offImage)
    offDurVar.grid(row=0, column=1, sticky="w")
    
    #start ping related config
    ping_frame = Frame(rebooterWindow)
    ping_frame.pack()
    
    Label(ping_frame, text="Outage Detection Trigger Time (min)").grid(row=0, column=0, sticky="e")
    triggerTimeVar = Entry(ping_frame, width=5, validate="focusin", validatecommand=odtImage)
    triggerTimeVar.grid(row=0, column=1, sticky="w")
    
    Label(ping_frame, text='After Reboot Detection Delay (min)').grid(row=1,column=0,sticky="e")
    detectionDelayVar = Entry(ping_frame, width=5, validate="focusin", validatecommand=arddImage)
    detectionDelayVar.grid(row=1,column=1,sticky="w")
    
    Label(ping_frame, text='Max Reboots Per Outage (0=Forever)').grid(row=2,column=0,sticky="e")
    rebootAttemptsVal = Entry(ping_frame, width=5, validate="focusin", validatecommand=timingImage)
    rebootAttemptsVal.grid(row=2,column=1,sticky="w")
    
    logic_label_frame = LabelFrame(ping_frame, text="Logic")
    logic_label_frame.grid(row=3,column=0,sticky="w")
    logicVar = IntVar()
    Checkbutton(logic_label_frame, text='AND', variable=logicVar, onvalue=1, offvalue=0, command=timingImage).grid(row=0,column=0,sticky="w")
    Label(logic_label_frame, text='ALL URLs failing can trigger a reboot').grid(row=1,column=0,sticky="e")
    Checkbutton(logic_label_frame, text='OR', variable=logicVar, onvalue=0, offvalue=1, command=timingImage).grid(row=2,column=0,sticky="w", pady=(5,0))
    Label(logic_label_frame, text='ANY URL failing can trigger a reboot').grid(row=3,column=0,sticky="e")

    url_label_frame = LabelFrame(ping_frame, text="URLs or IPs to ping")
    url_label_frame.grid(row=4,column=0,sticky="w")
    url1Var = Entry(url_label_frame, width=25, validate="focusin", validatecommand=timingImage)
    url1Var.pack(padx=15)
    url2Var = Entry(url_label_frame, width=25, validate="focusin", validatecommand=timingImage)
    url2Var.pack(padx=15)
    url3Var = Entry(url_label_frame, width=25, validate="focusin", validatecommand=timingImage)
    url3Var.pack(padx=15)
    url4Var = Entry(url_label_frame, width=25, validate="focusin", validatecommand=timingImage)
    url4Var.pack(padx=15)
    url5Var = Entry(url_label_frame, width=25, validate="focusin", validatecommand=timingImage)
    url5Var.pack(padx=15)
    
    refresh_config_fields(listbox, api, server_cert_path, server_key_path)
    
    rebooterWindow.protocol("WM_DELETE_WINDOW", rebooterWindow.destroy)

def openRebooterWindow():
    global rebooterWindow, root_UI, update_job

    if rebooterWindow.winfo_exists():
      try:
        root_UI.after_cancel(update_job)
      except:
        update_job=None
      seconds_since_update=0
      read_rebooter_config()
      timingImage()
      rebooterWindow.deiconify()
      rebooterWindow.grab_set() # only allow usage of this window

  
def closeRebooterWindow():
    global rebooterWindow, root_UI, update_job

    if rebooterWindow.winfo_exists():
      update_job = root_UI.after(1000,update_cb)#update
      rebooterWindow.grab_release() # allow using other windows
      rebooterWindow.withdraw()






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

    Button(
        root,
        text="Configure",
        command=lambda: launch_rebooter_config_window(
            root_UI_in=root,
            listbox=listbox,
            api=api,
            server_cert_path=server_cert_path,
            server_key_path=server_key_path
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


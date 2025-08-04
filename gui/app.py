#!/usr/bin/env python3

__version__ = "1.1.0" # script version

import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*found in sys.modules after import.*")
import sys
import socket
import tkinter.scrolledtext as st
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from pathlib import Path
from queue import Queue
from rebooter_pro_api.rebooter_gateway import RebooterProAPI, load_config
from rebooter_pro_api.rebooter_config import parse_config
from PIL import ImageTk, Image
import json
import webbrowser

import platform
IS_MACOS = platform.system() == "Darwin"

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
            log_queue.put(f"Subscribed to notifications from {host_or_ip}\n")
            messagebox.showinfo("Success", f"Subscribed to notifications from {host_or_ip}")
        else:
            log_queue.put(f"Subscription failed ({status}): {result}\n")
            messagebox.showerror("Error", f"HTTP {status}: {result}")
    except Exception as e:
        log_queue.put(f"Error sending notification: {e}\n")
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

def on_closing(root, api):
    api.stop_server()
    api.stop_discovery()
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
        print(f"Failed to load image {image_name}: {e}")

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

    cfg = parse_config(result)
    log_queue.put(f"Config Received:\n{json.dumps(cfg, indent=2)}\n")

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

def send_rebooter_config(listbox, api, pc_cert_path, pc_key_path):
    global enablePowerVar, enablePingVar, offDurVar, triggerTimeVar, detectionDelayVar, rebootAttemptsVal, logicVar
    global url1Var, url2Var, url3Var, url4Var, url5Var, ping_frame

    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Please select a Rebooter device.")
        return

    selected = listbox.get(selection[0])
    device = devices[selected]
    host_or_ip = device.get("hostname") or device["ip"]

    urls = [entry.get().strip() for entry in [url1Var, url2Var, url3Var, url4Var, url5Var] if entry.get().strip()]

    try:
        config_payload = {
            "off_duration": int(offDurVar.get()),
            "max_auto_reboots": int(rebootAttemptsVal.get()),
            "enable_power_fail_reboot": bool(enablePowerVar.get()),
            "enable_ping_fail_reboot": bool(enablePingVar.get()),
            "ping_config": {
                "any_fail_logic": logicVar.get() == 0,
                "outage_trigger_time": int(triggerTimeVar.get()),
                "detection_delay": int(detectionDelayVar.get()),
                "target_addrs": urls
            }
        }
    except Exception as e:
        messagebox.showerror("Invalid Input", f"Please check that all values are valid integers.\n\n{e}")
        return

    try:
        client = api.create_client(host_or_ip, remote_port=device["port"])
        status, response = client.post_config(config_payload, pc_cert_path=pc_cert_path, pc_key_path=pc_key_path)
        if status == 200:
            messagebox.showinfo("Success", "Configuration sent successfully.")
            log_queue.put(f"Config Sent:\n{json.dumps(config_payload, indent=2)}\n")
            
            cfg = parse_config(response)
            log_queue.put(f"Config Received:\n{json.dumps(cfg, indent=2)}\n")
            
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
        else:
            messagebox.showerror("Error", f"HTTP {status}: {response}")
            log_queue.put(f"Failed to send config ({status}): {response}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send configuration:\n{e}")
        log_queue.put(f"Exception in post_config: {e}\n")

def pingEnableView():
    global enablePingVar, ping_frame
    timingImage()
    if (enablePingVar.get() == 1):
      ping_frame.pack()
    if (enablePingVar.get() == 0):
      ping_frame.pack_forget()


def launch_rebooter_config_window(root_UI_in, listbox, api, server_cert_path, server_key_path):
    global mainimage
    global ping_frame
    global enablePowerVar, enablePingVar, offDurVar, triggerTimeVar, detectionDelayVar, rebootAttemptsVal, logicVar, url1Var, url2Var, url3Var, url4Var, url5Var
    
    rebooterWindow = Toplevel(root_UI_in)
    rebooterWindow.title("Rebooter Configuration")
    rebooterWindow.geometry("700x750")
    
    Button(rebooterWindow, command=lambda: send_rebooter_config(listbox, api, server_cert_path, server_key_path), text="Send Config", **({"bg": "#008fff"} if not IS_MACOS else {})).pack()
    
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
    
    rebooterWindow.grab_set()
    
    refresh_config_fields(listbox, api, server_cert_path, server_key_path)
    
    rebooterWindow.protocol("WM_DELETE_WINDOW", lambda: (rebooterWindow.grab_release(), rebooterWindow.destroy()))


# === Info Window ===
def open_info_window(listbox, api, pc_cert_path, pc_key_path):
    if not listbox.curselection():
        messagebox.showwarning("No selection", "Please select a Rebooter device first.")
        return

    selected = listbox.get(listbox.curselection()[0])
    device = devices[selected]
    host_or_ip = device.get("hostname") or device["ip"]

    try:
        client = api.create_client(host_or_ip, remote_port=device["port"])
        status, info = client.get_info(pc_cert_path, pc_key_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to retrieve info:\n{e}")
        return

    if status != 200:
        messagebox.showerror("Error", f"HTTP {status}: {info}")
        return

    log_queue.put(f"Info Received:\n{json.dumps(info, indent=2)}\n")
    # === Build Info Window ===
    win = Toplevel()
    win.title("Rebooter Info")
    win.geometry("400x250")
    win.grab_set()

    Label(win, text=f"Device: {info.get('device', '?')}").pack(pady=5)
    Label(win, text=f"Firmware Version: {info.get('firmware_version', '?')}").pack(pady=5)
    Label(win, text=f"MAC: {info.get('MAC', '?')}").pack(pady=5)
    Label(win, text=f"OTA Update: {'Available' if info.get('update_available') else 'None'}").pack(pady=5)

    def on_update():
        try:
            status, resp = client.post_info(pc_cert_path, pc_key_path)
            if status == 200 and resp.get("do_update"):
                messagebox.showinfo("OTA Update", "Update started successfully.")
            else:
                messagebox.showerror("OTA Update", f"Failed to start update.\nResponse: {resp}")
        except Exception as e:
            messagebox.showerror("OTA Update Error", str(e))
        win.destroy()

    if info.get("update_available"):
        Button(win, text="Update Firmware", command=on_update, **({"bg": "#ff9800"} if not IS_MACOS else {})).pack(pady=(10, 0))

    Button(win, text="Close", command=win.destroy).pack(pady=10)


# === Control Window ===
def open_control_window(listbox, api, pc_cert_path, pc_key_path):
    if not listbox.curselection():
        messagebox.showwarning("No selection", "Please select a Rebooter device first.")
        return

    selected = listbox.get(listbox.curselection()[0])
    device = devices[selected]
    host_or_ip = device.get("hostname") or device["ip"]

    try:
        client = api.create_client(host_or_ip, remote_port=device["port"])
        status, state = client.get_control(pc_cert_path, pc_key_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to get outlet state:\n{e}")
        return

    if status != 200:
        messagebox.showerror("Error", f"HTTP {status}: {state}")
        return
        
    log_queue.put(f"Outlet State Received:\n{json.dumps(state, indent=2)}\n")

    win = Toplevel()
    win.title("Outlet Control")
    win.geometry("300x200")
    win.grab_set()

    outlet_on = state.get("outlet_active", False)
    outlet_state = BooleanVar(value=outlet_on)

    status_label = Label(win, text=f"Outlet is currently: {'Powered' if outlet_on else 'Not Powered'}")
    status_label.pack(pady=10)

    toggle_button = Button(win)

    def toggle_outlet():
        new_state = not outlet_state.get()
        try:
            cmd = {"outlet_active": new_state}
            status, resp = client.post_control(cmd, pc_cert_path, pc_key_path)
            if status == 200:
                outlet_state.set(new_state)
                status_label.config(text=f"Outlet is currently: {'Powered' if new_state else 'Not Powered'}")
                toggle_button.config(text=f"Turn Outlet {'OFF' if new_state else 'ON'}")
                log_queue.put(f"Outlet State Sent:\n{json.dumps(cmd, indent=2)}\n")
                log_queue.put(f"Outlet State Received:\n{json.dumps(resp, indent=2)}\n")
            else:
                messagebox.showerror("Outlet Error", f"HTTP {status}: {resp}")
        except Exception as e:
            messagebox.showerror("Outlet Error", str(e))

    toggle_button.config(
        text=f"Turn Outlet {'OFF' if outlet_on else 'ON'}",
        command=toggle_outlet
    )
    toggle_button.pack(pady=5)

    def reboot_outlet():
        try:
            cmd = {"outlet_reboot": True}
            status, resp = client.post_control(cmd, pc_cert_path, pc_key_path)
            if status == 200 and resp.get("outlet_reboot"):
                log_queue.put(f"Outlet State Sent:\n{json.dumps(cmd, indent=2)}\n")
                log_queue.put(f"Outlet State Received:\n{json.dumps(resp, indent=2)}\n")
                outlet_rebooting_action(listbox)
                win.destroy()
            else:
                messagebox.showerror("Reboot Failed", f"HTTP {status}: {resp}")
        except Exception as e:
            messagebox.showerror("Reboot Error", str(e))

    Button(win, text="Reboot Device", **({"bg": "#ff4444"} if not IS_MACOS else {}), command=reboot_outlet).pack(pady=10)
    Button(win, text="Close", command=win.destroy).pack(pady=5)

# === Schedules Window ===
def load_joda_timezones(filepath):
    try:
        with open(filepath, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        log_queue.put(f"Failed to load timezones from {filepath}: {e}\n")
        return []

def refresh_schedule_fields(listbox, api, pc_cert_path, pc_key_path, timezone_var, schedule_entries, frame):
    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("No Selection", "Please select a Rebooter device first.")
        return

    device = devices[listbox.get(selection[0])]
    host = device.get("hostname") or device["ip"]
    client = api.create_client(host, remote_port=device["port"])

    try:
        status, data = client.get_schedules(pc_cert_path, pc_key_path)
        log_queue.put(f"Schedules Received:\n{json.dumps(data, indent=2)}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch schedules:\n{e}")
        return

    if status != 200:
        messagebox.showerror("Error", f"GET /schedules failed ({status}):\n{data}")
        return

    timezone_var.set(data.get("timezone", "UTC"))
    schedules = data.get("schedules", [])

    for i in range(10):
        cron_str = schedules[i] if i < len(schedules) else ""
        sv = StringVar(value=cron_str)
        schedule_entries.append(sv)
        entry = Entry(frame, textvariable=sv, width=40)
        entry.grid(row=i, column=1, padx=5, pady=2)
        Button(frame, text="Edit", command=lambda sv=sv: open_cron_editor_popup(sv)).grid(row=i, column=2, padx=5)
        readable = cron_to_readable(cron_str)
        label = Label(frame, text=readable)
        label.grid(row=i, column=0, sticky="w")
        
        # Update label when entry changes
        def make_updater(lbl, var):
            return lambda *_: lbl.config(text=cron_to_readable(var.get()))
        sv.trace_add("write", make_updater(label, sv))


def cron_to_readable(cron_expr):
    try:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return "Invalid cron format"

        minute, hour, _, _, dow = parts

        # Accept wildcard (*) or integer values
        if minute != "*" and not minute.isdigit():
            return "Invalid cron format"
        if hour != "*" and not hour.isdigit():
            return "Invalid cron format"

        dow_names = {
            "*": "Every day",
            "0": "Sunday", "1": "Monday", "2": "Tuesday", "3": "Wednesday",
            "4": "Thursday", "5": "Friday", "6": "Saturday"
        }

        dow_label = dow_names.get(dow, f"Day {dow}")

        if hour == "*":
            time_label = f"every hour at minute {minute}"
            if minute == "*":
                time_label = f"every minute"
        elif minute == "*":
            time_label = f"every minute past hour {hour}"
        else:
            time_label = f"{int(hour)}:{int(minute):02d}"

        return f"{dow_label} at {time_label}"
    except Exception:
        return "Invalid cron format"


def open_cron_editor_popup(string_var):
    popup = Toplevel()
    popup.title("Edit Schedule")
    popup.geometry("250x180")
    popup.grab_set()

    # Dropdown variables
    minute = StringVar()
    hour = StringVar()
    day = StringVar()

    # Cron value parsing
    cron_value = string_var.get().strip()
    parts = cron_value.split()

    # Fallback values
    minute.set("0")
    hour.set("0")
    day.set("Every Day (*)")

    # Reverse map for day
    day_map = {
        "*": "Every Day (*)",
        "0": "Sunday (0)",
        "1": "Monday (1)",
        "2": "Tuesday (2)",
        "3": "Wednesday (3)",
        "4": "Thursday (4)",
        "5": "Friday (5)",
        "6": "Saturday (6)"
    }

    if len(parts) == 5:
        if parts[0].isdigit():
            minute.set(parts[0])
        if parts[1].isdigit():
            hour.set(parts[1])
        if parts[4] in day_map:
            day.set(day_map[parts[4]])

    # Dropdown values
    day_options = list(day_map.values())

    Label(popup, text="Minute:").grid(row=0, column=0, padx=10, pady=(10, 2), sticky="e")
    ttk.Combobox(popup, textvariable=minute, values=[str(i) for i in range(60)], state="readonly", width=13).grid(row=0, column=1, pady=(10, 2), sticky="w")

    Label(popup, text="Hour:").grid(row=1, column=0, padx=10, pady=2, sticky="e")
    ttk.Combobox(popup, textvariable=hour, values=[str(i) for i in range(24)], state="readonly", width=13).grid(row=1, column=1, pady=2, sticky="w")

    Label(popup, text="Day of Week:").grid(row=2, column=0, padx=10, pady=2, sticky="e")
    ttk.Combobox(popup, textvariable=day, values=day_options, state="readonly", width=13).grid(row=2, column=1, pady=2, sticky="w")

    def save_and_close():
        day_code = [k for k, v in day_map.items() if v == day.get()][0]
        cron = f"{minute.get()} {hour.get()} * * {day_code}"
        string_var.set(cron)
        popup.destroy()

    Button(popup, text="Save", command=save_and_close).grid(row=3, column=0, columnspan=2, pady=10)

def open_schedule_window(listbox, api, pc_cert_path, pc_key_path):
    import tkinter as tk
    from tkinter import Toplevel, StringVar, Entry, Label, Button, messagebox
    from tkinter import ttk
    import json

    joda_timezones = load_joda_timezones(resource_path("joda_timezones.txt"))

    # Open popup window
    win = Toplevel()
    win.title("Reboot Schedule Manager")
    win.geometry("600x500")
    win.grab_set()

    Label(win, text="Timezone:").pack(pady=(10, 0))

    timezone_var = StringVar()
    timezone_dropdown = ttk.Combobox(win, textvariable=timezone_var, values=joda_timezones, state="readonly")
    timezone_dropdown.pack(fill="x", padx=5, pady=5)

    schedule_entries = []

    frame = tk.Frame(win)
    frame.pack(pady=10)

    def save_schedules():
        cron_list = [sv.get().strip() for sv in schedule_entries if sv.get().strip()]
        if len(cron_list) > 10:
            messagebox.showerror("Error", "No more than 10 schedules allowed.")
            return
        for cron in cron_list:
            if len(cron.encode("utf-8")) > 64:
                messagebox.showerror("Error", f"Schedule too long: {cron}")
                return

        selection = listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a Rebooter device.")
            return

        device = devices[listbox.get(selection[0])]
        host = device.get("hostname") or device["ip"]
        client = api.create_client(host, remote_port=device["port"])

        try:
            status, resp = client.post_schedules(timezone_var.get(), cron_list, pc_cert_path, pc_key_path)
            if status == 200:
                messagebox.showinfo("Success", "Schedules updated.")
                log_queue.put(f"Schedules Sent:\n{json.dumps(resp, indent=2)}\n")
                win.destroy()
            else:
                messagebox.showerror("Error", f"POST /schedules failed ({status})")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    Button(win, text="Save", command=save_schedules, **({"bg": "#00c853", "fg": "white"} if not IS_MACOS else {})).pack(pady=10)
    Button(win, text="Cancel", command=win.destroy).pack()

    refresh_schedule_fields(
        listbox=listbox,
        api=api,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        timezone_var=timezone_var,
        schedule_entries=schedule_entries,
        frame=frame
    )




# === Main GUI ===
#disable or enable the passed list of buttons based on if a rebooter in the list is selected
def on_device_select(event, listbox, buttons):
    new_state = NORMAL if listbox.curselection() else DISABLED
    for btn in buttons:
        btn.config(state=new_state)

#remove the rebooter from the list if a reboot is happening (we need to stop scanning, remove it, and restart scnning
def delete_device_and_rescan(device_name, listbox):
    global api
    matching_index = None
    matching_label = None

    for i in range(listbox.size()):
        label = listbox.get(i)
        if label.startswith(device_name):
            matching_index = i
            matching_label = label
            break

    if matching_index is None:
        messagebox.showinfo("Not Found", f"No device named {device_name} found in the list.")
        return
    if api:
        api.stop_discovery()

    
    listbox.delete(matching_index)
    devices.pop(matching_label, None)
    listbox.selection_clear(0, END)
    listbox.event_generate("<<ListboxSelect>>")
    
    if api:
        api.start_discovery()
        
    log_queue.put(f"Removed {device_name} from list (due to reboot) and restarted DNS scans\n")

def outlet_rebooting_action(listbox):
    selection = listbox.curselection()
    if not selection:
        messagebox.showinfo("No selection", "No device is selected.")
        return

    index = selection[0]
    label = listbox.get(index)

    # Remove from listbox and devices dict and rescan after 7 seconds (give rebooter pro time to fully go offline before clear)
    print(label[:20])
    listbox.after(7000, lambda: delete_device_and_rescan(label[:20], listbox))

    # Show message window
    info_win = Toplevel()
    info_win.title("Device Rebooting")
    info_win.geometry("400x160")
    info_win.grab_set()
    
    # Frame for message content
    msg_frame = Frame(info_win)
    msg_frame.pack(expand=True, fill=BOTH, padx=10, pady=10)
    
    Label(
        msg_frame,
        text="Rebooter device is rebooting.\n\nIt will reappear once it's back online.",
        wraplength=360,
        justify="center"
    ).pack()
    
    def close_all_aux_windows():
        for window in info_win.winfo_toplevel().winfo_children():
            if isinstance(window, Toplevel):
                window.destroy()
        info_win.destroy()  # Also destroy this window

    # Frame for OK button pinned to the bottom
    btn_frame = Frame(info_win)
    btn_frame.pack(pady=(0, 10))
    Button(btn_frame, text="OK", width=12, **({"bg": "#008fff", "fg": "white"} if not IS_MACOS else {}), command=close_all_aux_windows).pack()
    
def launch_provisioning(api, listbox):
    from tkinter import simpledialog

    def show_wifi_entry():
        def on_entry_win_close():
            if api:
                api.stop_discovery()
            listbox.delete(0, END)
            devices.clear()
            if api:
                api.start_discovery()
            entry_win.destroy()
            
        entry_win = Toplevel()
        entry_win.title("Enter Wi-Fi Credentials")
        entry_win.geometry("300x300")
        entry_win.grab_set()
        entry_win.protocol("WM_DELETE_WINDOW", on_entry_win_close)

        Label(entry_win, text="Wi-Fi SSID:").pack(pady=(10, 2))
        ssid_entry = Entry(entry_win, width=25)
        ssid_entry.pack()

        Label(entry_win, text="Wi-Fi Password:").pack(pady=(10, 2))
        password_entry = Entry(entry_win, width=25, show="*")
        password_entry.pack()

        def submit():
            ssid = ssid_entry.get().strip()
            password = password_entry.get().strip()
            if not ssid:
                messagebox.showerror("Missing SSID", "Please enter a Wi-Fi SSID.")
                return

            client = api.create_client("192.168.250.1", remote_port=443)
            try:
                status, resp = client.post_prov(ssid, password)
                if status == 200:
                    # Ask the user to reconnect their PC
                    messagebox.showinfo(
                        "Provisioning Complete",
                        "Please reconnect your PC to your regular Wi-Fi network,\nthen click OK to continue."
                    )
                else:
                    messagebox.showerror("Error", f"Provisioning failed: {status}\n{resp}\n\nPlease reconnect your PC to your regular Wi-Fi network,\nthen click OK to continue.")
            except Exception as e:
                messagebox.showerror("Error", f"Provisioning error:\n{e}\n\nPlease reconnect your PC to your regular Wi-Fi network,\nthen click OK to continue.")
            on_entry_win_close()

        Button(entry_win, text="Submit", command=submit, **({"bg": "#00c853", "fg": "white"} if not IS_MACOS else {})).pack(pady=10)

        # Instructional text
        instruction_label = Label(entry_win, text="Or open this URL in your browser:", font=("Arial", 10))
        instruction_label.pack(pady=(15, 2))

        # Clickable link
        def open_browser_link(event):
            webbrowser.open("http://192.168.250.1/")

        link_label = Label(entry_win, text="http://192.168.250.1/", fg="blue", cursor="hand2", font=("Arial", 11, "underline"))
        link_label.pack()
        link_label.bind("<Button-1>", open_browser_link)
        

    # First popup for instructions
    popup = Toplevel()
    popup.title("Connect to Device")
    popup.geometry("300x180")
    popup.grab_set()

    Label(
        popup, 
        text="1. Connect your PC to the Rebooter SoftAP.\n(CS-RBTR-XXXXXX)\n"
             "2. Wait for connection to complete.\n"
             "3. Click OK to continue.", 
        justify=LEFT,
        anchor="w").pack(pady=20, fill='x', padx=10)

    Button(popup, text="OK", command=lambda: (popup.destroy(), show_wifi_entry())).pack()



def main():
    global api

    root = Tk()
    root.title("Rebooter Pro Network Tool")

    show_notifications_var = BooleanVar(value=False)
    
    menubar = Menu(root)
    root.config(menu=menubar)

    view_menu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="View", menu=view_menu)
    
    view_menu.add_checkbutton(
        label="Enable Notifications",
        variable=show_notifications_var,
        command=lambda: subscribe_button.pack_forget() if not show_notifications_var.get() else subscribe_button.pack(side=LEFT, padx=5)
    )

    help_menu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)

    def show_about():
        global __version__
        messagebox.showinfo("About Rebooter Pro GUI", f"Rebooter Pro GUI\nVersion {__version__}\n© 2025 Grid Connect")


    help_menu.add_command(label="About", command=show_about)

    device_frame = Frame(root)
    device_frame.pack(padx=10, pady=(10, 5), fill=BOTH)

    device_top_frame = Frame(device_frame)
    device_top_frame.pack(fill=X)
    
    Label(device_top_frame, text="Discovered Devices").pack(side=LEFT)
    
    Button(
        device_top_frame,
        text="Add New Rebooter to Wi-Fi",
        **({"bg": "#ff9800"} if not IS_MACOS else {}),
        command=lambda: launch_provisioning(api, listbox)
    ).pack(side=RIGHT, padx=5)
    
    listbox = Listbox(device_frame, width=80, height=10)
    listbox.bind("<<ListboxSelect>>", lambda e: on_device_select(e, listbox, [config_button, subscribe_button, info_button, control_button, schedule_button]))
    listbox.configure(exportselection=False)
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

    # Https Notification Handler ===
    def handle_notification(data):
        log_queue.put(f"Notification Received:\n{json.dumps(data, indent=2)}\n")
        
        #if it is a reboot notification, delete the device as it will be offline for a bit
        if data.get("code") == 3:
            full_name = data.get("device")
            if full_name:
                match = re.search(r"(\d{7})$", full_name)
                if match:
                    serial_number = match.group(1)
                    device_name = f"Rebooter Pro {serial_number}"
                    listbox.after(15000, lambda: delete_device_and_rescan(device_name, listbox))
                else:
                    log_queue.put(f"Could not extract serial from device name: {full_name}\n")

    # Rebooter Discovery Callback ===
    def on_device_update(device_info):
        serial = device_info.get("serial")
        if not serial:
            return

        # Remove all matching serials from listbox and device map
        items = listbox.get(0, END)
        for item in items:
            if item.startswith(serial):
                idx = listbox.get(0, END).index(item)
                listbox.delete(idx)
                devices.pop(item, None)

            if device_info.get("removed"):
                log_queue.put(f"Service removed: {serial}\n")
                return

        # Format new label
        ip = device_info["ip"]
        port = device_info["port"]
        hostname = device_info["hostname"]
        label = f"{serial} ({ip}:{port}) [{hostname}]"

        # Save new entry
        devices[label] = {
            "ip": ip,
            "port": port,
            "serial": serial,
            "hostname": hostname
        }

        listbox.insert(END, label)
        log_queue.put(f"Discovered {label}\n")

    api = RebooterProAPI(
        cert_path=server_cert_path,
        key_path=server_key_path,
        port=server_port,
        host=server_host,
        verify_cert_path=rebooter_cert_path,
        notification_callback=handle_notification,
        discovery_callback=on_device_update
    )
    api.start_server()

    top_button_frame = Frame(root)
    top_button_frame.pack(pady=5)

    info_button = Button(
        top_button_frame,
        text="Device Info",
        state=DISABLED,
        command=lambda: open_info_window(
            listbox=listbox,
            api=api,
            pc_cert_path=server_cert_path,
            pc_key_path=server_key_path
        )
    )
    info_button.pack(side=LEFT, padx=5)

    subscribe_button = Button(
        top_button_frame,
        text="Subscribe to Notifications",
        state=DISABLED,
        command=lambda: on_subscribe(
            listbox,
            api,
            pc_cert_path=server_cert_path,
            pc_key_path=server_key_path,
            pc_https_port=server_port
        )
    )
    if show_notifications_var.get():
        subscribe_button.pack(side=LEFT, padx=5)

    action_frame = Frame(root)
    action_frame.pack(pady=5)

    control_button = Button(
        action_frame,
        text="Outlet Control",
        state=DISABLED,
        command=lambda: open_control_window(
            listbox=listbox,
            api=api,
            pc_cert_path=server_cert_path,
            pc_key_path=server_key_path
        )
    )
    control_button.pack(side=LEFT, padx=5)

    config_button = Button(
        action_frame,
        text="Device Configuration",
        state=DISABLED,
        command=lambda: launch_rebooter_config_window(
            root_UI_in=root,
            listbox=listbox,
            api=api,
            server_cert_path=server_cert_path,
            server_key_path=server_key_path
        )
    )
    config_button.pack(side=LEFT, padx=5)

    schedule_button = Button(
        action_frame,
        text="Manage Schedules",
        state=DISABLED,
        command=lambda: open_schedule_window(
            listbox=listbox,
            api=api,
            pc_cert_path=server_cert_path,
            pc_key_path=server_key_path
        )
    )
    schedule_button.pack(side=LEFT, padx=5)

    api.start_discovery()
    
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root, api))
    update_console()
    root.mainloop()

if __name__ == "__main__":
    main()


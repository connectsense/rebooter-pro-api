import json
import ssl
import http.client
import ipaddress


def create_ssl_context(rebooter_cert_path=None, pc_cert_path=None, pc_key_path=None, verify=True):
    """
    Creates an SSL context.
    
    - If verify=False, disables all certificate verification.
    - If verify=True and rebooter_cert_path is provided, tries to use it for verification.
      If the file is missing or invalid, falls back to disabling verification.
    - If verify=True and no rebooter_cert_path is provided, disables verification (does not use system trust).
    - If pc_cert_path and pc_key_path are provided, loads them for client authentication.
    Failure to load client cert/key will be logged and ignored.
    """

    if not verify or not rebooter_cert_path:
        # Verification disabled entirely — client certs still allowed
        context = ssl._create_unverified_context()
        if pc_cert_path and pc_key_path:
            try:
                context.load_cert_chain(certfile=pc_cert_path, keyfile=pc_key_path)
            except Exception as e:
                print(f"Failed to load PC cert/key ({pc_cert_path}, {pc_key_path}): {e}")
                print("Continuing without client certificate.")
        return context

    # Create default context with verification enabled
    context = ssl.create_default_context()

    try:
        context.load_verify_locations(cafile=rebooter_cert_path)
    except Exception as e:
        print(f"Could not load rebooter_cert_path ({rebooter_cert_path}): {e}")
        print("Falling back to unverified SSL context.")
        return ssl._create_unverified_context()

    if pc_cert_path and pc_key_path:
        try:
            context.load_cert_chain(certfile=pc_cert_path, keyfile=pc_key_path)
        except Exception as e:
            print(f"Failed to load PC cert/key ({pc_cert_path}, {pc_key_path}): {e}")
            print("Continuing without client certificate.")

    return context


def post_notify(
    rebooter_host_or_ip,
    rebooter_port,
    callback_url,
    callback_port,
    callback_cert_path,
    rebooter_cert_path=None,
    pc_cert_path=None,
    pc_key_path=None
):
    """
    Sends a POST /notify to the Rebooter Pro device.

    - If rebooter_host_or_ip is an IP address, disables TLS certificate validation.
    - If it's a hostname, validates the certificate using rebooter_cert_path (if provided).
    - If pc_cert_path and pc_key_path are provided, uses them for client certificate authentication.
    """

    try:
        ipaddress.ip_address(rebooter_host_or_ip)
        is_ip = True
    except ValueError:
        is_ip = False

    context = create_ssl_context(
        rebooter_cert_path=rebooter_cert_path,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        verify=not is_ip
    )

    with open(callback_cert_path, "r") as f:
        callback_cert = f.read()

    payload = json.dumps({
        "url": callback_url,
        "port": callback_port,
        "cert": callback_cert
    })

    conn = http.client.HTTPSConnection(rebooter_host_or_ip, rebooter_port, context=context)
    conn.request("POST", "/notify", body=payload, headers={
        "Content-Type": "application/json"
    })

    resp = conn.getresponse()
    return resp.status, resp.read().decode()

def get_config(
    rebooter_host_or_ip,
    rebooter_port,
    rebooter_cert_path=None,
    pc_cert_path=None,
    pc_key_path=None
):
    """
    Retrieves the current configuration from the Rebooter Pro device.
    """
    import ssl
    import http.client
    import ipaddress

    try:
        ipaddress.ip_address(rebooter_host_or_ip)
        is_ip = True
    except ValueError:
        is_ip = False

    context = create_ssl_context(
        rebooter_cert_path=rebooter_cert_path,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        verify=not is_ip
    )

    conn = http.client.HTTPSConnection(rebooter_host_or_ip, rebooter_port, context=context)
    conn.request("GET", "/config")

    resp = conn.getresponse()
    raw = resp.read()
    if resp.status == 200:
        return resp.status, json.loads(raw.decode())
    else:
        return resp.status, raw.decode()

def post_config(
    rebooter_host_or_ip,
    rebooter_port,
    config_dict,
    rebooter_cert_path=None,
    pc_cert_path=None,
    pc_key_path=None
):
    import ssl
    import http.client
    import ipaddress

    try:
        ipaddress.ip_address(rebooter_host_or_ip)
        is_ip = True
    except ValueError:
        is_ip = False

    context = create_ssl_context(
        rebooter_cert_path=rebooter_cert_path,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        verify=not is_ip
    )

    payload = json.dumps(config_dict)
    conn = http.client.HTTPSConnection(rebooter_host_or_ip, rebooter_port, context=context)
    conn.request("POST", "/config", body=payload, headers={"Content-Type": "application/json"})
    
    resp = conn.getresponse()
    raw = resp.read()
    if resp.status == 200:
        return resp.status, json.loads(raw.decode())
    else:
        return resp.status, raw.decode()
        
def get_info(
    rebooter_host_or_ip,
    rebooter_port,
    rebooter_cert_path=None,
    pc_cert_path=None,
    pc_key_path=None
):
    context = create_ssl_context(
        rebooter_cert_path=rebooter_cert_path,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        verify=True
    )

    conn = http.client.HTTPSConnection(rebooter_host_or_ip, rebooter_port, context=context)
    conn.request("GET", "/info")
    resp = conn.getresponse()
    raw = resp.read()
    if resp.status == 200:
        return resp.status, json.loads(raw.decode())
    else:
        return resp.status, raw.decode()

def post_info(
    rebooter_host_or_ip,
    rebooter_port,
    pc_cert_path,
    pc_key_path,
    rebooter_cert_path=None
):
    context = create_ssl_context(
        rebooter_cert_path=rebooter_cert_path,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        verify=True
    )

    payload = json.dumps({"do_update": True})
    conn = http.client.HTTPSConnection(rebooter_host_or_ip, rebooter_port, context=context)
    conn.request("POST", "/info", body=payload, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    raw = resp.read()
    if resp.status == 200:
        return resp.status, json.loads(raw.decode())
    else:
        return resp.status, raw.decode()

def get_control(
    rebooter_host_or_ip,
    rebooter_port,
    rebooter_cert_path=None,
    pc_cert_path=None,
    pc_key_path=None
):
    context = create_ssl_context(
        rebooter_cert_path=rebooter_cert_path,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        verify=True
    )

    conn = http.client.HTTPSConnection(rebooter_host_or_ip, rebooter_port, context=context)
    conn.request("GET", "/control")
    resp = conn.getresponse()
    raw = resp.read()
    if resp.status == 200:
        return resp.status, json.loads(raw.decode())
    else:
        return resp.status, raw.decode()


def post_control(
    rebooter_host_or_ip,
    rebooter_port,
    command_dict,
    rebooter_cert_path=None,
    pc_cert_path=None,
    pc_key_path=None
):
    context = create_ssl_context(
        rebooter_cert_path=rebooter_cert_path,
        pc_cert_path=pc_cert_path,
        pc_key_path=pc_key_path,
        verify=True
    )

    payload = json.dumps(command_dict)
    conn = http.client.HTTPSConnection(rebooter_host_or_ip, rebooter_port, context=context)
    conn.request("POST", "/control", body=payload, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    raw = resp.read()
    if resp.status == 200:
        return resp.status, json.loads(raw.decode())
    else:
        return resp.status, raw.decode()


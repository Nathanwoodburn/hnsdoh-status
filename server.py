from collections import defaultdict
from functools import cache, wraps
import json
from flask import (
    Flask,
    make_response,
    redirect,
    request,
    jsonify,
    render_template,
    send_from_directory,
    send_file,
)
import os
import json
import requests
import dns.resolver
import dns.message
import dns.query
import dns.name
import dns.rdatatype
import ssl
import dnslib
import dnslib.dns
import socket
from datetime import datetime
from dateutil import relativedelta
import dotenv
import time
import logging
import signal
import sys
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

dotenv.load_dotenv()

app = Flask(__name__)

# Configure scheduler - use coalescing to prevent missed jobs piling up
scheduler = BackgroundScheduler(daemon=True, job_defaults={'coalesce': True, 'max_instances': 1})

node_names = {
    "18.169.98.42": "Easy HNS",
    "172.233.46.92": "EZ Domains",
    "194.50.5.27": "Nathan.Woodburn/",
    "139.177.195.185": "HNSCanada",
    "172.105.120.203": "EZ Domains",
    "173.233.72.88": "Zorro"
}
node_locations = {
    "18.169.98.42": "England",
    "172.233.46.92": "Netherlands",
    "194.50.5.27": "Australia",
    "139.177.195.185": "Canada",
    "172.105.120.203": "Singapore",
    "173.233.72.88": "United States"
}
nodes = []
manual_nodes = []
last_log = datetime.now() - relativedelta.relativedelta(years=1)

sent_notifications = {}

log_dir = "/data"
if not os.path.exists(log_dir):
    if not os.path.exists("./logs"):
        os.mkdir("./logs")
    log_dir = "./logs"

if not os.path.exists(f"{log_dir}/node_status.json"):
    with open(f"{log_dir}/node_status.json", "w") as file:
        json.dump([], file)

if not os.path.exists(f"{log_dir}/sent_notifications.json"):
    with open(f"{log_dir}/sent_notifications.json", "w") as file:
        json.dump({}, file)
else:
    with open(f"{log_dir}/sent_notifications.json", "r") as file:
        sent_notifications = json.load(file)

if (os.getenv("NODES")):
    manual_nodes = os.getenv("NODES").split(",")

print(f"Log directory: {log_dir}", flush=True)


def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


# Assets routes
@app.route("/assets/<path:path>")
def send_report(path):
    if path.endswith(".json"):
        return send_from_directory(
            "templates/assets", path, mimetype="application/json"
        )

    if os.path.isfile("templates/assets/" + path):
        return send_from_directory("templates/assets", path)

    # Try looking in one of the directories
    filename: str = path.split("/")[-1]
    if (
        filename.endswith(".png")
        or filename.endswith(".jpg")
        or filename.endswith(".jpeg")
        or filename.endswith(".svg")
    ):
        if os.path.isfile("templates/assets/img/" + filename):
            return send_from_directory("templates/assets/img", filename)

    return render_template("404.html"), 404


# region Special routes
@app.route("/favicon.png")
def faviconPNG():
    return send_from_directory("templates/assets/img", "favicon.png")


@app.route("/.well-known/<path:path>")
def wellknown(path):
    req = requests.get(f"https://nathan.woodburn.au/.well-known/{path}")
    return make_response(
        req.content, 200, {"Content-Type": req.headers["Content-Type"]}
    )


# endregion


# region Helper functions
def get_node_list() -> list:
    ips = []
    # Do a DNS lookup
    result: dns.resolver.Answer = dns.resolver.resolve("hnsdoh.com", "A")

    # Print the IP addresses
    for ipval in result:
        ips.append(ipval.to_text())

    # Add manual nodes
    for node in manual_nodes:
        if node not in ips:
            print(f"Adding manual node: {node}", flush=True)
            ips.append(node)
        else:
            print(f"Skipping manual node: {node}", flush=True)
    return ips


# Add retry decorator for network operations
def retry(max_attempts=3, delay_seconds=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            last_error = None
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except (socket.timeout, socket.error, dns.exception.Timeout, requests.exceptions.RequestException) as e:
                    attempts += 1
                    last_error = e
                    logger.warning(f"Attempt {attempts} failed with error: {e} - retrying in {delay_seconds} seconds")
                    if attempts < max_attempts:
                        time.sleep(delay_seconds)
            logger.error(f"All {max_attempts} attempts failed. Last error: {last_error}")
            return False  # Return False as a fallback for checks
        return wrapper
    return decorator


@retry(max_attempts=3, delay_seconds=2)
def check_plain_dns(ip: str) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ip]
    resolver.timeout = 5  # Set a reasonable timeout
    resolver.lifetime = 5  # Total timeout for the query

    try:
        result = resolver.resolve("1.wdbrn", "TXT")
        for txt in result:
            if "Test 1" in txt.to_text():
                return True
        return False
    except dns.resolver.NXDOMAIN:
        logger.info(f"Domain not found for plain DNS check on {ip}")
        return False
    except dns.resolver.NoAnswer:
        logger.info(f"No answer received for plain DNS check on {ip}")
        return False
    except (dns.exception.Timeout, socket.timeout):
        logger.warning(f"Timeout during plain DNS check on {ip}")
        raise  # Re-raise for retry decorator
    except Exception as e:
        logger.error(f"Error during plain DNS check on {ip}: {e}")
        return False


def build_dns_query(domain: str, qtype: str = "A"):
    """
    Constructs a DNS query in binary wire format using dnslib.
    """
    q = dnslib.DNSRecord.question(domain, qtype)
    return q.pack()


@retry(max_attempts=3, delay_seconds=2)
def check_doh(ip: str) -> dict:
    status = False
    server_name = []
    sock = None
    ssock = None
    
    try:
        dns_query = build_dns_query("2.wdbrn", "TXT")
        request = (
            f"POST /dns-query HTTP/1.1\r\n"
            f"Host: hnsdoh.com\r\n"
            "Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(dns_query)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        wireframe_request = request.encode() + dns_query
        
        # Create socket with timeout
        sock = socket.create_connection((ip, 443), timeout=10)
        context = ssl.create_default_context()
        context.check_hostname = False  # Skip hostname verification for IP-based connection
        ssock = context.wrap_socket(sock, server_hostname="hnsdoh.com")

        ssock.settimeout(10)  # Set a timeout for socket operations
        ssock.sendall(wireframe_request)
        
        response_data = b""
        while True:
            try:
                data = ssock.recv(4096)
                if not data:
                    break
                response_data += data
            except socket.timeout:
                logger.warning(f"Socket timeout while receiving data from {ip}")
                if response_data:  # We might have partial data
                    break
                else:
                    raise

        if not response_data:
            logger.warning(f"No data received from {ip}")
            return {"status": status, "server": server_name}

        response_str = response_data.decode("latin-1", errors="replace")
        
        # Check if we have a complete HTTP response with headers and body
        if "\r\n\r\n" not in response_str:
            logger.warning(f"Incomplete HTTP response from {ip}")
            return {"status": status, "server": server_name}
            
        headers, body = response_str.split("\r\n\r\n", 1)

        # Try to get server from headers
        for header in headers.split("\r\n"):
            if header.lower().startswith("server:"):
                server_name.append(header.split(":", 1)[1].strip())

        try:
            dns_response = dnslib.DNSRecord.parse(body.encode("latin-1"))
            for rr in dns_response.rr:
                if "Test 2" in str(rr):
                    status = True
                    break
        except Exception as e:
            logger.error(f"Error parsing DNS response from {ip}: {e}")

    except (socket.timeout, socket.error) as e:
        logger.warning(f"Socket error during DoH check on {ip}: {e}")
        raise  # Re-raise for retry decorator
    except ssl.SSLError as e:
        logger.error(f"SSL error during DoH check on {ip}: {e}")
        return {"status": False, "server": server_name}
    except Exception as e:
        logger.error(f"Unexpected error during DoH check on {ip}: {e}")
        return {"status": False, "server": server_name}
    finally:
        # Ensure sockets are always closed
        if ssock:
            try:
                ssock.close()
            except:
                pass
        if sock and sock != ssock:
            try:
                sock.close()
            except:
                pass
                
    return {"status": status, "server": server_name}


@retry(max_attempts=3, delay_seconds=2)
def check_dot(ip: str) -> bool:
    qname = dns.name.from_text("3.wdbrn")
    q = dns.message.make_query(qname, dns.rdatatype.TXT)
    try:
        response = dns.query.tls(
            q, ip, timeout=5, port=853, server_hostname="hnsdoh.com"
        )
        if response.rcode() == dns.rcode.NOERROR:
            for rrset in response.answer:
                for rr in rrset:
                    if "Test 3" in rr.to_text():
                        return True
        return False
    except dns.exception.Timeout:
        logger.warning(f"Timeout during DoT check on {ip}")
        raise  # Re-raise for retry decorator
    except ssl.SSLError as e:
        logger.error(f"SSL error during DoT check on {ip}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error during DoT check on {ip}: {e}")
        return False


@retry(max_attempts=3, delay_seconds=2)
def verify_cert(ip: str, port: int) -> dict:
    expires = "ERROR"
    valid = False
    expiry_date_str = (datetime.now() - relativedelta.relativedelta(years=1)).strftime("%b %d %H:%M:%S %Y GMT")
    sock = None
    ssock = None
    
    try:
        sock = socket.create_connection((ip, port), timeout=10)
        # Wrap the socket in SSL/TLS
        context = ssl.create_default_context()
        context.check_hostname = False  # Skip hostname verification for IP-based connection
        ssock = context.wrap_socket(sock, server_hostname="hnsdoh.com")
        ssock.settimeout(10)  # Set timeout for socket operations
    
        # Retrieve the server's certificate
        cert = ssock.getpeercert()
        if not cert:
            logger.error(f"No certificate returned from {ip}:{port}")
            return {"valid": False, "expires": "ERROR", "expiry_date": expiry_date_str}

        # Extract the expiry date from the certificate
        if "notAfter" not in cert:
            logger.error(f"Certificate from {ip}:{port} missing notAfter field")
            return {"valid": False, "expires": "ERROR", "expiry_date": expiry_date_str}
            
        expiry_date_str = cert["notAfter"]

        # Convert the expiry date string to a datetime object
        expiry_date = datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y GMT")
        expires = format_relative_time(expiry_date)
        valid = expiry_date > datetime.now()
        
    except (socket.timeout, socket.error) as e:
        logger.warning(f"Socket error during certificate check on {ip}:{port}: {e}")
        raise  # Re-raise for retry decorator
    except ssl.SSLError as e:
        logger.error(f"SSL error during certificate check on {ip}:{port}: {e}")
        return {"valid": False, "expires": "ERROR", "expiry_date": expiry_date_str}
    except Exception as e:
        logger.error(f"Error during certificate check on {ip}:{port}: {e}")
        return {"valid": False, "expires": "ERROR", "expiry_date": expiry_date_str}
    finally:
        # Ensure sockets are always closed
        if ssock:
            try:
                ssock.close()
            except:
                pass
        if sock and sock != ssock:
            try:
                sock.close()
            except:
                pass
                
    return {"valid": valid, "expires": expires, "expiry_date": expiry_date_str}


def format_relative_time(expiry_date: datetime) -> str:
    now = datetime.now()
    delta = expiry_date - now

    if delta.days > 0:
        return f"in {delta.days} days" if delta.days > 1 else "in 1 day"
    elif delta.days < 0:
        return f"{-delta.days} days ago" if -delta.days > 1 else "1 day ago"
    elif delta.seconds >= 3600:
        hours = delta.seconds // 3600
        return f"in {hours} hours" if hours > 1 else "in 1 hour"
    elif delta.seconds >= 60:
        minutes = delta.seconds // 60
        return f"in {minutes} minutes" if minutes > 1 else "in 1 minute"
    else:
        return f"in {delta.seconds} seconds" if delta.seconds > 1 else "in 1 second"


def format_last_check(last_log: datetime) -> str:
    now = datetime.now()
    delta = now - last_log

    if delta.days > 0:
        return f"{delta.days} days ago" if delta.days > 1 else "1 day ago"
    elif delta.days < 0:
        return f"in {-delta.days} days" if -delta.days > 1 else "in 1 day"
    elif delta.seconds >= 3600:
        hours = delta.seconds // 3600
        return f"{hours} hours ago" if hours > 1 else "1 hour ago"
    elif delta.seconds >= 60:
        minutes = delta.seconds // 60
        return f"{minutes} minutes ago" if minutes > 1 else "1 minute ago"
    else:
        return "less than a minute ago"


def check_nodes() -> list:
    global nodes
    if last_log > datetime.now() - relativedelta.relativedelta(minutes=1):
        # Load the last log
        with open(f"{log_dir}/node_status.json", "r") as file:
            data = json.load(file)
        newest = {
            "date": datetime.now() - relativedelta.relativedelta(years=1),
            "nodes": [],
        }
        for entry in data:
            if datetime.strptime(entry["date"], "%Y-%m-%d %H:%M:%S") > newest["date"]:
                newest = entry
                newest["date"] = datetime.strptime(newest["date"], "%Y-%m-%d %H:%M:%S")
        node_status = newest["nodes"]
    else:
        if len(nodes) == 0:
            nodes = get_node_list()
            
        node_status = []
        for ip in nodes:
            logger.info(f"Checking node {ip}")
            try:
                plain_dns_result = check_plain_dns(ip)
                doh_check = check_doh(ip)
                dot_result = check_dot(ip)
                cert_result = verify_cert(ip, 443)
                cert_853_result = verify_cert(ip, 853)
                
                node_status.append(
                    {
                        "ip": ip,
                        "name": node_names[ip] if ip in node_names else ip,
                        "location": (
                            node_locations[ip] if ip in node_locations else "Unknown"
                        ),
                        "plain_dns": plain_dns_result,
                        "doh": doh_check["status"],
                        "doh_server": doh_check["server"],
                        "dot": dot_result,
                        "cert": cert_result,
                        "cert_853": cert_853_result,
                    }
                )
                logger.info(f"Node {ip} check complete")
            except Exception as e:
                logger.error(f"Error checking node {ip}: {e}")
                # Add a failed entry for this node to ensure it's still included
                node_status.append(
                    {
                        "ip": ip,
                        "name": node_names[ip] if ip in node_names else ip,
                        "location": (
                            node_locations[ip] if ip in node_locations else "Unknown"
                        ),
                        "plain_dns": False,
                        "doh": False,
                        "doh_server": [],
                        "dot": False,
                        "cert": {"valid": False, "expires": "ERROR", "expiry_date": "ERROR"},
                        "cert_853": {"valid": False, "expires": "ERROR", "expiry_date": "ERROR"},
                    }
                )
                
        # Save the node status to a file
        log_status(node_status)
    logger.info("Finished checking nodes")

    # Send notifications if any nodes are down
    for node in node_status:
        if (
            not node["plain_dns"]
            or not node["doh"]
            or not node["dot"]
            or not node["cert"]["valid"]
            or not node["cert_853"]["valid"]
        ):
            send_down_notification(node)
            continue
        # Check if cert is expiring in 7 days
        try:
            cert_expiry = datetime.strptime(
                node["cert"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
            )
            if cert_expiry < datetime.now() + relativedelta.relativedelta(days=7):
                send_down_notification(node)
                continue
                
            cert_853_expiry = datetime.strptime(
                node["cert_853"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
            )
            if cert_853_expiry < datetime.now() + relativedelta.relativedelta(days=7):
                send_down_notification(node)
        except Exception as e:
            logger.error(f"Error processing certificate expiry for {node['ip']}: {e}")
    
    return node_status


def check_nodes_from_log() -> list:
    global last_log
    # Load the last log
    try:
        with open(f"{log_dir}/node_status.json", "r") as file:
            data = json.load(file)
        
        newest = {
            "date": datetime.now() - relativedelta.relativedelta(years=1),
            "nodes": [],
        }
        
        for entry in data:
            if datetime.strptime(entry["date"], "%Y-%m-%d %H:%M:%S") > newest["date"]:
                newest = entry
                newest["date"] = datetime.strptime(newest["date"], "%Y-%m-%d %H:%M:%S")
        
        node_status = newest["nodes"]
        
        # Get check staleness threshold from environment variable or use default (15 minutes)
        staleness_threshold_str = os.getenv("STALENESS_THRESHOLD_MINUTES", "15")
        try:
            staleness_threshold = int(staleness_threshold_str)
        except ValueError:
            logger.warning(f"Invalid STALENESS_THRESHOLD_MINUTES value: {staleness_threshold_str}, using default of 15")
            staleness_threshold = 15
        
        if datetime.now() > newest["date"] + relativedelta.relativedelta(minutes=staleness_threshold):
            logger.warning(f"Data is stale (older than {staleness_threshold} minutes), triggering immediate check")
            node_status = check_nodes()
        else:
            last_log = newest["date"]
            logger.info(f"Using cached node status from {format_last_check(last_log)}")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error reading node status file: {e}")
        logger.info("Running initial node check")
        node_status = check_nodes()
    
    return node_status


def send_notification(title, description, author):
    discord_hook = os.getenv("DISCORD_HOOK")
    if discord_hook:
        data = {
            "content": "",
            "embeds": [
                {
                    "title": title,
                    "description": description,
                    "url": "https://status.hnsdoh.com",
                    "color": 5814783,
                    "author": {
                        "name": author,
                        "icon_url": "https://status.hnsdoh.com/favicon.png",
                    },
                }
            ],
            "username": "HNSDoH",
            "avatar_url": "https://status.hnsdoh.com/favicon.png",
            "attachments": [],
        }
        response = requests.post(discord_hook, json=data)
        print("Sent notification", flush=True)
    else:
        print("No discord hook", flush=True)


def send_down_notification(node):
    global sent_notifications

    # Check if a notification has already been sent
    if node["ip"] not in sent_notifications:
        sent_notifications[node["ip"]] = datetime.strftime(
            datetime.now(), "%Y-%m-%d %H:%M:%S"
        )
    else:
        last_send = datetime.strptime(
            sent_notifications[node["ip"]], "%Y-%m-%d %H:%M:%S"
        )

        if last_send > datetime.now() - relativedelta.relativedelta(hours=1):
            print(
                f"Notification already sent for {node['name']} in the last hr",
                flush=True,
            )
            return

        # Only send certain notifications once per day
        if node["plain_dns"] and node["doh"] and node["dot"]:
            if last_send > datetime.now() - relativedelta.relativedelta(days=1):
                print(
                    f"Notification already sent for {node['name']} in the last day",
                    flush=True,
                )
                return

    # Save the notification to the file
    sent_notifications[node["ip"]] = datetime.strftime(
        datetime.now(), "%Y-%m-%d %H:%M:%S"
    )
    with open(f"{log_dir}/sent_notifications.json", "w") as file:
        json.dump(sent_notifications, file, indent=4)

    title = f"{node['name']} is down"

    description = f"{node['name']} ({node['ip']}) is down with the following issues:\n"
    if not node["plain_dns"]:
        description += "- Plain DNS is down\n"
    if not node["doh"]:
        description += "- DoH is down\n"
    if not node["dot"]:
        description += "- DoT is down\n"
    if not node["cert"]["valid"]:
        description += "- Certificate on port 443 is invalid\n"
    if not node["cert_853"]["valid"]:
        description += "- Certificate on port 853 is invalid\n"

    if node["plain_dns"] and node["doh"] and node["dot"]:
        if node["cert"]["valid"] and node["cert_853"]["valid"]:
            description = f"The certificate on {node['name']} ({node['ip']}) is expiring soon\n"
            title = f"{node['name']} certificate is expiring soon"
        # Also add the expiry date of the certificates
        description += "\nCertificate expiry dates:\n"
        description += f"- Certificate on port 443 expires {node['cert']['expires']}\n"
        description += f"- Certificate on port 853 expires {node['cert_853']['expires']}\n"
    send_notification(title, description, node["name"])


# endregion

# region File logs


def log_status(node_status: list):
    global last_log
    last_log = datetime.now()
    # Check if the file exists
    filename = f"{log_dir}/node_status.json"
    if os.path.isfile(filename):
        with open(filename, "r") as file:
            data = json.load(file)
    else:
        data = []

    # Get oldest date
    oldest = datetime.now()
    newest = datetime.now() - relativedelta.relativedelta(years=1)
    for entry in data:
        date = datetime.strptime(entry["date"], "%Y-%m-%d %H:%M:%S")
        if date < oldest:
            oldest = date
        if date > newest:
            newest = date

    # If the oldest date is more than 7 days ago, save the file and create a new one
    if (datetime.now() - oldest).days > 7:
        # Copy the file to a new one
        new_filename = f"{log_dir}/node_status_{newest.strftime('%Y-%m-%d')}.json"
        os.rename(filename, new_filename)
        data = []

    # Add the new entry
    data.append(
        {"date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "nodes": node_status}
    )

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)
    print("Logged status", flush=True)


# endregion
# region History functions
def get_history(days: int) -> list:
    log_files = [
        f
        for f in os.listdir(log_dir)
        if f.endswith(".json") and f.startswith("node_status")
    ]
    history = []

    for log_file in log_files:
        file_path = os.path.join(log_dir, log_file)
        with open(file_path, "r") as file:
            data = json.load(file)
            for entry in data:
                entry_date = datetime.strptime(entry["date"], "%Y-%m-%d %H:%M:%S")
                if datetime.now() - relativedelta.relativedelta(days=days) < entry_date:
                    history.append(entry)
    return history


def summarize_history(history: list) -> dict:
    nodes_status = defaultdict(
        lambda: {
            "name": "",
            "location": "",
            "ip": "",
            "plain_dns": {"last_down": "Never", "percentage": 0},
            "doh": {"last_down": "Never", "percentage": 0},
            "dot": {"last_down": "Never", "percentage": 0},
        }
    )
    overall_status = {
        "plain_dns": {"last_down": "Never", "percentage": 0},
        "doh": {"last_down": "Never", "percentage": 0},
        "dot": {"last_down": "Never", "percentage": 0},
    }

    # Collect data
    total_counts = defaultdict(
        lambda: {
            "plain_dns": {"down": 0, "total": 0},
            "doh": {"down": 0, "total": 0},
            "dot": {"down": 0, "total": 0},
        }
    )

    for entry in history:
        date = datetime.strptime(entry["date"], "%Y-%m-%d %H:%M:%S")
        for node in entry["nodes"]:
            ip = node["ip"]
            # Update node details if not already present
            if nodes_status[ip]["name"] == "":
                nodes_status[ip]["name"] = node.get("name", "")
                nodes_status[ip]["location"] = node.get("location", "")
                nodes_status[ip]["ip"] = ip

            # Update counts and last downtime
            for key in ["plain_dns", "doh", "dot"]:
                status = node.get(key, "up")
                if status == False:
                    total_counts[ip][key]["down"] += 1
                total_counts[ip][key]["total"] += 1

            # Update last downtime for each key
            for key in ["plain_dns", "doh", "dot"]:
                if node.get(key) == False:
                    # Check if the last downtime is more recent
                    if nodes_status[ip][key]["last_down"] == "Never":
                        nodes_status[ip][key]["last_down"] = date.strftime("%Y-%m-%d %H:%M:%S")
                    elif date > datetime.strptime(nodes_status[ip][key]["last_down"], "%Y-%m-%d %H:%M:%S"):
                        nodes_status[ip][key]["last_down"] = date.strftime("%Y-%m-%d %H:%M:%S")

    # Calculate percentages and prepare final summary
    node_list = []
    for ip, status in nodes_status.items():
        node_data = status.copy()
        for key in ["plain_dns", "doh", "dot"]:
            total = total_counts[ip][key]["total"]
            down = total_counts[ip][key]["down"]
            if total > 0:
                node_data[key]["percentage"] = ((total - down) / total) * 100
                # Round to 2 decimal places
                node_data[key]["percentage"] = round(node_data[key]["percentage"], 2)
            else:
                node_data[key]["percentage"] = 100
        node_list.append(node_data)

    # Aggregate overall status
    overall_counts = {
        "plain_dns": {"down": 0, "total": 0},
        "doh": {"down": 0, "total": 0},
        "dot": {"down": 0, "total": 0},
    }
    for ip, counts in total_counts.items():
        for key in ["plain_dns", "doh", "dot"]:
            overall_counts[key]["total"] += counts[key]["total"]
            overall_counts[key]["down"] += counts[key]["down"]

    for key in ["plain_dns", "doh", "dot"]:
        total = overall_counts[key]["total"]
        down = overall_counts[key]["down"]
        if total > 0:
            overall_status[key]["percentage"] = ((total - down) / total) * 100
            # Round to 2 decimal places
            overall_status[key]["percentage"] = round(overall_status[key]["percentage"], 2)
            last_downs = [
                nodes_status[ip][key]["last_down"]
                for ip in nodes_status
                if nodes_status[ip][key]["last_down"] != "Never"
            ]
            if last_downs:
                overall_status[key]["last_down"] = max(last_downs)
        else:
            overall_status[key]["percentage"] = 100

    return {"nodes": node_list, "overall": overall_status, "check_counts": total_counts}


def convert_nodes_to_dict(nodes):
    nodes_dict = {}
    for node in nodes:
        ip = node.get("ip")
        if ip:
            nodes_dict[ip] = node
    return nodes_dict


# endregion


# region API routes
@app.route("/api")
def api_index():
    agent = request.headers.get("User-Agent")
    # Check if the request is not from a browser
    nonBrowser = ["curl", "Postman", "Insomnia", "httpie", "wget", "python-requests"]

    endpoints = [
        {"route": "/api/nodes", "description": "Get the current status of all nodes"},
        {
            "route": "/api/history",
            "description": "Get a summary of the last x days of node status",
            "parameters": [
                {
                    "name": "days",
                    "type": "int",
                    "description": "Number of days to get the history for",
                }
            ],
        },
        {
            "route": "/api/history/<int:days>",
            "description": "Get a summary of the last x days of node status",
        },
        {
            "route": "/api/full",
            "description": "Get the full history of node status for the last x days",
            "parameters": [
                {
                    "name": "days",
                    "type": "int",
                    "description": "Number of days to get the history for",
                }
            ],
        },
        {"route": "/api/refresh", "description": "Force a status check of all nodes"},
        {
            "route": "/api/latest",
            "description": "Get the latest status of all nodes",
        }
    ]

    if any(agent.lower().find(x) != -1 for x in nonBrowser):
        print("API request", flush=True)
        return jsonify({"status": "ok", "endpoints": endpoints})

    else:
        # Redirect to the main page
        return render_template("api.html",endpoints=endpoints)


@app.route("/api/nodes")
def api_nodes():
    node_status = check_nodes_from_log()
    return jsonify(node_status)


@app.route("/api/history")
def api_history():
    history_days = 7
    if "days" in request.args:
        try:
            history_days = int(request.args["days"])
        except:
            pass
    history = get_history(history_days)
    history_summary = summarize_history(history)
    return jsonify(history_summary)


@app.route("/api/history/<int:days>")
def api_history_days(days: int):
    history = get_history(days)
    history_summary = summarize_history(history)
    return jsonify(history_summary)


@app.route("/api/full")
def api_all():
    history_days = 7
    if "history" in request.args:
        try:
            history_days = int(request.args["history"])
        except:
            pass
    if "days" in request.args:
        try:
            history_days = int(request.args["days"])
        except:
            pass
    history = get_history(history_days)
    return jsonify(history)


@app.route("/api/refresh")
def api_refresh():
    node_status = check_nodes()
    return jsonify(node_status)

@app.route("/api/latest")
def api_errors():
    node_status = check_nodes_from_log()

    alerts = []
    warnings = []
    for node in node_status:
        node["class"] = "normal"
        if not node["plain_dns"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} does not support plain DNS")

        if not node["doh"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} does not support DoH")

        if not node["dot"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} does not support DoT")

        if not node["cert"]["valid"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} has an invalid certificate")

        if not node["cert_853"]["valid"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} has an invalid certificate on port 853")

        cert_expiry = datetime.strptime(
            node["cert"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
        )
        if cert_expiry < datetime.now():
            node["class"] = "error"
            alerts.append(f"The {node['name']} node's certificate has expired")
            continue
        elif cert_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            node["class"] = "warning"
            warnings.append(
                f"The {node['name']} node's certificate is expiring {format_relative_time(cert_expiry)}"
            )
            continue
        cert_853_expiry = datetime.strptime(
            node["cert_853"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
        )
        if cert_853_expiry < datetime.now():
            node["class"] = "error"
            alerts.append(
                f"The {node['name']} node's certificate has expired for DNS over TLS (port 853)"
            )
            continue
        elif cert_853_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            node["class"] = "warning"
            warnings.append(
                f"The {node['name']} node's certificate is expiring {format_relative_time(cert_853_expiry)} for DNS over TLS (port 853)"
            )

    last_check = format_last_check(last_log)

    # Convert alerts and warnings to a string
    alert_string = ""
    for alert in alerts:
        alert_string += f"{alert}\n"
    warning_string = ""
    for warning in warnings:
        warning_string += f"{warning}\n"

    status_string = f"Warnings: {len(warnings)} | Alerts: {len(alerts)}"
    if (len(alerts) == 0) and (len(warnings) == 0):
        status_string = "HNSDoH is up and running!"

    # Get nodes down
    nodes = len(node_status)
    down_nodes = 0
    for node in node_status:
        if not node["plain_dns"]:
            down_nodes += 1
            continue
        if not node["doh"]:
            down_nodes += 1
            continue
        if not node["dot"]:
            down_nodes += 1
            continue
        if not node["cert"]["valid"]:
            down_nodes += 1
            continue
        if not node["cert_853"]["valid"]:
            down_nodes += 1

    return jsonify({
        "warnings": warnings,
        "warnings_string": warning_string,
        "alerts": alerts,
        "alerts_string": alert_string,
        "last_check": last_check,
        "status_string": status_string,
        "up": nodes - down_nodes,
        "down": down_nodes,
        "total": nodes,
    })


# endregion


# region Main routes
@app.route("/")
def index():
    node_status = check_nodes_from_log()

    alerts = []
    warnings = []
    for node in node_status:
        node["class"] = "normal"
        if not node["plain_dns"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} does not support plain DNS")

        if not node["doh"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} does not support DoH")

        if not node["dot"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} does not support DoT")

        if not node["cert"]["valid"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} has an invalid certificate")

        if not node["cert_853"]["valid"]:
            node["class"] = "error"
            alerts.append(f"{node['name']} has an invalid certificate on port 853")

        cert_expiry = datetime.strptime(
            node["cert"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
        )
        if cert_expiry < datetime.now():
            node["class"] = "error"
            alerts.append(f"The {node['name']} node's certificate has expired")
            continue
        elif cert_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            node["class"] = "warning"
            warnings.append(
                f"The {node['name']} node's certificate is expiring {format_relative_time(cert_expiry)}"
            )
            continue
        cert_853_expiry = datetime.strptime(
            node["cert_853"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
        )
        if cert_853_expiry < datetime.now():
            node["class"] = "error"
            alerts.append(
                f"The {node['name']} node's certificate has expired for DNS over TLS (port 853)"
            )
            continue
        elif cert_853_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            node["class"] = "warning"
            warnings.append(
                f"The {node['name']} node's certificate is expiring {format_relative_time(cert_853_expiry)} for DNS over TLS (port 853)"
            )

    history_days = 30
    if "history" in request.args:
        try:
            history_days = int(request.args["history"])
        except:
            pass
    history = get_history(history_days)
    history_summary = summarize_history(history)

    # Convert time to relative time
    for node in history_summary["nodes"]:
        for key in ["plain_dns", "doh", "dot"]:
            if node[key]["last_down"] == "Never":
                node[key]["last_down"] = "over 30 days ago"
            else:
                node[key]["last_down"] = format_last_check(
                    datetime.strptime(node[key]["last_down"], "%Y-%m-%d %H:%M:%S")
                )
    
    for key in ["plain_dns", "doh", "dot"]:
        if history_summary["overall"][key]["last_down"] == "Never":
            continue
        history_summary["overall"][key]["last_down"] = format_last_check(
            datetime.strptime(history_summary["overall"][key]["last_down"], "%Y-%m-%d %H:%M:%S")
        )

    history_summary["nodes"] = convert_nodes_to_dict(history_summary["nodes"])

    last_check = format_last_check(last_log)

    # Replace true/false with up/down
    for node in node_status:
        for key in ["plain_dns", "doh", "dot"]:
            if node[key]:
                node[key] = "Up"
            else:
                node[key] = "Down"

    return render_template(
        "index.html",
        nodes=node_status,
        warnings=warnings,
        alerts=alerts,
        history=history_summary,
        last_check=last_check,
    )


@app.route("/manifest.json")
def manifest():
    with open("templates/manifest.json", "r") as file:
        manifest = json.load(file)
    manifest["start_url"] = request.url_root
    return jsonify(manifest)


@app.route("/<path:path>")
def catch_all(path: str):
    if os.path.isfile("templates/" + path):
        return render_template(path)

    # Try with .html
    if os.path.isfile("templates/" + path + ".html"):
        return render_template(path + ".html")

    if os.path.isfile("templates/" + path.strip("/") + ".html"):
        return render_template(path.strip("/") + ".html")

    # Try to find a file matching
    if path.count("/") < 1:
        # Try to find a file matching
        filename = find(path, "templates")
        if filename:
            return send_file(filename)

    return render_template("404.html"), 404


# endregion


# region Error Catching
# 404 catch all
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# endregion

# After defining check_nodes() function
def scheduled_node_check():
    """Function to be called by the scheduler to check all nodes"""
    try:
        logger.info("Running scheduled node check")
        # Get fresh node list on each check to pick up DNS changes
        global nodes
        nodes = []  # Reset node list to force refresh
        check_nodes()
        logger.info("Completed scheduled node check")
    except Exception as e:
        logger.error(f"Error in scheduled node check: {e}")

def scheduler_listener(event):
    """Listener for scheduler events"""
    if event.exception:
        logger.error(f"Error in scheduled job: {event.exception}")
    else:
        logger.debug("Scheduled job completed successfully")

# Function to start the scheduler
def start_scheduler():
    # Get check interval from environment variable or use default (5 minutes)
    check_interval_str = os.getenv("CHECK_INTERVAL_MINUTES", "5")
    try:
        check_interval = int(check_interval_str)
    except ValueError:
        logger.warning(f"Invalid CHECK_INTERVAL_MINUTES value: {check_interval_str}, using default of 5")
        check_interval = 5

    logger.info(f"Setting up scheduler to run every {check_interval} minutes")
    
    # Add the job to the scheduler
    scheduler.add_job(
        scheduled_node_check,
        IntervalTrigger(minutes=check_interval),
        id='node_check_job',
        replace_existing=True
    )
    
    # Add listener for job events
    scheduler.add_listener(scheduler_listener, EVENT_JOB_ERROR | EVENT_JOB_EXECUTED)
    
    # Start the scheduler if it's not already running
    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler started")

# Register signal handlers for graceful shutdown in Docker
def signal_handler(sig, frame):
    logger.info(f"Received signal {sig}, shutting down...")
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler shut down")
    sys.exit(0)

# Register the signal handlers for Docker
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Initialize the scheduler when the app starts without relying on @before_first_request
# which is deprecated in newer Flask versions
with app.app_context():
    start_scheduler()
    # Run an immediate check
    scheduled_node_check()

if __name__ == "__main__":
    # The scheduler is already started in the app context above
    # Run the Flask app
    app.run(debug=True, port=5000, host="0.0.0.0")

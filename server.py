from collections import defaultdict
from functools import cache
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

dotenv.load_dotenv()

app = Flask(__name__)

node_names = {
    "18.169.98.42": "Easy HNS",
    "172.233.46.92": "EZ Domains",
    "194.50.5.27": "Nathan.Woodburn/",
    "139.177.195.185": "HNSCanada",
    "172.105.120.203": "EZ Domains",
}
node_locations = {
    "18.169.98.42": "England",
    "172.233.46.92": "Netherlands",
    "194.50.5.27": "Australia",
    "139.177.195.185": "Canada",
    "172.105.120.203": "Singapore",
}
nodes = []
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
        if os.path.isfile("templates/assets/img/favicon/" + filename):
            return send_from_directory("templates/assets/img/favicon", filename)

    return render_template("404.html"), 404


# region Special routes
@app.route("/favicon.png")
def faviconPNG():
    return send_from_directory("templates/assets/img", "favicon.png")


@app.route("/.well-known/<path:path>")
def wellknown(path):
    # Try to proxy to https://nathan.woodburn.au/.well-known/
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
    return ips


def check_plain_dns(ip: str) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ip]

    try:
        result = resolver.resolve("1.wdbrn", "TXT")
        for txt in result:
            if "Test 1" in txt.to_text():
                return True
        return False
    except Exception as e:
        print(e)
        return False


def build_dns_query(domain: str, qtype: str = "A"):
    """
    Constructs a DNS query in binary wire format using dnslib.
    """
    q = dnslib.DNSRecord.question(domain, qtype)
    return q.pack()


def check_doh(ip: str) -> bool:
    status = False
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
        sock = socket.create_connection((ip, 443))
        context = ssl.create_default_context()
        ssock = context.wrap_socket(sock, server_hostname="hnsdoh.com")
    
        ssock.sendall(wireframe_request)
        response_data = b""
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            response_data += data

        response_str = response_data.decode("latin-1")
        headers, body = response_str.split("\r\n\r\n", 1)

        dns_response: dnslib.DNSRecord = dnslib.DNSRecord.parse(body.encode("latin-1"))
        for rr in dns_response.rr:
            if "Test 2" in str(rr):
                status = True

    except Exception as e:
        print(e)

    finally:
        # Close the socket connection
        # Check if ssock is defined
        if "ssock" in locals():
            ssock.close()
    return status


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
    except Exception as e:
        print(e)
        return False


def verify_cert(ip: str, port: int) -> bool:
    sock = socket.create_connection((ip, port))

    # Wrap the socket in SSL/TLS
    context = ssl.create_default_context()
    ssock = context.wrap_socket(sock, server_hostname="hnsdoh.com")
    expires = "ERROR"
    try:
        # Retrieve the server's certificate
        cert = ssock.getpeercert()

        # Extract the expiry date from the certificate
        expiry_date_str = cert["notAfter"]

        # Convert the expiry date string to a datetime object
        expiry_date = datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y GMT")
        expires = format_relative_time(expiry_date)
        valid = expiry_date > datetime.now()

    finally:
        # Close the SSL and socket connection
        ssock.close()
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
        return f"{delta.seconds} seconds ago" if delta.seconds > 1 else "1 second ago"

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
                node_status.append(
                    {
                        "ip": ip,
                        "name": node_names[ip] if ip in node_names else ip,
                        "location": (
                            node_locations[ip] if ip in node_locations else "Unknown"
                        ),
                        "plain_dns": check_plain_dns(ip),
                        "doh": check_doh(ip),
                        "dot": check_dot(ip),
                        "cert": verify_cert(ip, 443),
                        "cert_853": verify_cert(ip, 853),
                    }
                )
        else:
            node_status = []
            for ip in nodes:
                node_status.append(
                    {
                        "ip": ip,
                        "name": node_names[ip] if ip in node_names else ip,
                        "location": (
                            node_locations[ip] if ip in node_locations else "Unknown"
                        ),
                        "plain_dns": check_plain_dns(ip),
                        "doh": check_doh(ip),
                        "dot": check_dot(ip),
                        "cert": verify_cert(ip, 443),
                        "cert_853": verify_cert(ip, 853),
                    }
                )
        # Save the node status to a file
        log_status(node_status)
    print("Finished checking nodes", flush=True)

    # Send notifications if any nodes are down
    for node in node_status:
        if not node["plain_dns"] or not node["doh"] or not node["dot"] or not node["cert"]["valid"] or not node["cert_853"]["valid"]:
            send_down_notification(node)
            continue
        # Check if cert is expiring in 7 days
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
    return node_status

def check_nodes_from_log() -> list:
    global last_log
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
    if datetime.now() > newest["date"] + relativedelta.relativedelta(minutes=10):
        print("Failed to get a new enough log, checking nodes", flush=True)
        node_status = check_nodes()
    else:
        last_log = newest["date"]
    return node_status

def send_notification(title, description,author):
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
        sent_notifications[node["ip"]] = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
    else:
        last_send = datetime.strptime(sent_notifications[node["ip"]], "%Y-%m-%d %H:%M:%S")

        if last_send > datetime.now() - relativedelta.relativedelta(hours=1):
            print(f"Notification already sent for {node['name']} in the last hr", flush=True)
            return

        # Only send certain notifications once per day 
        if node["plain_dns"] and node["doh"] and node["dot"]:
            if last_send > datetime.now() - relativedelta.relativedelta(days=1):
                print(f"Notification already sent for {node['name']} in the last day", flush=True)
                return
            
    # Save the notification to the file
    sent_notifications[node["ip"]] = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
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
    
    # Also add the expiry date of the certificates
    description += "\nCertificate expiry dates:\n"
    description += f"- Certificate on port 443 expires {node['cert']['expires']}\n"
    description += f"- Certificate on port 853 expires {node['cert_853']['expires']}\n"
    send_notification(title, description, node['name'])


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

            # Update counts and last downtime
            for key in ["plain_dns", "doh", "dot"]:
                status = node.get(key, "up")
                if status == "down":
                    total_counts[ip][key]["down"] += 1
                total_counts[ip][key]["total"] += 1

            # Update last downtime for each key
            for key in ["plain_dns", "doh", "dot"]:
                if node.get(key) == "down":
                    nodes_status[ip][key]["last_down"] = date.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

    # Calculate percentages and prepare final summary
    node_list = []
    for ip, status in nodes_status.items():
        node_data = status.copy()
        for key in ["plain_dns", "doh", "dot"]:
            total = total_counts[ip][key]["total"]
            down = total_counts[ip][key]["down"]
            if total > 0:
                node_data[key]["percentage"] = ((total - down) / total) * 100
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
        name = node.get("name")
        if name:
            nodes_dict[name] = node
    return nodes_dict


# endregion


# region API routes
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

# endregion


# region Main routes
@app.route("/")
def index():
    node_status = check_nodes_from_log()

    alerts = []
    warnings = []
    for node in node_status:
        if not node["plain_dns"]:
            alerts.append(f"{node['name']} does not support plain DNS")

        if not node["doh"]:
            alerts.append(f"{node['name']} does not support DoH")

        if not node["dot"]:
            alerts.append(f"{node['name']} does not support DoT")

        if not node["cert"]["valid"]:
            alerts.append(f"{node['name']} has an invalid certificate")

        if not node["cert_853"]["valid"]:
            alerts.append(f"{node['name']} has an invalid certificate on port 853")

        cert_expiry = datetime.strptime(
            node["cert"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
        )
        if cert_expiry < datetime.now():
            alerts.append(
                f"The {node['name']} node's certificate has expired"
            )
            continue
        elif cert_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            warnings.append(
                f"The {node['name']} node's certificate is expiring {format_relative_time(cert_expiry)}"
            )
            continue
        cert_853_expiry = datetime.strptime(
            node["cert_853"]["expiry_date"], "%b %d %H:%M:%S %Y GMT"
        )
        if cert_853_expiry < datetime.now():
            alerts.append(
                f"The {node['name']} node's certificate has expired for DNS over TLS (port 853)"
            )
            continue
        elif cert_853_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            warnings.append(
                f"The {node['name']} node's certificate is expiring {format_relative_time(cert_853_expiry)} for DNS over TLS (port 853)"
            )
        

    history_days = 7
    if "history" in request.args:
        try:
            history_days = int(request.args["history"])
        except:
            pass
    history = get_history(history_days)
    history_summary = summarize_history(history)
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
if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")

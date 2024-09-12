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

log_dir = "/data"
if not os.path.exists(log_dir):
    if not os.path.exists("./logs"):
        os.mkdir("./logs")
    log_dir = "./logs"

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
    
def build_dns_query(domain: str, qtype: str = 'A'):
    """
    Constructs a DNS query in binary wire format using dnslib.
    """
    q = dnslib.DNSRecord.question(domain, qtype)
    return q.pack()

def check_doh(ip: str) -> bool:
    status = False
    dns_query = build_dns_query("2.wdbrn", 'TXT')
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
    try:
        ssock.sendall(wireframe_request)
        response_data = b""
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            response_data += data
        
        response_str = response_data.decode('latin-1')
        headers, body = response_str.split("\r\n\r\n", 1)
        
        dns_response:dnslib.DNSRecord = dnslib.DNSRecord.parse(body.encode('latin-1'))
        for rr in dns_response.rr:
            if "Test 2" in str(rr):
                status = True

    except Exception as e:
        print(e)
        
    finally:
        # Close the socket connection
        ssock.close()
    return status

def check_dot(ip: str) -> bool:
    qname = dns.name.from_text("3.wdbrn")
    q = dns.message.make_query(qname, dns.rdatatype.TXT)
    try:
        response = dns.query.tls(q, ip, timeout=5, port=853, server_hostname="hnsdoh.com")
        if response.rcode() == dns.rcode.NOERROR:
            for rrset in response.answer:
                for rr in rrset:
                    if "Test 3" in rr.to_text():
                        return True
        return False
    except Exception as e:
        print(e)
        return False

def verify_cert(ip: str,port:int) -> bool:
    sock = socket.create_connection((ip, port))
    
    # Wrap the socket in SSL/TLS
    context = ssl.create_default_context()
    ssock = context.wrap_socket(sock, server_hostname="hnsdoh.com")
    expires = "ERROR"
    try:
        # Retrieve the server's certificate
        cert = ssock.getpeercert()
        
        # Extract the expiry date from the certificate
        expiry_date_str = cert['notAfter']
        
        # Convert the expiry date string to a datetime object
        expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y GMT')
        print(expiry_date)
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
    newest = datetime.now()-relativedelta.relativedelta(years=1)
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
    data.append({
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nodes": node_status
    })

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    
        

# endregion


# region Main routes
@app.route("/")
def index():
    global nodes

    if last_log > datetime.now() - relativedelta.relativedelta(minutes=1):
        # Load the last log
        with open(f"{log_dir}/node_status.json", "r") as file:
            data = json.load(file)
        newest = {"date": datetime.now()-relativedelta.relativedelta(years=1), "nodes": []}
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
                node_status.append({
                    "ip": ip,
                    "name": node_names[ip] if ip in node_names else ip,
                    "location": node_locations[ip] if ip in node_locations else "Unknown",
                    "plain_dns": check_plain_dns(ip),
                    "doh": check_doh(ip),
                    "dot": check_dot(ip),
                    "cert": verify_cert(ip,443),
                    "cert_853": verify_cert(ip,853)
                    })
        else:
            node_status = []
            for ip in nodes:
                node_status.append({
                    "ip": ip,
                    "name": node_names[ip] if ip in node_names else ip,
                    "location": node_locations[ip] if ip in node_locations else "Unknown",
                    "plain_dns": check_plain_dns(ip),
                    "doh": check_doh(ip),
                    "dot": check_dot(ip),
                    "cert": verify_cert(ip,443),
                    "cert_853": verify_cert(ip,853)
                    })
        # Save the node status to a file
        log_status(node_status)

    warnings = []
    for node in node_status:
        if not node["plain_dns"]:
            warnings.append(f"{node['name']} does not support plain DNS")
        if not node["doh"]:
            warnings.append(f"{node['name']} does not support DoH")
        if not node["dot"]:
            warnings.append(f"{node['name']} does not support DoT")
        if not node["cert"]["valid"]:
            warnings.append(f"{node['name']} has an invalid certificate")
        if not node["cert_853"]["valid"]:
            warnings.append(f"{node['name']} has an invalid certificate on port 853")
        cert_expiry = datetime.strptime(node["cert"]["expiry_date"], '%b %d %H:%M:%S %Y GMT')
        if cert_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            warnings.append(f"{node['name']} has a certificate expiring in less than 7 days on port 443")
        cert_853_expiry = datetime.strptime(node["cert_853"]["expiry_date"], '%b %d %H:%M:%S %Y GMT')
        if cert_853_expiry < datetime.now() + relativedelta.relativedelta(days=7):
            warnings.append(f"{node['name']} has a certificate expiring in less than 7 days on port 853")

    return render_template("index.html",nodes=node_status,warnings=warnings)


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

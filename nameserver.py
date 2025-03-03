#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import ipaddress
import subprocess
import base64
import secrets
import hashlib
from datetime import datetime
from jinja2 import Template
import curses
from curses import wrapper
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from shutil import which

# -----------------------------------------------------------------------------
# Logging and Privilege Check (hostname updates require root)
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
# if os.geteuid() != 0:
#     logging.error("This script must be run as root to update /etc/hostname, /etc/hosts, and /etc/resolv.conf")
#     sys.exit(1)

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def render_template(template_str, context):
    try:
        return Template(template_str, trim_blocks=True, lstrip_blocks=True).render(context) + "\n"
    except Exception as e:
        logging.error("Template rendering error: %s", e)
        sys.exit(1)

def write_file(path, content, mode=0o644):
    try:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)
        logging.info("Created file: %s", path)
    except Exception as e:
        logging.error("Error writing to %s: %s", path, e)
        sys.exit(1)

def generate_rndc_secret():
    return base64.b64encode(os.urandom(16)).decode("utf-8")

def chunk_string(s, size=200):
    return " ".join([f'"{s[i:i+size]}"' for i in range(0, len(s), size)])

def generate_dkim_keys():
    try:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pub = priv.public_key()
        pem_pub = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        dkim_pub = "".join(line for line in pem_pub.decode().splitlines() if "-----" not in line)
        dkim_pub_chunked = chunk_string(dkim_pub, 200)
        pem_priv = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return dkim_pub_chunked, pem_priv.decode()
    except Exception as e:
        logging.error("DKIM key generation failed: %s", e)
        sys.exit(1)

# -----------------------------------------------------------------------------
# System File Update Functions
# -----------------------------------------------------------------------------
def update_etc_hostname(hostname):
    try:
        with open("/etc/hostname", "w") as f:
            f.write(hostname + "\n")
        logging.info("Updated /etc/hostname with: %s", hostname)
    except Exception as e:
        logging.error("Error updating /etc/hostname: %s", e)

def update_etc_hosts(ip, hostname):
    try:
        shortname = hostname.split('.')[0]
        with open("/etc/hosts", "a") as f:
            f.write(f"{ip} {hostname} {shortname}\n")
        logging.info("Appended /etc/hosts with: %s %s", ip, hostname)
    except Exception as e:
        logging.error("Error updating /etc/hosts: %s", e)

def update_resolv_conf(nameserver):
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write(f"nameserver 8.8.8.8\n")
            f.write(f"nameserver {nameserver}\n")
        logging.info("Updated /etc/resolv.conf with nameserver: %s", nameserver)
    except Exception as e:
        logging.error("Error updating /etc/resolv.conf: %s", e)

# -----------------------------------------------------------------------------
# rndc Key Generation Function
# -----------------------------------------------------------------------------
def generate_rndc_key(rndc_key_file):
    if which("rndc-confgen") is None:
        logging.error("rndc-confgen not found. Please install bind9utils or ensure it's in your PATH.")
        sys.exit(1)
    try:
        subprocess.run(["rndc-confgen", "-a", "-c", rndc_key_file], check=True)
        logging.info("Generated rndc key at: %s", rndc_key_file)
    except subprocess.CalledProcessError as e:
        logging.error("Failed to generate rndc key: %s", e)
        sys.exit(1)

# -----------------------------------------------------------------------------
# named.ca Generator
# -----------------------------------------------------------------------------
def gen_named_ca(internet=True, context={}):
    if internet:
        root_servers = [
            {"ns": "B.ROOT-SERVERS.NET.", "a": "128.9.0.107"},
            {"ns": "C.ROOT-SERVERS.NET.", "a": "192.33.4.12"},
            {"ns": "D.ROOT-SERVERS.NET.", "a": "128.8.10.90"},
            {"ns": "E.ROOT-SERVERS.NET.", "a": "192.203.230.10"},
            {"ns": "F.ROOT-SERVERS.NET.", "a": "192.5.5.241"},
            {"ns": "G.ROOT-SERVERS.NET.", "a": "192.112.36.4"},
            {"ns": "H.ROOT-SERVERS.NET.", "a": "128.63.2.53"},
            {"ns": "I.ROOT-SERVERS.NET.", "a": "192.36.148.17"},
            {"ns": "J.ROOT-SERVERS.NET.", "a": "198.41.0.10"},
            {"ns": "K.ROOT-SERVERS.NET.", "a": "198.41.0.11"},
            {"ns": "L.ROOT-SERVERS.NET.", "a": "198.32.64.12"},
            {"ns": "M.ROOT-SERVERS.NET.", "a": "198.32.65.12"}
        ]
        template = """
; Internet Root Hints File
{% for server in root_servers %}
.                        3600000    NS   {{ server.ns }}
{{ server.ns }}      3600000    A    {{ server.a }}
{% endfor %}
; End of File
"""
        return Template(template, trim_blocks=True, lstrip_blocks=True).render(root_servers=root_servers)
    else:
        template = """
; Non-Internet Root Hints File
@    IN    SOA  {{ noninternet_root }}.   hostmaster.{{ noninternet_root }}. (
                 {{ serial }} ; serial number (YYYYMMDD##)
                 10800       ; refresh after 3 hours
                 3600        ; retry after 1 hour
                 604800      ; expire after 1 week
                 86400 )     ; minimum TTL of 1 day
;
{{ noninternet_root }}.      999999     IN    A    {{ noninternet_ip }}
;
{{ domain }}.                         IN    NS   {{ noninternet_ns1 }}.
{{ domain }}.                         IN    NS   {{ noninternet_ns2 }}.
; End of File
"""
        return Template(template, trim_blocks=True, lstrip_blocks=True).render(**context)

# -----------------------------------------------------------------------------
# TUI Functions for Interactive Input
# -----------------------------------------------------------------------------
def tui_menu(stdscr):
    stdscr.clear()
    try:
        stdscr.addstr(0, 0, "Select Setup Mode:")
        stdscr.addstr(2, 2, "1. Setup from Scratch")
        stdscr.addstr(3, 2, "2. Standalone DNS")
        stdscr.addstr(4, 2, "3. Add New Parent Domain")
        stdscr.addstr(6, 0, "Enter choice (1, 2 or 3): ")
    except curses.error:
        pass
    return stdscr.getstr().decode("utf-8").strip()

def tui_setup_from_scratch(stdscr):
    curses.echo()
    stdscr.clear()
    try:
        stdscr.addstr(0, 0, "Setup from Scratch")
        stdscr.addstr(2, 0, "Enter Root Domain (e.g., framique.com): ")
        domain = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(3, 0, "Enter IP Address (e.g., 185.143.228.205): ")
        ip = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(4, 0, "Enter Mail Zone (e.g., mail.framique.com): ")
        mail_zone = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(5, 0, "Enter Generic Subdomain (e.g., vpn.framique.com): ")
        sub_zone = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(6, 0, "Enter Full Hostname (FQDN) for the server (e.g., server.framique.com): ")
        hostname = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(7, 0, "Enter Listen-On IPs (comma separated, leave blank for 'any'): ")
        listen_on = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(8, 0, "Enter SPF record text [leave blank for default]: ")
        spf_text = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(9, 0, "Enter DMARC record text [leave blank for default]: ")
        dmarc = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(10, 0, "Enter output directory (default: /etc/bind): ")
        outdir = stdscr.getstr().decode("utf-8").strip()
    except curses.error:
        outdir = "/etc/bind"
    stdscr.getch()
    if not outdir:
        outdir = "/etc/bind"
    if not spf_text:
        spf_text = f"v=spf1 a mx ip4:{ip} -all"
    if not dmarc:
        dmarc = f"v=DMARC1; p=none; rua=mailto:postmaster@{domain}"
    return {"domain": domain, "ip": ip, "mail_zone": mail_zone, "sub_zone": sub_zone,
            "hostname": hostname, "listen_on": listen_on, "spf": spf_text, "dmarc": dmarc, "output_dir": outdir}

def tui_standalone_dns(stdscr):
    curses.echo()
    stdscr.clear()
    try:
        stdscr.addstr(0, 0, "Standalone DNS Setup")
        stdscr.addstr(2, 0, "Enter Domain for DNS update (e.g., existingdomain.com): ")
        domain = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(3, 0, "Enter Listen-On IPs (comma separated, leave blank for 'any'): ")
        listen_on = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(4, 0, "Enter Full Hostname (FQDN) for the server [optional]: ")
        hostname = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(5, 0, "Enter DMARC record text [optional]: ")
        dmarc = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(6, 0, "Enter output directory (default: /etc/bind): ")
        outdir = stdscr.getstr().decode("utf-8").strip()
    except curses.error:
        outdir = "/etc/bind"
    stdscr.getch()
    if not outdir:
        outdir = "/etc/bind"
    return {"domain": domain, "ip": "", "mail_zone": "", "sub_zone": "",
            "hostname": hostname, "listen_on": listen_on, "spf": "", "dmarc": dmarc, "output_dir": outdir}

def tui_add_new_parent_domain(stdscr):
    curses.echo()
    stdscr.clear()
    try:
        stdscr.addstr(0, 0, "Add New Parent Domain")
        stdscr.addstr(2, 0, "Enter Parent Domain (e.g., newparent.com): ")
        domain = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(3, 0, "Enter IP Address for A record (e.g., 192.0.2.1): ")
        ip = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(4, 0, "Enter Full Hostname (FQDN) for the server (e.g., ns.newparent.com): ")
        hostname = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(5, 0, "Enter DMARC record text [leave blank for default]: ")
        dmarc = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(6, 0, "Enter SPF record text [leave blank for default]: ")
        spf_text = stdscr.getstr().decode("utf-8").strip()
        stdscr.addstr(7, 0, "Enter output directory (default: /etc/bind): ")
        outdir = stdscr.getstr().decode("utf-8").strip()
    except curses.error:
        outdir = "/etc/bind"
    stdscr.getch()
    if not outdir:
        outdir = "/etc/bind"
    if not spf_text:
        spf_text = f"v=spf1 a mx ip4:{ip} -all"
    if not dmarc:
        dmarc = f"v=DMARC1; p=none; rua=mailto:postmaster@{domain}"
    return {"domain": domain, "ip": ip, "mail_zone": "", "sub_zone": "",
            "hostname": hostname, "listen_on": "", "spf": spf_text, "dmarc": dmarc, "output_dir": outdir}

def run_tui():
    def tui(stdscr):
        curses.echo()
        choice = tui_menu(stdscr)
        if choice == "1":
            return tui_setup_from_scratch(stdscr)
        elif choice == "2":
            return tui_standalone_dns(stdscr)
        elif choice == "3":
            return tui_add_new_parent_domain(stdscr)
        else:
            stdscr.addstr(10, 0, "Invalid choice. Exiting.")
            stdscr.getch()
            sys.exit(1)
    return wrapper(tui)()

# -----------------------------------------------------------------------------
# Bind Configuration Manager Class
# -----------------------------------------------------------------------------
class BindConfigManager:
    def __init__(self, context):
        self.ctx = context

    def gen_named_conf(self):
        tmpl = """
include "{{ bind_dir }}/rndc.key";

controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};

include "{{ bind_dir }}/named.conf.options";
include "{{ bind_dir }}/named.conf.local";
zone "." IN {
    type hint;
    file "{{ bind_dir }}/named.ca";
};
"""
        return render_template(tmpl, self.ctx)

    def gen_named_conf_options(self):
        listen_ips = self.ctx.get("listen_on", "")
        if listen_ips:
            ip_list = [ip.strip() for ip in listen_ips.split(",") if validate_ip(ip.strip())]
            listen_str = "{" + "; ".join(ip_list) + ";}"
        else:
            listen_str = "{ any; }"
        tmpl = """
// named.conf.options
options {
    listen-on port 53 %s;
    listen-on-v6 port 53 { ::1; };
    directory "{{ bind_dir }}";
    dump-file "{{ bind_dir }}/data/cache_dump.db";
    statistics-file "{{ bind_dir }}/data/named_stats.txt";
    memstatistics-file "{{ bind_dir }}/data/named_mem_stats.txt";
    recursing-file "{{ bind_dir }}/data/named.recursing";
    secroots-file "{{ bind_dir }}/data/named.secroots";
    allow-query { any; };
    recursion yes;
    allow-recursion { localhost; };
    bindkeys-file "{{ bind_dir }}/named.root.key";
    pid-file "/run/named/named.pid";
    session-keyfile "/run/named/session.key";
};
""" % listen_str
        return render_template(tmpl, self.ctx)

    def gen_named_conf_local(self):
        tmpl = """
// named.conf.local
{% if domain %}
zone "{{ domain }}" {
    type master;
    file "{{ zones_dir }}/db.{{ domain }}";
};
{% endif %}
{% if mail_zone %}
zone "{{ mail_zone }}" {
    type master;
    file "{{ zones_dir }}/db.{{ mail_zone }}";
};
{% endif %}
{% if sub_zone %}
zone "{{ sub_zone }}" {
    type master;
    file "{{ zones_dir }}/db.{{ sub_zone }}";
};
{% endif %}
{% if reverse_zone %}
zone "{{ reverse_zone }}" {
    type master;
    file "{{ zones_dir }}/db.{{ reverse_zone }}";
};
{% endif %}
{% if domain %}
zone "ns1.{{ domain }}" {
    type master;
    file "{{ zones_dir }}/db.ns1.{{ domain }}";
};
zone "ns2.{{ domain }}" {
    type master;
    file "{{ zones_dir }}/db.ns2.{{ domain }}";
};
{% endif %}
"""
        return render_template(tmpl, self.ctx)

    def gen_zone_file(self, zone_type):
        hostname_record = ""
        if self.ctx.get("hostname") and self.ctx.get("ip"):
            hostname_record = f"{self.ctx['hostname']} IN A {self.ctx['ip']}\n"
        if zone_type == "default":
            tmpl = """
$TTL 604800
@       IN      SOA     {{ root_ns1 }}. hostmaster.{{ domain }}. (
    {{ serial }} ; serial
    604800     ; refresh
    86400      ; retry
    2419200    ; expire
    604800     ; minimum
)
@       IN      NS      {{ root_ns1 }}.
@       IN      NS      {{ root_ns2 }}.
@       IN      A       {{ ip }}
ns1     IN      A       {{ ip }}
ns2     IN      A       {{ ip }}
""" + hostname_record + """
@       IN      MX 10   mail.{{ domain }}.
_dmarc  IN      TXT     "{{ dmarc }}"
@       IN      TXT     "{{ spf }}"
default._domainkey IN TXT  "v=DKIM1; h=sha256; k=rsa; p={{ dkim_public|replace('\\n','')|replace(' ', '') }}"
"""
        elif zone_type == "reverse":
            tmpl = """
$TTL 604800
@       IN      SOA     {{ root_ns1 }}. hostmaster.{{ domain }}. (
    {{ serial }} ; serial
    604800     ; refresh
    86400      ; retry
    2419200    ; expire
    604800     ; minimum
)
@       IN      NS      {{ root_ns1 }}.
@       IN      NS      {{ root_ns2 }}.
{% set last_octet = ip.split('.')[-1] %}
{{ last_octet }}       IN PTR {{ domain }}.
"""
        elif zone_type == "mail":
            tmpl = """
$TTL 14400
@       IN  SOA {{ mail_ns1 }}. postmaster.{{ mail_zone }}. (
    {{ serial }} ; serial
    3600       ; refresh
    7200       ; retry
    1209600    ; expire
    86400      ; minimum
)
@       IN  NS  {{ mail_ns1 }}.
@       IN  NS  {{ mail_ns2 }}.
@       IN  A   {{ ip }}
localhost.{{ mail_zone }}. IN A 127.0.0.1
@       IN  MX 0 mail.{{ mail_zone }}.
_dmarc  IN TXT "v=DMARC1; p=none; rua=mailto:postmaster@{{ mail_zone }}"
@       IN TXT "{{ spf }}"
default._domainkey IN TXT "v=DKIM1; h=sha256; k=rsa; p={{ dkim_public|replace('\\n','')|replace(' ', '') }}"
"""
        elif zone_type == "sub":
            tmpl = """
$TTL 14400
@       IN  SOA {{ sub_ns1 }}. postmaster.{{ sub_zone }}. (
    {{ serial }} ; serial
    3600       ; refresh
    7200       ; retry
    1209600    ; expire
    86400      ; minimum
)
@       IN  NS  {{ sub_ns1 }}.
@       IN  NS  {{ sub_ns2 }}.
@       IN  A   {{ ip }}
@       IN TXT "v=spf1 +a +mx +ip4:{{ ip }} ~all"
default._domainkey IN TXT "v=DKIM1; h=sha256; k=rsa; p={{ dkim_public|replace('\\n','')|replace(' ', '') }}"
_dmarc  IN TXT "v=DMARC1; p=none"
{% if extra_srv %}
; SRV records:
{% for rec in extra_srv %}
{{ rec.priority }} {{ rec.weight }} {{ rec.port }} {{ rec.target }}
{% endfor %}
{% endif %}
"""
        else:
            tmpl = ""
        return render_template(tmpl, self.ctx)

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
def get_config(args):
    essentials = ["domain", "ip", "mail_zone", "sub_zone", "hostname"]
    if args.force_tui or not all(getattr(args, field, None) for field in essentials):
        return run_tui()
    else:
        return {
            "domain": args.domain,
            "ip": args.ip,
            "mail_zone": args.mail_zone,
            "sub_zone": args.sub_zone,
            "hostname": args.hostname,
            "listen_on": args.listen_on if args.listen_on else "",
            "spf": args.spf if args.spf else f"v=spf1 a mx ip4:{args.ip} -all",
            "dmarc": args.dmarc if args.dmarc else f"v=DMARC1; p=none; rua=mailto:postmaster@{args.domain}",
            "output_dir": args.output_dir
        }

def main():
    parser = argparse.ArgumentParser(description="Advanced Dynamic BIND9 DNS Setup Generator")
    parser.add_argument("--domain", help="Root domain (e.g., framique.com)")
    parser.add_argument("--ip", help="IP address for A records (e.g., 185.143.228.205)")
    parser.add_argument("--mail-zone", help="Mail zone (e.g., mail.framique.com)")
    parser.add_argument("--sub-zone", help="Generic subdomain (e.g., vpn.framique.com)")
    parser.add_argument("--hostname", help="Full hostname (FQDN) for the server (e.g., server.framique.com)")
    parser.add_argument("--listen-on", help="Comma-separated list of IPs for the listen-on directive")
    parser.add_argument("--spf", help="SPF record text")
    parser.add_argument("--dmarc", help="DMARC record text")
    parser.add_argument("--noninternet", action="store_true", help="Generate a non-Internet named.ca file")
    parser.add_argument("--output-dir", default="/etc/bind", help="Output directory for configuration files")
    parser.add_argument("--force-tui", action="store_true", help="Force interactive mode even if arguments are provided")
    args = parser.parse_args()

    config = get_config(args)

    if not validate_ip(config["ip"]):
        logging.error("Invalid IP address provided.")
        sys.exit(1)
    octets = config["ip"].split(".")
    if len(octets) != 4:
        logging.error("IP must be in dotted IPv4 format.")
        sys.exit(1)
    rev_zone = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"

    gen_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    serial = datetime.now().strftime("%Y%m%d%H")
    dkim_pub, dkim_priv = generate_dkim_keys()
    rndc_sec = generate_rndc_secret()

    # Determine output directory.
    bind_dir = os.path.abspath(config.get("output_dir"))
    zones_dir = bind_dir
    keys_dir = os.path.join(bind_dir, "keys")  # Unused since DNSSEC is managed externally.
    dynamic_dir = os.path.join(bind_dir, "dynamic")
    for d in [bind_dir, zones_dir, keys_dir, dynamic_dir]:
        os.makedirs(d, exist_ok=True)

    # Generate or update rndc key using rndc-confgen.
    rndc_key_file = os.path.join(bind_dir, "rndc.key")
    if not os.path.exists(rndc_key_file):
        generate_rndc_key(rndc_key_file)

    # Create an empty managed-keys.bind file to avoid errors.
    managed_keys_file = os.path.join(dynamic_dir, "managed-keys.bind")
    if not os.path.exists(managed_keys_file):
        write_file(managed_keys_file, "")

    # Generate named.ca file (root hints).
    named_ca_file = os.path.join(bind_dir, "named.ca")
    named_ca_content = gen_named_ca(internet=(not args.noninternet), context={**{"serial": serial, "domain": config.get("domain", "")}, **config})
    write_file(named_ca_file, named_ca_content)

    context = {
        "generation_date": gen_date,
        "bind_dir": bind_dir,
        "zones_dir": zones_dir,
        "serial": serial,
        "ip": config["ip"],
        "rndc_secret": rndc_sec,
        "dkim_public": dkim_pub,
        "domain": config.get("domain", ""),
        "mail_zone": config.get("mail_zone", ""),
        "sub_zone": config.get("sub_zone", ""),
        "hostname": config.get("hostname", ""),
        "reverse_zone": rev_zone,
        "listen_on": config.get("listen_on", ""),
        "spf": config.get("spf", f"v=spf1 a mx ip4:{config['ip']} -all"),
        "dmarc": config.get("dmarc", f"v=DMARC1; p=none; rua=mailto:postmaster@{config['domain']}")
    }
    if context["domain"]:
        context["root_ns1"] = "ns1." + context["domain"]
        context["root_ns2"] = "ns2." + context["domain"]
    if context["mail_zone"]:
        context["mail_ns1"] = "ns1." + context["domain"]
        context["mail_ns2"] = "ns2." + context["domain"]
    if context["sub_zone"]:
        context["sub_ns1"] = "ns1." + context["domain"]
        context["sub_ns2"] = "ns2." + context["domain"]

    bcm = BindConfigManager(context)
    write_file(os.path.join(bind_dir, "named.conf"), bcm.gen_named_conf())
    write_file(os.path.join(bind_dir, "named.conf.options"), bcm.gen_named_conf_options())
    write_file(os.path.join(bind_dir, "named.conf.local"), bcm.gen_named_conf_local())

    # Generate zone files.
    if context["domain"]:
        write_file(os.path.join(zones_dir, f"db.{context['domain']}"), bcm.gen_zone_file("default"))
        write_file(os.path.join(zones_dir, f"db.ns1.{context['domain']}"), bcm.gen_zone_file("default"))
        write_file(os.path.join(zones_dir, f"db.ns2.{context['domain']}"), bcm.gen_zone_file("default"))
    if context["mail_zone"]:
        write_file(os.path.join(zones_dir, f"db.{context['mail_zone']}"), bcm.gen_zone_file("mail"))
    if context["sub_zone"]:
        write_file(os.path.join(zones_dir, f"db.{context['sub_zone']}"), bcm.gen_zone_file("sub"))
    write_file(os.path.join(zones_dir, f"db.{rev_zone}"), bcm.gen_zone_file("reverse"))
    write_file(os.path.join(bind_dir, "default._domainkey.private"), dkim_priv)

    # Update system files for hostname, hosts, and resolv.conf.
    update_etc_hostname(context["hostname"])
    update_etc_hosts(context["ip"], context["hostname"])
    nameserver = context["listen_on"].split(",")[0].strip() if context["listen_on"] else context["ip"]
    update_resolv_conf(nameserver)

    logging.info("Advanced dynamic DNS configuration generated successfully.")
    logging.info("DNSSEC is managed externally. Reload BIND (e.g., 'sudo rndc reconfig') and verify zones with 'dig'.")

if __name__ == "__main__":
    main()

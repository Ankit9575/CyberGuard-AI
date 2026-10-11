
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS


app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

REQUEST_TIMEOUT = 5
MAX_IP_LOOKUPS = 4

# Set FRONTEND_ORIGIN when deploying, for example:
# FRONTEND_ORIGIN=https://your-site.netlify.app
frontend_origin = os.getenv("FRONTEND_ORIGIN", "").strip()

if frontend_origin:
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": [frontend_origin],
                "methods": ["GET", "OPTIONS"],
            }
        },
    )
else:
    # Local development only. Configure FRONTEND_ORIGIN for deployment.
    CORS(app, resources={r"/api/*": {"origins": "*"}})


USER_AGENT = "CyberGuardAI-Educational-Project/2.0"

# Basic in-memory request limit. For production, use a shared rate limiter.
_rate_lock = threading.Lock()
_request_times = defaultdict(deque)
RATE_LIMIT = 30
RATE_WINDOW_SECONDS = 60


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value):
    """Accept a domain or HTTP(S) URL and return its hostname."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Please enter a domain name or website URL.")

    value = value.strip()

    if len(value) > 2048:
        raise ValueError("The input is too long.")

    if any(char.isspace() for char in value):
        raise ValueError("The input must not contain spaces.")

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValueError("Please enter a valid website URL.") from exc

    if parsed.scheme not in ("http", "https") or not hostname:
        raise ValueError("Only valid HTTP or HTTPS website URLs are supported.")

    hostname = hostname.rstrip(".").lower()

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The domain name is invalid.") from exc

    if len(hostname) > 253 or "." not in hostname:
        raise ValueError("Enter a fully qualified domain, such as example.com.")

    # Do not accept IP addresses in the domain field.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name rather than an IP address.")

    labels = hostname.split(".")
    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if not all(label_pattern.fullmatch(label) for label in labels):
        raise ValueError("The domain contains invalid characters.")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost addresses are not supported.")

    if hostname.endswith(".local"):
        raise ValueError("Local network domains are not supported.")

    return hostname


def check_rate_limit():
    """Apply a small per-client in-memory request limit."""

    client_ip = request.remote_addr or "unknown"
    now = time.monotonic()

    with _rate_lock:
        times = _request_times[client_ip]

        while times and now - times[0] >= RATE_WINDOW_SECONDS:
            times.popleft()

        if len(times) >= RATE_LIMIT:
            return False

        times.append(now)

        # Keep the in-memory table from growing indefinitely.
        if len(_request_times) > 2000:
            expired_keys = [
                key
                for key, entries in _request_times.items()
                if not entries or now - entries[-1] >= RATE_WINDOW_SECONDS
            ]
            for key in expired_keys:
                _request_times.pop(key, None)

    return True


@app.before_request
def enforce_rate_limit():
    if request.path.startswith("/api/") and not check_rate_limit():
        response = jsonify({
            "status": "error",
            "message": "Too many requests. Please wait a minute and try again.",
        })
        response.status_code = 429
        response.headers["Retry-After"] = "60"
        return response

    return None


def dns_lookup(domain, record_type):
    """Return DNS records and distinguish missing records from failures."""

    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=REQUEST_TIMEOUT,
            raise_on_no_answer=False,
        )

        if answers.rrset is None:
            return {"status": "no_records", "records": []}

        records = []

        for answer in answers:
            if record_type == "MX":
                records.append({
                    "priority": answer.preference,
                    "server": str(answer.exchange).rstrip("."),
                })
            elif record_type == "SOA":
                records.append({
                    "primary_nameserver": str(answer.mname).rstrip("."),
                    "responsible_mailbox": str(answer.rname).rstrip("."),
                    "serial": answer.serial,
                    "refresh": answer.refresh,
                    "retry": answer.retry,
                    "expire": answer.expire,
                    "minimum": answer.minimum,
                })
            else:
                records.append(str(answer).rstrip("."))

        return {"status": "success", "records": records}

    except dns.resolver.NXDOMAIN:
        return {"status": "not_found", "records": []}
    except dns.resolver.NoAnswer:
        return {"status": "no_records", "records": []}
    except (dns.resolver.NoNameservers, dns.exception.Timeout):
        return {"status": "lookup_failed", "records": []}
    except Exception:
        app.logger.exception("DNS lookup failed for %s (%s)", domain, record_type)
        return {"status": "lookup_failed", "records": []}


def get_ip_addresses(domain):
    """Resolve public IPv4 and IPv6 addresses only."""

    addresses = {"ipv4": [], "ipv6": []}

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM,
        )

        for result in results:
            address = result[4][0].split("%")[0]

            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue

            if not parsed.is_global:
                continue

            key = "ipv4" if parsed.version == 4 else "ipv6"

            if address not in addresses[key]:
                addresses[key].append(address)

    except (socket.gaierror, OSError):
        pass

    return addresses


def get_ip_intelligence(addresses):
    """Retrieve approximate public IP metadata from ipwho.is."""

    results = []

    for address in addresses[:MAX_IP_LOOKUPS]:
        try:
            response = requests.get(
                f"https://ipwho.is/{address}",
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=False,
            )

            if response.status_code != 200:
                results.append({
                    "ip": address,
                    "status": "metadata_unavailable",
                })
                continue

            data = response.json()

            if not data.get("success", True):
                results.append({
                    "ip": address,
                    "status": "metadata_unavailable",
                })
                continue

            connection = data.get("connection") or {}

            results.append({
                "ip": address,
                "status": "success",
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "isp": connection.get("isp"),
                "organization": connection.get("org"),
                "asn": connection.get("asn"),
                "source": "ipwho.is",
            })

        except (requests.RequestException, ValueError):
            results.append({
                "ip": address,
                "status": "metadata_unavailable",
            })

    return results


def get_registration_data(domain):
    """Retrieve public domain registration information through RDAP."""

    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": USER_AGENT,
            },
            allow_redirects=True,
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "No registration record was returned.",
            }

        response.raise_for_status()
        data = response.json()

        events = {}

        for event in data.get("events", []):
            action = event.get("eventAction")
            event_date = event.get("eventDate")

            if action and event_date:
                events[action] = event_date

        entities = []

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])

            # Avoid returning registrant/admin/technical contact details.
            if any(
                role in ("registrant", "administrative", "technical")
                for role in roles
            ):
                continue

            name = None
            vcard = entity.get("vcardArray", [])

            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if (
                        isinstance(item, list)
                        and len(item) >= 4
                        and item[0] == "fn"
                    ):
                        name = item[3]
                        break

            if name or roles:
                entities.append({
                    "name": name,
                    "roles": roles,
                })

        return {
            "status": "success",
            "domain": data.get("ldhName") or domain,
            "handle": data.get("handle"),
            "registrar_entities": entities,
            "nameservers": [
                item.get("ldhName")
                for item in data.get("nameservers", [])
                if item.get("ldhName")
            ],
            "events": events,
            "secure_dns": data.get("secureDNS"),
            "source": "RDAP",
            "note": (
                "Some registration details may be hidden, redacted, "
                "or unavailable."
            ),
        }

    except (requests.RequestException, ValueError):
        return {
            "status": "unavailable",
            "message": "Registration information could not be retrieved.",
        }


def get_tls_info(domain):
    """Inspect the TLS certificate using a public resolved IP."""

    addresses = get_ip_addresses(domain)
    all_addresses = addresses["ipv4"] + addresses["ipv6"]

    if not all_addresses:
        return {
            "status": "unavailable",
            "message": "No public IP address was available for a TLS connection.",
        }

    context = ssl.create_default_context()
    last_error = None

    for address in all_addresses[:MAX_IP_LOOKUPS]:
        try:
            # Connect to a verified public IP while retaining the domain as SNI.
            with socket.create_connection(
                (address, 443),
                timeout=REQUEST_TIMEOUT,
            ) as connection:
                with context.wrap_socket(
                    connection,
                    server_hostname=domain,
                ) as tls_socket:
                    cert = tls_socket.getpeercert()

            def flatten_name(items):
                output = []
                for group in items or []:
                    for key, value in group:
                        output.append(f"{key}={value}")
                return ", ".join(output) or "Not provided"

            def parse_cert_date(value):
                if not value:
                    return None

                parsed = datetime.strptime(
                    value,
                    "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)

                return parsed.isoformat()

            expires = parse_cert_date(cert.get("notAfter"))
            starts = parse_cert_date(cert.get("notBefore"))
            now = datetime.now(timezone.utc)

            expired = (
                datetime.fromisoformat(expires) < now
                if expires else None
            )
            not_yet_valid = (
                datetime.fromisoformat(starts) > now
                if starts else None
            )

            return {
                "status": "success",
                "subject": flatten_name(cert.get("subject")),
                "issuer": flatten_name(cert.get("issuer")),
                "valid_from": starts,
                "valid_until": expires,
                "expired": expired,
                "not_yet_valid": not_yet_valid,
                "subject_alt_names": [
                    value
                    for kind, value in cert.get("subjectAltName", [])
                    if kind == "DNS"
                ][:30],
                "source": "TLS handshake",
            }

        except (
            OSError,
            ssl.SSLError,
            ValueError,
        ) as exc:
            last_error = exc

    app.logger.info("TLS lookup unavailable for %s: %s", domain, last_error)

    return {
        "status": "unavailable",
        "message": (
            "A trusted TLS certificate could not be retrieved. "
            "The service may be unavailable or use an invalid certificate."
        ),
    }


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "CyberGuard AI Website Intelligence API",
        "timestamp": utc_now(),
    })


@app.get("/api/intelligence")
def website_intelligence():
    raw_domain = request.args.get("domain", "")

    try:
        domain = normalize_domain(raw_domain)
    except ValueError as exc:
        return jsonify({
            "status": "error",
            "message": str(exc),
        }), 400

    # Resolve only the hostname. Never fetch the submitted website URL.
    addresses = get_ip_addresses(domain)
    all_ips = addresses["ipv4"] + addresses["ipv6"]

    dns_records = {
        record: dns_lookup(domain, record)
        for record in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
    }

    return jsonify({
        "status": "success",
        "domain": domain,
        "checked_at": utc_now(),
        "ip_addresses": addresses,
        "dns": dns_records,
        "ip_intelligence": get_ip_intelligence(all_ips),
        "registration": get_registration_data(domain),
        "tls": get_tls_info(domain),
        "limitations": [
            "IP addresses may belong to a CDN or reverse proxy, not the origin server.",
            "Geolocation is approximate and does not identify a person's location.",
            "Unavailable data does not establish that a website is malicious or safe.",
            "This endpoint does not perform a vulnerability scan or a live threat-reputation check.",
        ],
    })


@app.errorhandler(404)
def not_found(_error):
    return jsonify({
        "status": "error",
        "message": "API endpoint not found.",
    }), 404


@app.errorhandler(413)
def payload_too_large(_error):
    return jsonify({
        "status": "error",
        "message": "The request is too large.",
    }), 413


@app.errorhandler(500)
def internal_error(_error):
    return jsonify({
        "status": "error",
        "message": "An internal server error occurred.",
    }), 500


if __name__ == "__main__":
    # Local development only. Use a production WSGI server when deploying.
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )

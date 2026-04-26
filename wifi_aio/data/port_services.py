"""Common port and service mapping.

Contains the top 200 most common network ports with their associated
service names, protocols, and descriptions for network assessment.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# Port database: port_number -> {service, protocol, description, category}
PORT_SERVICES: Dict[int, Dict] = {
    # ── Well-known ports (0-1023) ───────────────────────────────────────
    20:    {"service": "ftp-data",   "protocol": "TCP", "description": "FTP Data Transfer",          "category": "file_transfer"},
    21:    {"service": "ftp",        "protocol": "TCP", "description": "FTP Control",                 "category": "file_transfer"},
    22:    {"service": "ssh",        "protocol": "TCP", "description": "Secure Shell",                "category": "remote_access"},
    23:    {"service": "telnet",     "protocol": "TCP", "description": "Telnet (insecure)",           "category": "remote_access"},
    25:    {"service": "smtp",       "protocol": "TCP", "description": "Simple Mail Transfer",        "category": "email"},
    26:    {"service": "rsftp",      "protocol": "TCP", "description": "RSFTP Alternate",             "category": "file_transfer"},
    37:    {"service": "time",       "protocol": "TCP", "description": "Time Protocol",               "category": "system"},
    42:    {"service": "nameserver", "protocol": "TCP", "description": "Host Name Server",            "category": "dns"},
    43:    {"service": "nicname",    "protocol": "TCP", "description": "WHOIS",                       "category": "information"},
    49:    {"service": "tacacs",     "protocol": "TCP", "description": "TACACS+",                     "category": "authentication"},
    53:    {"service": "dns",        "protocol": "TCP/UDP", "description": "Domain Name System",      "category": "dns"},
    67:    {"service": "dhcp-s",     "protocol": "UDP", "description": "DHCP Server",                 "category": "network"},
    68:    {"service": "dhcp-c",     "protocol": "UDP", "description": "DHCP Client",                 "category": "network"},
    69:    {"service": "tftp",       "protocol": "UDP", "description": "Trivial FTP",                 "category": "file_transfer"},
    79:    {"service": "finger",     "protocol": "TCP", "description": "Finger Protocol",             "category": "information"},
    80:    {"service": "http",       "protocol": "TCP", "description": "HTTP Web Server",             "category": "web"},
    88:    {"service": "kerberos",   "protocol": "TCP", "description": "Kerberos Authentication",     "category": "authentication"},
    106:   {"service": "pop3pw",     "protocol": "TCP", "description": "POP3 Password",               "category": "email"},
    110:   {"service": "pop3",       "protocol": "TCP", "description": "POP3 Mail",                   "category": "email"},
    111:   {"service": "rpcbind",    "protocol": "TCP", "description": "RPC Bind / Portmapper",       "category": "rpc"},
    113:   {"service": "ident",      "protocol": "TCP", "description": "Ident / Auth Service",        "category": "authentication"},
    119:   {"service": "nntp",       "protocol": "TCP", "description": "Network News Transfer",       "category": "information"},
    123:   {"service": "ntp",        "protocol": "UDP", "description": "Network Time Protocol",       "category": "system"},
    135:   {"service": "msrpc",      "protocol": "TCP", "description": "Microsoft RPC",               "category": "rpc"},
    137:   {"service": "netbios-ns", "protocol": "UDP", "description": "NetBIOS Name Service",        "category": "file_share"},
    138:   {"service": "netbios-dgm","protocol": "UDP", "description": "NetBIOS Datagram",            "category": "file_share"},
    139:   {"service": "netbios-ssn","protocol": "TCP", "description": "NetBIOS Session",             "category": "file_share"},
    143:   {"service": "imap",       "protocol": "TCP", "description": "IMAP Mail",                   "category": "email"},
    161:   {"service": "snmp",       "protocol": "UDP", "description": "SNMP",                        "category": "network"},
    162:   {"service": "snmptrap",   "protocol": "UDP", "description": "SNMP Trap",                   "category": "network"},
    179:   {"service": "bgp",        "protocol": "TCP", "description": "Border Gateway Protocol",     "category": "routing"},
    194:   {"service": "irc",        "protocol": "TCP", "description": "IRC Chat",                    "category": "messaging"},
    199:   {"service": "smux",       "protocol": "TCP", "description": "SNMP Unix Multiplexer",       "category": "network"},
    220:   {"service": "imap3",      "protocol": "TCP", "description": "IMAP3",                       "category": "email"},
    389:   {"service": "ldap",       "protocol": "TCP", "description": "LDAP Directory",              "category": "authentication"},
    443:   {"service": "https",      "protocol": "TCP", "description": "HTTPS Web Server",            "category": "web"},
    445:   {"service": "microsoft-ds","protocol": "TCP", "description": "SMB/CIFS File Sharing",      "category": "file_share"},
    464:   {"service": "kpasswd",    "protocol": "TCP", "description": "Kerberos Password",            "category": "authentication"},
    465:   {"service": "smtps",      "protocol": "TCP", "description": "SMTP over SSL",               "category": "email"},
    497:   {"service": "retrospect", "protocol": "TCP", "description": "Retrospect Backup",           "category": "backup"},
    500:   {"service": "isakmp",     "protocol": "UDP", "description": "IKE/ISAKMP VPN",              "category": "vpn"},
    512:   {"service": "exec",       "protocol": "TCP", "description": "Remote Process Execution",    "category": "remote_access"},
    513:   {"service": "login",      "protocol": "TCP", "description": "Remote Login (rlogin)",       "category": "remote_access"},
    514:   {"service": "shell",      "protocol": "TCP", "description": "Remote Shell (rsh)",          "category": "remote_access"},
    515:   {"service": "printer",    "protocol": "TCP", "description": "LPD Print Service",           "category": "printing"},
    520:   {"service": "rip",        "protocol": "UDP", "description": "RIP Routing",                 "category": "routing"},
    523:   {"service": "ibm-db2",    "protocol": "TCP", "description": "IBM DB2 Database",            "category": "database"},
    530:   {"service": "rpc",        "protocol": "TCP", "description": "RPC Procedure Call",          "category": "rpc"},
    543:   {"service": "klogin",     "protocol": "TCP", "description": "Kerberos Login",              "category": "remote_access"},
    544:   {"service": "kshell",     "protocol": "TCP", "description": "Kerberos Shell",              "category": "remote_access"},
    548:   {"service": "afp",        "protocol": "TCP", "description": "Apple Filing Protocol",       "category": "file_share"},
    554:   {"service": "rtsp",       "protocol": "TCP", "description": "Real Time Streaming",         "category": "streaming"},
    587:   {"service": "submission", "protocol": "TCP", "description": "SMTP Submission",             "category": "email"},
    593:   {"service": "http-rpc",   "protocol": "TCP", "description": "HTTP RPC Epmap",              "category": "rpc"},
    631:   {"service": "ipp",        "protocol": "TCP", "description": "Internet Printing",           "category": "printing"},
    636:   {"service": "ldaps",      "protocol": "TCP", "description": "LDAP over SSL",               "category": "authentication"},
    646:   {"service": "ldp",        "protocol": "TCP", "description": "LDP Label Distribution",      "category": "routing"},
    873:   {"service": "rsync",      "protocol": "TCP", "description": "rsync File Sync",             "category": "file_transfer"},
    902:   {"service": "vmware-auth","protocol": "TCP", "description": "VMware Auth Daemon",          "category": "virtualization"},
    993:   {"service": "imaps",      "protocol": "TCP", "description": "IMAP over SSL",               "category": "email"},
    995:   {"service": "pop3s",      "protocol": "TCP", "description": "POP3 over SSL",               "category": "email"},
    # ── Registered ports (1024-49151) ───────────────────────────────────
    1025:  {"service": "nfs-or-iiop","protocol": "TCP", "description": "NFS / IIOP",                  "category": "file_share"},
    1080:  {"service": "socks",      "protocol": "TCP", "description": "SOCKS Proxy",                 "category": "proxy"},
    1194:  {"service": "openvpn",    "protocol": "UDP", "description": "OpenVPN",                     "category": "vpn"},
    1241:  {"service": "nessus",     "protocol": "TCP", "description": "Nessus Scanner",               "category": "security"},
    1433:  {"service": "mssql",      "protocol": "TCP", "description": "Microsoft SQL Server",        "category": "database"},
    1434:  {"service": "mssql-udp",  "protocol": "UDP", "description": "MSSQL Browser",               "category": "database"},
    1521:  {"service": "oracle",     "protocol": "TCP", "description": "Oracle Database",             "category": "database"},
    1524:  {"service": "ingreslock", "protocol": "TCP", "description": "Ingres Database Lock",        "category": "database"},
    1723:  {"service": "pptp",       "protocol": "TCP", "description": "PPTP VPN",                    "category": "vpn"},
    1725:  {"service": "iden-ralp",  "protocol": "TCP", "description": "iden RALP",                   "category": "messaging"},
    1883:  {"service": "mqtt",       "protocol": "TCP", "description": "MQTT IoT Protocol",           "category": "iot"},
    2049:  {"service": "nfs",        "protocol": "TCP", "description": "Network File System",         "category": "file_share"},
    2082:  {"service": "cpanel",     "protocol": "TCP", "description": "cPanel HTTP",                 "category": "web"},
    2083:  {"service": "cpanels",    "protocol": "TCP", "description": "cPanel HTTPS",                "category": "web"},
    2086:  {"service": "whm",        "protocol": "TCP", "description": "WHM HTTP",                    "category": "web"},
    2087:  {"service": "whms",       "protocol": "TCP", "description": "WHM HTTPS",                   "category": "web"},
    2100:  {"service": "oracle-xe",  "protocol": "TCP", "description": "Oracle XE FTP",               "category": "database"},
    2181:  {"service": "zookeeper",  "protocol": "TCP", "description": "ZooKeeper",                   "category": "middleware"},
    2222:  {"service": "eht-alt",    "protocol": "TCP", "description": "SSH Alternate",               "category": "remote_access"},
    2375:  {"service": "docker",     "protocol": "TCP", "description": "Docker API (unencrypted)",    "category": "virtualization"},
    2376:  {"service": "docker-tls", "protocol": "TCP", "description": "Docker API (TLS)",           "category": "virtualization"},
    2500:  {"service": "rtsserv",    "protocol": "TCP", "description": "RTS Server",                  "category": "messaging"},
    3000:  {"service": "ppp",        "protocol": "TCP", "description": "Grafana / Node.js Dev",       "category": "web"},
    3001:  {"service": "nessus-web", "protocol": "TCP", "description": "Nessus Web UI",               "category": "security"},
    3128:  {"service": "squid",      "protocol": "TCP", "description": "Squid Web Proxy",             "category": "proxy"},
    3260:  {"service": "iscsi",      "protocol": "TCP", "description": "iSCSI Target",                "category": "storage"},
    3306:  {"service": "mysql",      "protocol": "TCP", "description": "MySQL Database",              "category": "database"},
    3389:  {"service": "rdp",        "protocol": "TCP", "description": "Remote Desktop Protocol",     "category": "remote_access"},
    3460:  {"service": "edM-light",  "protocol": "TCP", "description": "EDM Manager",                 "category": "middleware"},
    3632:  {"service": "distcc",     "protocol": "TCP", "description": "Distributed Compiler",        "category": "development"},
    3690:  {"service": "svn",        "protocol": "TCP", "description": "Subversion",                  "category": "development"},
    4369:  {"service": "epmd",       "protocol": "TCP", "description": "Erlang Port Mapper",          "category": "middleware"},
    4400:  {"service": "ds-srv",     "protocol": "TCP", "description": "Directory Services",          "category": "authentication"},
    4500:  {"service": "nat-t",      "protocol": "UDP", "description": "IPSec NAT Traversal",        "category": "vpn"},
    4567:  {"service": "tram",       "protocol": "TCP", "description": "TRAM",                        "category": "middleware"},
    4848:  {"service": "glassfish",  "protocol": "TCP", "description": "GlassFish Admin",             "category": "web"},
    5000:  {"service": "upnp",       "protocol": "TCP", "description": "UPnP / Flask Dev",            "category": "web"},
    5003:  {"service": "filemaker",  "protocol": "TCP", "description": "FileMaker Database",          "category": "database"},
    5060:  {"service": "sip",        "protocol": "UDP", "description": "SIP VoIP",                    "category": "voip"},
    5061:  {"service": "sips",       "protocol": "TCP", "description": "SIP over TLS",                "category": "voip"},
    5222:  {"service": "xmpp",       "protocol": "TCP", "description": "XMPP Messaging",              "category": "messaging"},
    5269:  {"service": "xmpp-s2s",   "protocol": "TCP", "description": "XMPP Server-to-Server",      "category": "messaging"},
    5353:  {"service": "mdns",       "protocol": "UDP", "description": "mDNS / Bonjour",              "category": "dns"},
    5355:  {"service": "llmnr",      "protocol": "UDP", "description": "LLMNR Name Resolution",      "category": "dns"},
    5432:  {"service": "postgresql", "protocol": "TCP", "description": "PostgreSQL Database",         "category": "database"},
    5555:  {"service": "freeciv",    "protocol": "TCP", "description": "Freeciv / Android Debug",     "category": "development"},
    5672:  {"service": "amqp",       "protocol": "TCP", "description": "AMQP RabbitMQ",               "category": "middleware"},
    5800:  {"service": "vnc-http",   "protocol": "TCP", "description": "VNC over HTTP",               "category": "remote_access"},
    5900:  {"service": "vnc",        "protocol": "TCP", "description": "VNC Remote Desktop",          "category": "remote_access"},
    5901:  {"service": "vnc-1",      "protocol": "TCP", "description": "VNC Display :1",              "category": "remote_access"},
    5984:  {"service": "couchdb",    "protocol": "TCP", "description": "CouchDB HTTP API",            "category": "database"},
    5985:  {"service": "winrm",      "protocol": "TCP", "description": "WinRM HTTP",                  "category": "remote_access"},
    5986:  {"service": "winrms",     "protocol": "TCP", "description": "WinRM HTTPS",                 "category": "remote_access"},
    6060:  {"service": "x11",        "protocol": "TCP", "description": "X11 Window System",           "category": "remote_access"},
    6379:  {"service": "redis",      "protocol": "TCP", "description": "Redis Key-Value Store",       "category": "database"},
    6443:  {"service": "k8s-api",    "protocol": "TCP", "description": "Kubernetes API",              "category": "virtualization"},
    6556:  {"service": "checkmk",    "protocol": "TCP", "description": "Check_MK Monitoring",         "category": "monitoring"},
    7001:  {"service": "weblogic",   "protocol": "TCP", "description": "Oracle WebLogic",             "category": "web"},
    7002:  {"service": "weblogic-s", "protocol": "TCP", "description": "WebLogic SSL",                "category": "web"},
    7070:  {"service": "realserver", "protocol": "TCP", "description": "RealServer Admin",            "category": "streaming"},
    7210:  {"service": "fms",        "protocol": "TCP", "description": "FMS Management",              "category": "middleware"},
    7777:  {"service": "cbt",        "protocol": "TCP", "description": "Oracle CBt / HTTP Alt",       "category": "web"},
    8000:  {"service": "http-alt",   "protocol": "TCP", "description": "HTTP Alternate",              "category": "web"},
    8008:  {"service": "http-alt2",  "protocol": "TCP", "description": "HTTP Alternate 2",            "category": "web"},
    8009:  {"service": "ajp13",      "protocol": "TCP", "description": "Apache JServ Protocol",      "category": "web"},
    8080:  {"service": "http-proxy", "protocol": "TCP", "description": "HTTP Proxy / Tomcat",         "category": "web"},
    8081:  {"service": "sunproxy",   "protocol": "TCP", "description": "Sun Proxy Admin",             "category": "proxy"},
    8088:  {"service": "radan-http", "protocol": "TCP", "description": "HTTP Alternate",              "category": "web"},
    8181:  {"service": "glassfish2", "protocol": "TCP", "description": "GlassFish HTTP",              "category": "web"},
    8222:  {"service": "vmware-vmrc","protocol": "TCP", "description": "VMware VMRC",                 "category": "virtualization"},
    8333:  {"service": "bitcoin",    "protocol": "TCP", "description": "Bitcoin RPC",                 "category": "cryptocurrency"},
    8443:  {"service": "https-alt",  "protocol": "TCP", "description": "HTTPS Alternate",             "category": "web"},
    8500:  {"service": "coldfusion", "protocol": "TCP", "description": "Adobe ColdFusion",            "category": "web"},
    8545:  {"service": "eth-rpc",    "protocol": "TCP", "description": "Ethereum RPC",                "category": "cryptocurrency"},
    8888:  {"service": "sun-answer", "protocol": "TCP", "description": "Sun Answerbook / Jupyter",    "category": "web"},
    9000:  {"service": "php-fpm",    "protocol": "TCP", "description": "PHP-FPM / SonarQube",         "category": "web"},
    9001:  {"service": "tor-orport", "protocol": "TCP", "description": "Tor ORPort / PHP-FPM",       "category": "web"},
    9090:  {"service": "zeus-admin", "protocol": "TCP", "description": "Prometheus / Zeus Admin",     "category": "monitoring"},
    9091:  {"service": "tor-dirport","protocol": "TCP", "description": "Tor DirPort / Sendmail",     "category": "web"},
    9100:  {"service": "jetdirect",  "protocol": "TCP", "description": "HP JetDirect Printing",      "category": "printing"},
    9200:  {"service": "elasticsearch","protocol": "TCP", "description": "Elasticsearch HTTP",       "category": "database"},
    9300:  {"service": "es-transport","protocol": "TCP", "description": "Elasticsearch Transport",   "category": "database"},
    9443:  {"service": "tungsten",   "protocol": "TCP", "description": "Tungsten HTTPS",              "category": "web"},
    9600:  {"service": "odbc",       "protocol": "TCP", "description": "ODBC Data Source",            "category": "database"},
    9929:  {"service": "nmsg",       "protocol": "TCP", "description": "NMSG",                        "category": "network"},
    10000: {"service": "webmin",     "protocol": "TCP", "description": "Webmin Admin Panel",          "category": "web"},
    10051: {"service": "zabbix-tr","protocol": "TCP", "description": "Zabbix Trapper",              "category": "monitoring"},
    10250: {"service": "k8s-cadvisor","protocol": "TCP", "description": "Kubernetes cAdvisor",      "category": "virtualization"},
    11211: {"service": "memcached",  "protocol": "TCP", "description": "Memcached",                   "category": "database"},
    11333: {"service": "lscp",       "protocol": "TCP", "description": "LSCP",                        "category": "middleware"},
    15672: {"service": "rabbitmq-mgmt","protocol": "TCP", "description": "RabbitMQ Management",     "category": "middleware"},
    16010: {"service": "hbase",      "protocol": "TCP", "description": "HBase Master",               "category": "database"},
    18091: {"service": "couchbase-s","protocol": "TCP", "description": "Couchbase SSL",             "category": "database"},
    27017: {"service": "mongodb",    "protocol": "TCP", "description": "MongoDB",                     "category": "database"},
    27018: {"service": "mongodb-s",  "protocol": "TCP", "description": "MongoDB Shard",              "category": "database"},
    27019: {"service": "mongodb-cs", "protocol": "TCP", "description": "MongoDB Config Server",     "category": "database"},
    28017: {"service": "mongodb-web","protocol": "TCP", "description": "MongoDB Web Interface",     "category": "database"},
    29092: {"service": "kafka-jmx",  "protocol": "TCP", "description": "Kafka JMX",                  "category": "middleware"},
    50000: {"service": "db2c",       "protocol": "TCP", "description": "DB2 Connect",                "category": "database"},
    50070: {"service": "hdfs-nn",    "protocol": "TCP", "description": "HDFS NameNode",              "category": "storage"},
}


def get_service_by_port(port: int) -> Optional[Dict]:
    """Get service information for a port number.

    Args:
        port: Port number to look up.

    Returns:
        Service info dict, or None if not found.
    """
    return PORT_SERVICES.get(port)


def get_ports_by_category(category: str) -> List[int]:
    """Get all ports belonging to a service category.

    Args:
        category: Category name (e.g., "web", "database", "vpn").

    Returns:
        Sorted list of port numbers in the category.
    """
    return sorted(
        port for port, info in PORT_SERVICES.items()
        if info.get("category") == category
    )


def get_ports_by_service(service_name: str) -> List[int]:
    """Get all ports for a service name (case-insensitive partial match).

    Args:
        service_name: Service name to search for.

    Returns:
        List of matching port numbers.
    """
    svc_lower = service_name.lower()
    return sorted(
        port for port, info in PORT_SERVICES.items()
        if svc_lower in info.get("service", "").lower()
    )


def search_ports(keyword: str) -> List[Dict]:
    """Search port database by keyword.

    Args:
        keyword: Search term (matches service, description, category).

    Returns:
        List of matching entries with port number included.
    """
    kw_lower = keyword.lower()
    results = []
    for port, info in PORT_SERVICES.items():
        search_text = f"{port} {info.get('service', '')} {info.get('description', '')} {info.get('category', '')}".lower()
        if kw_lower in search_text:
            results.append({"port": port, **info})
    return sorted(results, key=lambda x: x["port"])

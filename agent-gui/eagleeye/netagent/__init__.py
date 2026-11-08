"""The network agent: reads routers and switches over SNMP (read only) and works out what is
connected where.

    snmp.py      our own SNMP client (v2c, v3 USM with SHA/SHA-2 + AES-128)
    recorded.py  answers recorded as net-snmp text (snmpwalk -On), for tests and dry runs
    collect.py   one device: system, interfaces, addresses, ARP, routes, MAC table, CDP/LLDP
    crawl.py     follow CDP/LLDP neighbours inside the allowed ranges; links, hosts, locations
    truth.py     score a crawl against a lab's ground-truth CSVs
"""

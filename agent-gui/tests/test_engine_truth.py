"""Scoring an engine's result against a ground-truth list (the lab's lab-devices.csv)."""

from __future__ import annotations

from eagleeye.pipeline.record import HostRecord
from eagleeye.stages.scan_own import load_truth, parse_truth_services, score_against_truth


def test_truth_services_parse_ports_products_and_versions():
    got = parse_truth_services("22 OpenSSH 10.2p1; 80/443 nginx 1.28.3; 8080 Apache httpd 2.4.62; "
                               "udp161 net-snmp 5.9.4; 135 RPC; ?")
    assert got[0] == {"port": 22, "protocol": "tcp", "product": "OpenSSH", "version": "10.2p1"}
    assert [g["port"] for g in got] == [22, 80, 443, 8080, 161, 135]
    assert got[3]["product"] == "Apache httpd" and got[4]["protocol"] == "udp"
    assert got[5] == {"port": 135, "protocol": "tcp", "product": "RPC", "version": ""}


def test_score_against_truth(tmp_path):
    csv_path = tmp_path / "truth.csv"
    csv_path.write_text(
        "ip,mac,name,device,os,services,notes\n"
        '192.168.36.50,00:0C:29:04:6C:77,lab-ubuntu,server,Ubuntu,"22 OpenSSH 10.2p1; 27017 MongoDB 8.0.3",x\n'
        "192.168.36.60,?,LAB-WIN11,workstation,Windows 11,445 SMB,x\n"
        "192.168.0.1,98:48:27:cb:55:6c,router,network,?,80 BusyBox,x\n", encoding="utf-8")
    truth = load_truth(csv_path)
    hosts = [HostRecord(ip="192.168.36.50", mac="00:0c:29:04:6c:77", hostname="LAB-UBUNTU",
                        ports=[{"port": 22, "protocol": "tcp", "product": "OpenSSH", "version": "10.2p1"},
                               {"port": 27017, "protocol": "tcp", "product": "MongoDB", "version": "6.1 or later"}])]
    s = score_against_truth(hosts, truth, "192.168.36.0/24")
    assert (s["devices"], s["found"], s["missing"]) == (2, 1, ["192.168.36.60"])     # the router is outside
    assert (s["mac_right"], s["mac_checked"], s["name_right"], s["name_checked"]) == (1, 1, 1, 1)
    assert (s["ports_found"], s["ports"], s["product_right"], s["version_right"], s["version_checked"]) == (2, 2, 2, 1, 2)   # services of found devices only
    assert s["wrong"] == [{"ip": "192.168.36.50", "port": 27017, "field": "version", "truth": "8.0.3", "got": "6.1 or later"}]

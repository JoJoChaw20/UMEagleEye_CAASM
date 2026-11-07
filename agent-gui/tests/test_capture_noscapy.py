"""Run by test_capture.py in a fresh interpreter in which scapy cannot be imported: the
built-in capture, its decoding and the network helpers must work without it. Frames are
hand-made bytes (no scapy to build them)."""

from __future__ import annotations

import struct
import sys


def _frame_arp(ip: bytes, mac: bytes) -> bytes:
    return (b"\xff" * 6 + mac + b"\x08\x06" + b"\x00\x01\x08\x00\x06\x04\x00\x01" + mac + ip
            + b"\x00" * 6 + bytes([192, 168, 0, 139]))


def _frame_ssdp(ip: bytes, mac: bytes) -> bytes:
    body = b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nSERVER: Linux UPnP/1.0 Samsung SmartTV\r\n\r\n"
    udp = struct.pack(">HHHH", 50000, 1900, 8 + len(body), 0) + body
    iph = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, ip, bytes([239, 255, 255, 250]))
    return b"\x01\x00\x5e\x7f\xff\xfa" + mac + b"\x08\x00" + iph + udp


def run() -> None:
    assert "scapy" in sys.modules and sys.modules["scapy"] is None
    from eagleeye import netinfo, vendor
    from eagleeye.passive import PassiveSuite
    from eagleeye.passive.capture import CaptureHub
    from eagleeye.passive.sniffers import InterfaceChooser

    class Source:
        name, error = "fake", None

        def open(self, deliver):
            return True

        def select(self, adapter):
            pass

        def pump(self, stop, seconds):
            stop.wait(0.01)
            return True

        def close(self):
            pass

    adapters = [{"name": "Wi-Fi", "description": "Wi-Fi", "ips": ["192.168.0.139"],
                 "mac": "14:13:33:c3:f6:03", "index": 2}]
    chooser = InterfaceChooser(probe=lambda: ("192.168.0.139", adapters),
                               network_of=lambda ip: {"local_ip": ip, "subnet": "192.168.0.0/24", "gateway_ip": None})
    hub = CaptureHub(Source(), chooser)
    suite = PassiveSuite(chooser=chooser, backend="native", make_hub=lambda name, ch: hub)
    assert suite.start(), suite.problems()
    chooser.refresh()
    router, tv = bytes.fromhex("984827cb556c"), bytes.fromhex("8c79f5001122")
    hub.deliver(_frame_arp(bytes([192, 168, 0, 1]), router))
    hub.deliver(_frame_ssdp(bytes([192, 168, 0, 60]), tv))
    seen = {h.ip: h.mac for h in suite.arp.drain()}
    assert seen == {"192.168.0.1": "98:48:27:cb:55:6c", "192.168.0.60": "8c:79:f5:00:11:22"}, seen
    assert "Samsung" in str(suite.ssdp.get_mac_info("8c:79:f5:00:11:22"))
    suite.stop()
    # The network helpers fall back to the adapter list; the vendor list to IEEE's.
    assert netinfo._scapy_routes() == []
    assert vendor.mac_vendor("98:48:27:cb:55:6c") == "TP-LINK TECHNOLOGIES CO.,LTD."
    assert not any(k.startswith("scapy.") for k in sys.modules)
    print("ok")

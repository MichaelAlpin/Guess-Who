import pyshark
from mac_vendor_lookup import MacLookup
import os


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """

        # Load file
        if os.path.exists(pcap_path):
            self.packets = pyshark.FileCapture(pcap_path)
        else:
            print("File path doesn't exist! Initialized an empty analyzer")
            self.packets = []

        # Save basic stats
        self.total_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

        for pkt in self.packets:
            self.total_count += 1
            if "tcp" in pkt:
                self.tcp_count += 1
            elif "udp" in pkt:
                self.udp_count += 1
            elif "icmp" in pkt:
                self.icmp_count += 1

        self.other_count = (
            self.total_count - self.tcp_count - self.udp_count - self.icmp_count
        )

    def get_ips(self):
        """
        Returns a list of ip addresses (strings) that appear in the pcap
        """

        ip_list = []

        for pkt in self.packets:
            if "ip" in pkt:
                if pkt.ip.src not in ip_list:
                    ip_list.append(pkt.ip.src)
                if pkt.ip.dst not in ip_list:
                    ip_list.append(pkt.ip.dst)
            if "arp" in pkt:
                if pkt.arp.src_proto_ipv4 not in ip_list:
                    ip_list.append(pkt.arp.src_proto_ipv4)
                if pkt.arp.dst_proto_ipv4 not in ip_list:
                    ip_list.append(pkt.arp.dst_proto_ipv4)

        return ip_list

    def get_macs(self):
        """
        Returns a list of MAC addresses (strings) that appear in the pcap
        """

        mac_list = []

        for pkt in self.packets:
            if "eth" in pkt:
                if pkt.eth.src not in mac_list:
                    mac_list.append(pkt.eth.src)
                if pkt.eth.dst not in mac_list:
                    mac_list.append(pkt.eth.dst)

        return mac_list

    def get_info_by_mac(self, mac):
        """
        Returns a dict with all information about the device with given MAC address
        """

        info = {"MAC": mac, "IP": "Unknown", "VENDOR": "Unknown"}

        if mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
            info["IP"] = "<MAC is Broadcast>"
            info["VENDOR"] = "<MAC is Broadcast>"
            return info

        # Check the VENDOR
        info["VENDOR"] = MacLookup().lookup(mac)

        # Check the IP
        for pkt in self.packets:
            if "eth" in pkt:
                if pkt.eth.src == mac:
                    # Check ARP information
                    if "arp" in pkt:
                        info["IP"] = pkt.arp.src_proto_ipv4

                    # Check IP information
                    if "ip" in pkt:
                        info["IP"] = pkt.ip.src
                elif pkt.eth.dst == mac:
                    # Check ARP information
                    if "arp" in pkt and pkt.arp.opcode == "2":
                        info["IP"] = pkt.arp.dst_proto_ipv4

                    # Check IP information
                    if "ip" in pkt:
                        info["IP"] = pkt.ip.dst
        return info

    def get_info_by_ip(self, ip):
        """
        Returns a dict with all information about the device with given IP address
        """

        info = {"MAC": "Unknown", "IP": ip, "VENDOR": "Unknown"}

        # Check the IP
        for pkt in self.packets:
            if "eth" in pkt:
                # Check ARP information
                if "arp" in pkt:
                    if pkt.arp.src_proto_ipv4 == ip:
                        info["MAC"] = pkt.eth.src
                    elif pkt.arp.opcode == "2" and pkt.arp.dst_proto_ipv4 == ip:
                        info["MAC"] = pkt.eth.dst

                # Check IP information
                if "ip" in pkt:
                    if pkt.ip.src == ip:
                        info["MAC"] = pkt.eth.src
                    elif pkt.ip.dst == ip:
                        info["MAC"] = pkt.eth.dst

        # Check the VENDOR, if MAC address was found
        if info["MAC"] != "Unknown":
            info["VENDOR"] = MacLookup().lookup(info["MAC"])

        return info

    def get_info(self):
        """
        Returns a list of dicts with information about every device in the pcap
        """
        return [self.get_info_by_mac(mac) for mac in self.get_macs()]

    def __repr__(self):
        return f"Network analyzer | {self.total_count} Packets | {self.tcp_count} TCP | {self.udp_count} UDP | {self.icmp_count} ICMP | {self.other_count} Other"

    def __str__(self):
        return f"Network analyzer | {self.total_count} Packets | {self.tcp_count} TCP | {self.udp_count} UDP | {self.icmp_count} ICMP | {self.other_count} Other"

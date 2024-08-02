import logging
import tkinter as tk
from tkinter import scrolledtext, filedialog, simpledialog
from scapy.all import sniff, Ether, IP, TCP, UDP , DNS
from scapy.layers.http import HTTP
import threading
import time
import os


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer")

        # Create a menu bar
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # Add "File" menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Start Sniffing", command=self.start_sniffing)
        self.file_menu.add_command(label="Stop Sniffing", command=self.stop_sniffing)
        self.file_menu.add_command(label="Export to PCAP", command=self.export_to_pcap)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)

        # Add "Filter" menu
        self.filter_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Filter", menu=self.filter_menu)
        self.filter_menu.add_command(label="Set Filter", command=self.set_filter)

        # Add "Search" menu
        self.search_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Search", menu=self.search_menu)
        self.search_menu.add_command(label="Search Packets", command=self.search_packets)

        # Create the main text area
        self.text_area = scrolledtext.ScrolledText(self.root, width=100, height=40)
        self.text_area.pack()

        # Configure logging
        logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO)

        # Flag to control sniffing
        self.sniffing = False
        self.packet_list = []
        self.filter_criteria = None

    def packet_callback(self, packet):
        if self.filter_criteria and not self.apply_filter(packet):
            return

        self.packet_list.append(packet)
        packet_summary = self.decode_packet(packet)

        self.text_area.insert(tk.END, packet_summary + "\n")
        self.text_area.see(tk.END)

        # Log packet details to file
        logging.info(packet_summary.strip())

    def decode_packet(self, packet):
        details = ""
        if Ether in packet:
            details += f"Ethernet Frame: {packet[Ether].summary()}\n"
        if IP in packet:
            details += f"IP Packet: {packet[IP].summary()}\n"
        if TCP in packet:
            details += f"TCP Segment: {packet[TCP].summary()}\n"
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                if HTTP in packet:
                    details += f"HTTP Data: {packet[HTTP].summary()}\n"
            # Check if packet contains FTP data (ports 20 and 21)
            if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                # Extract and decode raw data for FTP
                if len(packet[TCP].payload) > 0:
                    ftp_data = packet[TCP].payload.load.decode(errors='ignore')
                    details += f"FTP Data: {ftp_data}\n"
        if UDP in packet:
            details += f"UDP Datagram: {packet[UDP].summary()}\n"
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                if DNS in packet:
                    details += f"DNS Data: {packet[DNS].summary()}\n"
        return details

    def apply_filter(self, packet):
        if self.filter_criteria['ip']:
            if IP not in packet or (
                    packet[IP].src != self.filter_criteria['ip'] and packet[IP].dst != self.filter_criteria['ip']):
                return False
        if self.filter_criteria['protocol']:
            if self.filter_criteria['protocol'] == 'TCP' and TCP not in packet:
                return False
            if self.filter_criteria['protocol'] == 'UDP' and UDP not in packet:
                return False
            if self.filter_criteria['protocol'] == 'HTTP' and (
                    TCP not in packet or (packet[TCP].dport != 80 and packet[TCP].sport != 80)):
                return False
            if self.filter_criteria['protocol'] == 'DNS' and (
                    UDP not in packet or (packet[UDP].dport != 53 and packet[UDP].sport != 53)):
                return False
        if self.filter_criteria['port']:
            if TCP in packet and (
                    packet[TCP].sport != self.filter_criteria['port'] and packet[TCP].dport != self.filter_criteria[
                'port']):
                return False
            if UDP in packet and (
                    packet[UDP].sport != self.filter_criteria['port'] and packet[UDP].dport != self.filter_criteria[
                'port']):
                return False
        return True

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            # Run sniffing in a separate thread to avoid blocking the GUI
            sniff_thread = threading.Thread(target=self.sniff_packets)
            sniff_thread.daemon = True
            sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False

    def sniff_packets(self):
        while self.sniffing:
            sniff(prn=self.packet_callback, store=0, count=1)

    def export_to_pcap(self):
        if not self.packet_list:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            from scapy.utils import wrpcap
            wrpcap(file_path, self.packet_list)

    def set_filter(self):
        self.filter_criteria = {
            'ip': simpledialog.askstring("Filter", "Enter IP address to filter:"),
            'protocol': simpledialog.askstring("Filter", "Enter protocol to filter (TCP, UDP, HTTP, DNS):"),
            'port': simpledialog.askinteger("Filter", "Enter port to filter:")
        }

    def search_packets(self):
        search_term = simpledialog.askstring("Search", "Enter search term:")
        if not search_term:
            return

        results = [packet for packet in self.packet_list if search_term in self.decode_packet(packet)]
        self.text_area.delete('1.0', tk.END)
        for result in results:
            self.text_area.insert(tk.END, self.decode_packet(result) + "\n")
        self.text_area.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

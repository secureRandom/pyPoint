import logging
import xml.dom.minidom
from suds.client import Client
from suds.sax.element import Element
from suds.sax.element import Attribute
from suds.transport.https import WindowsHttpAuthenticated
import urllib2
from ntlm import HTTPNtlmAuthHandler
import staticCache
from suds import transport
import MySQLdb

sqlHost = "localhost"
sqlUser = "sqluser"
sqlPass = "sqlpasshere"
sqlDB   = "sqldbhere"

site_url = 'http://untranetsite.com/'
listName = 'text_list_name'
user = 'domain\\user'
rawPassword = raw_input("Enter the password: ")
ntlm = WindowsHttpAuthenticated(username=user,password=rawPassword)

#logging.basicConfig(level=logging.INFO)
#logging.getLogger('suds.client').setLevel(logging.DEBUG)
#logging.getLogger('suds.transport').setLevel(logging.DEBUG)
#logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)

def main():
	#c = Client(url='%s_vti_bin/Lists.asmx?WSDL' % (site_url_1),transport=ntlm,cache=staticCache.StaticSudsCache())
	c = Client(url='%s_vti_bin/Lists.asmx?WSDL' % (site_url),transport=ntlm)
	
	sqlselect = "select inet_ntoa(host), service, msg from results where riskval = 3"
	conn   = MySQLdb.connect(host=sqlHost,user=sqlUser,passwd=sqlPass,db=sqlDB)
	with conn:
        	cursor = conn.cursor()
        	cursor.execute(sqlHigh)
        	numrows = int(cursor.rowcount)
        	for i in range(numrows):
                	row = cursor.fetchone()
			message = \
			"""<?xml version="1.0" encoding="UTF-8"?>
        		<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        		<soap:Body>
                		<UpdateListItems xmlns="http://schemas.microsoft.com/sharepoint/soap/">
                		<listName>Vulnerabilities</listName>
                		<updates>
                		<Batch OnError="Continue" ListVersion="1">
                		<Method ID="1" Cmd="New">
                		<Field Name="Title">%s</Field>
                		<Field Name="Service">%s</Field>
                		<Field Name="Risk">High</Field>
                		<Field Name="Vulnerability_x0020_Synopsis">%s</Field>
                		</Method>
                		</Batch>
                		</updates>
                		</UpdateListItems>
        		</soap:Body>
        		</soap:Envelope>""" % (row[0], row[1], row[2])

			c.service.UpdateListItems(__inject={'msg':message})

if __name__=="__main__":main()

import string
from unicodedata import name
import xml.etree.ElementTree as ET
import sys


dic_nmap = {}

tree = ET.parse("/home/vitor.luz/script/nmap.xml")
root = tree.getroot()


def parse_xml():
    for i in root.iter('nmaprun'):
        for nmaprun in i:
            if nmaprun.tag == 'host':
                for host in nmaprun:
                    if host.tag == 'address':
                        if(':' not in host.attrib['addr']):
                            dic_nmap['ip_v4'] = host.attrib['addr']
                            dic_nmap['addrtype'] = host.attrib['addrtype']
                    if host.tag == 'ports':
                        for port in host :
                            if port.tag == 'port':
                                dic_nmap['protocol'] = port.attrib['protocol']
                                dic_nmap['portid'] = port.attrib['portid']
                                for itens in port:
                                    if itens.tag == 'state':
                                        dic_nmap['state'] = itens.attrib['state']
                                    if itens.tag == 'service:':
                                        try:
                                            dic_nmap['state'] = itens.attrib['name']
                                        except:
                                            dic_nmap['state'] = ''
                                        try:
                                            dic_nmap['version'] = itens.attrib['version']
                                        except:
                                            dic_nmap['version'] = ''
                                        try:
                                            dic_nmap['product'] = itens.attrib['product']
                                        except:
                                            dic_nmap['product'] = ''
                                        try:
                                            dic_nmap['cpe'] = itens.attrib['cpe']
                                        except:
                                            dic_nmap['cpe'] = ''

                                        

def main():
    parse_xml()
    

if __name__ == '__main__':
    main()

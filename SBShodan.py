#!/usr/bin/env python

import ftplib
import shodan
import sys
from netaddr import IPNetwork
import argparse
import socket
import re
import iptools


SHODAN_API_KEY="Your Shodan API Key"
api=shodan.Shodan(SHODAN_API_KEY)
if len(sys.argv)==1:
    print("Usage: %s <search query>" %sys.argv[0])
    sys.exit(1)
def anonymousLogin(hostname):
    try:
        ftp=ftplib.FTP(hostname)
        ftp.login('anonymous','')
        print '\n[*] ' + str(hostname) +' FTP Anonymous Logon Succeeded.'
        return ftp
    except Exception, e:
        print '\n[-] ' + str(hostname) +' FTP Anonymous Logon Failed.'
        return False

def command_line_parser():
    parser=argparse.ArgumentParser(add_help=False,description="SBShodan is a tool for searching Shodan using its API.")
    parser.add_argument("-ip",metavar="192.168.10.100",default=False,help="Use this if you have a signle target")
    parser.add_argument("-cidr",metavar="192.168.10.1/24",default=False,help="Use this if you have a CIDR for input")
    parser.add_argument("-f", metavar="ips.txt", default=None, help="A file containing your Target List")
    parser.add_argument('-h','-?','--h','--help','-help',action="store_true",help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.h:
        parser.print_help()
        sys.exit()
    return args.ip,args.cidr,args.f
def check_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET,ip)
    except AttributeError:
        try:
            socket.inet_aton(ip)
        except socket.error:
            return False
        return ip.count('.')==3
    except socket.error:
        return False
    return True

def check_cidr(cidr):
    temp=re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}/\d{1,2}$')
    if temp.match(cidr):
        ipp,mask=cidr.split('/')
        if check_ip(ipp):
            if int(mask) > 32:
                return False
            else:
                return False
            return True
        return False

def search_single_ip(ip_to_search):
    print ("[*] Searching Shodan for a given IP address : " + ip_to_search + "...")
    try:
        r=api.host(ip_to_search) #searching shodan for information
        #Result Display
        print """\nIP: %s 
Organization: %s
Operating System: %s
        """ %(r['ip_str'], r.get('org','n/a'),r.get('os','n/a'))
        #Displaying Banner Information
        for item in r['data']:
            print """Port: %s
Banner: %s
            """ % (item['port'], item['data'])
    except shodan.APIError, ex:
        print ("Error: %s" % ex)

def search_ip_cidr(given_cidr_ip):
    if given_cidr_ip is not False:
        ips=iptools.ipv4.cidr2block(given_cidr_ip)
        for ip in ips:
            print("\n ---- Result ----")
            search_single_ip(ip)
            print("\n")
def search_ip_file(my_file):
    if my_file is not False:
        try:
            #print("Imhere")
            with open(my_file,'r') as given_ips:
                add=given_ips.readlines()

        except IOError:
            print ("File I/O Error, enter a valid file name!")
            sys.exit()
        for ip in add:
            #print (ip)
            search_single_ip(ip)

if __name__ == '__main__':
    search_ip,search_cidr,search_file=command_line_parser()
    #shodan_obj=api()

    if search_ip is not False:
        if check_ip(search_ip) is not False:
            search_single_ip(search_ip)
        else:
            print ("The entered IP is not a valid address")

    elif search_cidr is not False:
        search_ip_cidr(search_cidr)
    elif search_file is not False:
        search_ip_file(search_file)

    else:
        print ("Please provide a valid Input")

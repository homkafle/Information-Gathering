#!/usr/bin/python
# -*-Coding: utf-8 -*--
#Author Hom Kafle, A script to request and display web server header information.
import urllib2

from urllib2 import Request, urlopen, URLError, HTTPError
link=raw_input('Enter a URL (e.g: http://www.abc.com):-')

try:
    url = urllib2.urlopen(link)
    data=url.read()
    print "The URL is:",url.geturl()
    print "The Headers are:", url.info()
except URLError, e:
    print e.reason
    (4,'getaddrinfo failed')
    

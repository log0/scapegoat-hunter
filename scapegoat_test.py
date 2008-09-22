import os
import socket
from urllib2 import urlopen

import unittest

import scapegoat

class ScapeGoatUnitTest(unittest.TestCase):
    '''
    def __init__(self):
        self.test_url = 'http://chioka.in/wp-content/themes/girl/style.css'
        self.test_log = '.log.tmp'
    '''
    test_url = 'http://chioka.in/wp-content/themes/girl/style.css'
    test_log = '.log.tmp'

    def test_run_nmap(self):
        nmap_args = {}
        nmap_args['ip'] = '127.0.0.1'
        nmap_args['-p'] = '80,8080'
        nmap_args['verbose'] = False
        nmap_args['output'] = self.test_log

        scapegoat.run_nmap(nmap_args)

        log_data = [ i.rstrip() for i in open(self.test_log, 'r').readlines() ]

        log_header = log_data[0]
        self.assertTrue( 'Nmap' in log_header )
        self.assertTrue( nmap_args['ip'] in log_header )
        self.assertTrue( nmap_args['-p'] in log_header )
        self.assertTrue( nmap_args['output'] in log_header )

        run_success = False

        for line in log_data[1:-1]:
            if nmap_args['ip'] in line and ( 'open' in line or 'closed' in line or 'filtered' in line ) :
                run_success = True

        # Check if there is at least one avaliable proxy
        self.assertTrue(run_success)

        # Clean up
        os.remove(self.test_log)

    def test_check_proxys(self):
        test_log = self.test_log
        test_url = self.test_url

        log_data = \
'''
# Nmap 4.68 scan initiated Sun Sep 21 20:25:44 2008 as: nmap -p 22,23,80 -oG log2.txt 203.168.164.68 
Host: 127.0.0.1 (lssh) Ports: 22/open/tcp//ssh///, 23/filtered/tcp//telnet///, 80/closed/tcp//http///, 8080/open/tcp/http///
# Nmap done at Sun Sep 21 20:25:47 2008 -- 1 IP address (1 host up) scanned in 3.370 seconds
'''

        expected_proxys = [{'ip':'127.0.0.1', 'port':'8080', 'user':'', 'pass':''}]

        log_file = open(test_log, 'w')
        log_file.write(log_data)
        log_file.close()

        proxys = scapegoat.check_proxys(test_url, test_log)
        self.assertTrue(proxys, expected_proxys)

        # Check for unremoved log file
        for filename in os.listdir('.'):
            self.assertTrue( test_log != filename )
                

    def test_check_proxy(self):
        test_url = self.test_url
        url_sock = urlopen(test_url)
        url_data = url_sock.read()
        
        self.assertTrue( scapegoat.check_proxy('127.0.0.1','8080', test_url, url_data) )


socket.setdefaulttimeout(10)
unittest.main()

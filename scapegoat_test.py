import socket
from urllib2 import urlopen

import unittest

import scapegoat

class ScapeGoatUnitTest(unittest.TestCase):
    def test_check_proxys(self):
        pass

    def test_check_proxy(self):
        control_url = 'http://chioka.in/wp-content/themes/girl/style.css'

        url_sock = urlopen(control_url)
        url_data = url_sock.read()
        
        self.assertTrue( scapegoat.check_proxy('127.0.0.1','8080', url_data) )


socket.setdefaulttimeout(10)
unittest.main()

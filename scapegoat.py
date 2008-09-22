import os
import re
import sys
import socket
from urllib2 import urlopen, build_opener
from urllib2 import HTTPHandler, ProxyHandler, HTTPError, URLError
from optparse import OptionParser

socket.setdefaulttimeout(10)

def run_nmap(args):

    cmd = 'nmap'
    cmd += ' -q'
    cmd += ' -oG %s' % (args['output'])
    cmd += ' -p %s' % (args['-p'])
    cmd += ' %s' % (args['ip'])

    if args['verbose'] == False:
        cmd += ' %s' % ('1>/dev/null') # send all the output to hell

    #print cmd
    os.system(cmd)

'''
def check_proxys
@test_url       - The URL to use as a control to verify proxy data in function check_proxy
@nmap_log_file  - The path to the nmap log file with results
Returns:
A List of proxies in form of {'ip':ip, 'port':port, 'user':user, 'pass':pass } for parsing.
'''
def check_proxys(test_url, nmap_log_file):

    # IP regex 
    r_ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    # nmap grepable format : port/state, check for port/open
    r_open_port = re.compile('\d{1,5}/open')

    proxys = []

    try:
        url_sock = urlopen(test_url)
        test_data = url_sock.read()
    except URLError, e:
        print 'Control : %s ' % (e)
        return proxys
    except HTTPError, e:
        print 'Control : %s ' % (e)
        return proxys
    except:
        print 'Control : Other Error'
        return proxys

    log_data = [ i.rstrip() for i in open(nmap_log_file, 'r').readlines() ]

    for line in log_data:
        if r_open_port.search(line):
            open_ports = r_open_port.findall(line)
            ip = r_ip.findall(line)[0]

            for open_port in open_ports:
                port = open_port.split('/')[0]
                print 'Checking %s:%s' % (ip, port)
                if check_proxy(ip, port, test_url, test_data):
                    proxys.append( {'ip':ip, 'port':port, 'user':'', 'pass':''} )

    #delete log file!
    os.remove( nmap_log_file )

    return proxys

'''
def check_proxy
@ip          - The IP of the host to test as a proxy
@port        - The port of the host to test as a proxy
@test_url    - The URL to test without proxy for verification
@test_data   - The URL data fetched without proxy at test_url

Returns:
True - If the ip:port is a proxy
False - Otherwise, or error
'''
def check_proxy(ip, port, test_url, test_data):

    proxy_info = {
        'user' : '',
        'pass' : '',
        'host' : ip,
        'port' : port,
    }

    proxy_dict = {'http':'%(user)s:%(pass)s@%(host)s:%(port)s' % (proxy_info)}
    proxy_handler = ProxyHandler(proxy_dict)

    url_data = ''

    try:
        opener = build_opener(proxy_handler, HTTPHandler)
        url_sock = opener.open(test_url)
        url_data = url_sock.read()
    except URLError, e:
        print 'check_proxy : %s' % (e)
    except HTTPError, e:
        print 'check_proxy : %s' % (e)
    except:
        print 'check_proxy : Other Error '

    # Fail early!
    if url_data == '':
        return False

    # TODO: Can do fuzzy string search to detect injection proxy
    if url_data != test_data:
        return False

    return True


if __name__ == '__main__':

    optparser = OptionParser()
    optparser.add_option('-t', '--target', dest='target', help='Target range to scan, in nmap format. Default is Random Scan on nmap.', default=None)
    optparser.add_option('-p', '--port', dest='port', help='Port range to scan, in nmap format. Default is 80,3128,8080', default='80,3128,8080')
    optparser.add_option('-q', '--quiet', action='store_false', dest='verbose', help='No output from nmap.', default=True)
    optparser.add_option('-u', '--url', dest='url', help='URL to validate proxy against, default is http://chioka.in/wp-content/themes/girl/style.css', default='http://chioka.in/wp-content/themes/girl/style.css')

    (op, args) = optparser.parse_args()

    target = None
    port = None

    target = op.target
    port = op.port
    verbose = op.verbose

    if not op.target:
        target = '-iR 1000'

    nmap_args = {}
    nmap_args['ip'] = target
    nmap_args['-p'] = port
    nmap_args['verbose'] = verbose
    nmap_args['output'] = '.log.tmp'

    print 'Execute Nmap...'
    run_nmap(nmap_args)

    print 'Verify results from Nmap...'
    proxys = check_proxys(op.url, nmap_args['output'])
    for proxy in proxys:
        print 'http://%(user)s:%(pass)s@%(ip)s:%(port)s' % (proxy)

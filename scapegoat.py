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
                if check_proxy(ip, port, test_url, test_data):
                    proxys.append( {'ip':ip, 'port':port, 'user':'', 'pass':''} )

    #delete log file!
    os.remove( nmap_log_file )

    return proxys

def check_proxy(ip, port, test_url, test_data):
    #print 'Checking %s:%s' % ( ip, port)

    proxy_info = {
        'user' : '',
        'pass' : '',
        'host' : ip,
        'port' : port,
    }

    proxy_dict = {'http':'%(user)s:%(pass)s@%(host)s:%(port)s' % (proxy_info)}
    proxy_handler = ProxyHandler(proxy_dict)

    try:
        opener = build_opener(proxy_handler, HTTPHandler)
        url_sock = opener.open(test_url)
        url_data = url_sock.read()
    except URLError, e:
        print e
        return
    except HTTPError, e:
        print e
        return
    except:
        print 'Other Error '
        return

    if url_data == test_data:
        #print 'Good Proxy : %(user)s:%(pass)s@%(host)s:%(port)s' % (proxy_info)
        return True
    else:
        #print '=========='
        #print url_data
        #print '=========='
        #print test_data
        #print '=========='
        #print 'Bad Proxy : %(user)s:%(pass)s@%(host)s:%(port)s' % (proxy_info)
        return False


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
        target = '-iR 100'

    nmap_args = {}
    nmap_args['ip'] = target
    nmap_args['-p'] = port
    nmap_args['verbose'] = verbose
    nmap_args['output'] = '.log.tmp'

    run_nmap(nmap_args)
    check_proxys(op.url, nmap_args['output'])

import os
import re
import sys
import socket
from urllib2 import urlopen, build_opener
from urllib2 import HTTPHandler, ProxyHandler, HTTPError, URLError
from optparse import OptionParser

# IP regex 
r_ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
# nmap grepable format : port/state, check for port/open
r_open_port = re.compile('\d{1,5}/open')

g_control_data = ''

socket.setdefaulttimeout(10)

TEMP_LOG = '.log.tmp'
CONTROL_URL = 'http://chioka.in/wp-content/themes/girl/style.css'

def run_nmap(args):
    global TEMP_LOG

    cmd = 'nmap'
    cmd += ' -q'
    cmd += ' -oG %s' % (TEMP_LOG)
    cmd += ' -p %s' % (args['-p'])
    cmd += ' %s' % (args['ip'])

    if args['verbose'] == False:
        cmd += ' %s' % ('1>/dev/null') # send all the output to hell

    print cmd
    os.system(cmd)
    pass

def check_proxys():
    global r_ip, r_open_port
    global g_control_data
    global CONTROL_URL

    try:
        url_sock = urlopen(CONTROL_URL)
        g_control_data = url_sock.read()
    except URLError, e:
        print 'Control : %s ' % (e)
        return 
    except HTTPError, e:
        print 'Control : %s ' % (e)
        return
    except:
        print 'Control : Other Error'
        return

    log_data = [ i.rstrip() for i in open(TEMP_LOG, 'r').readlines() ]

    for line in log_data:
        #print 'Studying : [%s]' % ( line )
        if r_open_port.search(line):
            open_ports = r_open_port.findall(line)

            ip = r_ip.findall(line)[0]
            print 'Inspecting %s' % (ip)

            for open_port in open_ports:
                port = open_port.split('/')[0]
                check_proxy(ip, port)


    #delete log file!
    pass

def check_proxy(ip, port):
    global g_control_data
    global CONTROL_URL
    print 'Checking %s:%s' % ( ip, port)

    proxy_info = {
        'user' : '',
        'pass' : '',
        'host' : ip,
        'port' : port,
    }

    #proxy_dict = {'http':'%(user)s:%(pass)s@%(host)s:%(port)s' % (proxy_info)}
    proxy_dict = {'http':'%(host)s:%(port)s' % (proxy_info)}
    print proxy_dict
    proxy_handler = ProxyHandler({'http':proxy_dict})

    opener = build_opener(proxy_handler, HTTPHandler)
    print 'URL OPener done'
    url_sock = opener.open(CONTROL_URL)
    print 'URL Opened'
    try:
        url_data = url_sock.read()
        print 'URL read data'

    except URLError, e:
        print e
        return
    except HTTPError, e:
        print e
        return
    except:
        print 'Other Error '
        return

    if url_data == g_control_data:
        print 'Good Proxy : %(user)s:%(pass)s@%(host)s:%(port)s' % (proxy_info)
    else:
        print '=========='
        print url_data
        print '=========='
        print g_control_data
        print '=========='
        print 'Bad Proxy : %(user)s:%(pass)s@%(host)s:%(port)s' % (proxy_info)




if __name__ == '__main__':
    optparser = OptionParser()
    optparser.add_option('-t', '--target', dest='target', help='Target range to scan, in nmap format. Default is Random Scan on nmap.', default=None)
    optparser.add_option('-p', '--port', dest='port', help='Port range to scan, in nmap format. Default is 80,3128,8080', default='80,3128,8080')
    optparser.add_option('-q', '--quiet', action='store_false', dest='verbose', help='No output from nmap.', default=True)

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

    run_nmap(nmap_args)
    check_proxys()

#!/usr/bin/python
'''
  Script to reboot my netgear router.
  Get the realm via curl:
    $ curl -I http://192.168.1.1/start.htm
    HTTP/1.0 401 Unauthorized
    WWW-Authenticate: Basic realm="NETGEAR WNDR3400"
    Content-type: text/html
'''

import urllib
import urllib2
import httplib


base_url = "http://192.168.1.1/"
settings_url = "BAS_ether.htm"
realm = "NETGEAR WNDR3400"
username = "SANITIZED"
password = "SANITIZED"
# TODO: Get these programatically, like the POST url:
# actually, all I need is 'apply', according to Postman.
values = {'system_name': 'WNDR3400',
          'domain_name': '',
          'WANAssign': 'dhcp',
          'DNSAssign': '0',
          'MACAssign': '0',
          'apply': 'Apply',
          'runtest': 'no',
          'wan_proto': 'dhcp',
          'wan_ipaddr': 'SANITIZED',
          'wan_netmask': 'SANITIZED',
          'wan_gateway': 'SANITIZED',
          'wan_dns_sel': '0',
          'wan_dns1_pri': 'SANITIZED',
          'wan_dns1_sec': 'SANITIZED',
          'wan_hwaddr_sel': '0',
          'wan_hwaddr_def': 'SANITIZED',
          'wan_hwaddr2': 'function toUpperCase() { [native code] }',
          'wan_hwaddr_pc': 'SANITIZED',
          'lan_ipaddr': 'SANITIZED',
          'lan_netmask': 'SANITIZED'}
headers = [('User-Agent', 'Mozilla/5.0'),
           ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'),
           ('Accept-Encoding', 'gzip, deflate'),
           ('Accept-Language', 'en-US,en;q=0.8'),
           ('Authorization', 'Basic SANITIZED'),
           ('Cache-Control', 'max-age=0'),
           ('Connection', 'keep-alive'),
           ('Content-Length', '465'),
           ('Content-Type', 'application/x-www-form-urlencoded'),
           ('Host', '192.168.1.1'),
           ('Origin', 'http://192.168.1.1'),
           ('Referer', 'http://192.168.1.1/BAS_ether.htm')]


def authenticate(url):
    # authenticate to the remote router
    password_mgr = urllib2.HTTPPasswordMgr()
    password_mgr.add_password(realm, url, username, password)
    handler = urllib2.HTTPBasicAuthHandler(password_mgr)

    return urllib2.build_opener(handler)


def connect(opener, url, data=None):
    if data:  # the presence of data means this is a reset request
        opener.addheaders = headers
        try:
            opener.open(url)
        except httplib.BadStatusLine:
            # ignore whatever weird status the router returns
            pass
    else:  # called by either the router_up() or get_form_url() functions
        opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
        opener.open(url)

    urllib2.install_opener(opener)
    req = urllib2.Request(url, data)

    return req


def router_up():
    # first I should check to see if the router is available:
    try:
        opener = authenticate(base_url)
        req = connect(opener, base_url)
        urllib2.urlopen(req)
    except Exception, e:
        print "Error connecting to the router: " + str(e)

    print "** Router up and running... **"
    return True


def get_form_url():
    # retrieve the correct post url for the cgi form:
    url = base_url + settings_url

    opener = authenticate(url)
    req = connect(opener, url)
    response = urllib2.urlopen(req)
    data = response.read()  # read the page returned by urlopen. 'data' is html.

    # find the right url to post to
    for line in data.split("\n"):
        if 'ether.cgi?id=' in line:
            form_action = line.split(' ')[3]
            start_pos = form_action.find('"')
            target_url = form_action[start_pos + 1: -1]

    print "** CGI form target is: %s... **" % target_url
    return target_url.strip()


def send_reset(target_url):
    # send the reset command to the router:
    post_url = base_url + target_url
    print "** Form POST url is: %s... **" % post_url
    form_data = urllib.urlencode(values)
    opener = authenticate(post_url)
    req = connect(opener, post_url, form_data)
    response = urllib2.urlopen(req)
    data = response.read()
    print "** Reset request sent... **"
    if "Updating Settings" in data:
        print "** Router reset. ** "


def main():
    if router_up():
        target_url = get_form_url()
        send_reset(target_url)


if __name__ == '__main__':
    main()

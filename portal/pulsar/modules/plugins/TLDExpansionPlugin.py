
import json
import requests
import sys
import socket
import favicon
import hashlib
import ssl
import re
import urllib3
from billiard import pool
from celery.utils.log import get_task_logger
from netaddr import IPNetwork
from requests.exceptions import ConnectionError, HTTPError
from pebble import ProcessPool as ThreadPool
from ..scanner_utils import BaseDiscoveryPlugin, aBulkRecordLookup, unique_list, Sandbox, proxies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = get_task_logger(__name__)
sandbox = Sandbox()

class TLDExpansionPlugin(BaseDiscoveryPlugin):
    expansion = True
    name = 'TLD Expansion Discovery'
    short = 'TLD Expansion'

    known_certs = []

    def setup(self, domain):
        try:
            try:
                self.tld_list = open('/portal/pulsar/modules/tld.list', 'r').read().split('\n')
            except OSError as e:
                logger.info('tld.list is missing!\n')
                logger.info(repr(e))
                raise
            self.domain = domain
            try:
                self.known_ip = socket.gethostbyname(domain)
            except Exception:
                try:
                    self.known_ip = socket.gethostbyname('www.'+domain)
                except Exception:
                    raise
            self.known_domain = domain.split('.')[0]
            self.known_fav = self.check_favicon(domain)
            self.known_certs.append(self.check_cert(domain))
        except Exception as e:
            logger.info("Fatal error: " + repr(e))
            raise

    def check_cert(self, dom):
        for vhost in ['', 'www.']:
            try:
                openssl_cmd = f' ( openssl s_client -connect {vhost + dom}:443 < /dev/null 2>/dev/null \
                 | openssl x509 -fingerprint -noout -in /dev/stdin )  2>&1 '
                cert = sandbox.exec_sandboxed(openssl_cmd)
                if cert is None or 'Fingerprint' not in cert:
                    raise Exception
                return cert
            except Exception:
                pass

    def check_favicon(self, dom):
        for proto in ['http', 'https']:
            try:
                fav = favicon.get(proto + '://' + dom + '/', stream=True, verify=False, proxies=proxies)
                r = requests.get(fav[0].url, verify=False, proxies=proxies)
                return hashlib.sha1(r.text.encode('utf-8')).hexdigest()
            except (ConnectionError, IndexError, HTTPError):
                pass

    def check_links(self, new_domain):
        for vhost in ['', 'www.']:
            for proto in ['http', 'https']:
                try:
                    r = requests.get(proto + '://' + vhost + new_domain + '/', verify=False,
                                     allow_redirects=True, proxies=proxies)
                    if re.search(r'http.:\/\/.*' + self.domain, r.text):
                        return True
                    else:
                        return False
                except ConnectionError:
                    pass

    def check_tld(self, new_domain):
        try:
            ip = socket.gethostbyname(str(new_domain))
            if str(ip) == str(self.known_ip):
                try:
                    self.known_certs.append(self.check_cert(new_domain))
                except Exception as e:
                    logger.info('failed: %s' % repr(e))
                    pass
                return 'ipv4'
            elif str(self.check_cert(new_domain)) in self.known_certs:
                try:
                    self.known_certs.append(self.check_cert(new_domain))
                except Exception as e:
                    logger.info('failed: %s' % repr(e))
                    pass
                return 'certificate'
            elif str(self.known_fav) == str(self.check_favicon(new_domain)):
                return 'favicon'
            elif self.check_links(new_domain):
                return 'links'
            else:
                return 'unknown'
        except Exception as e:
            pass

    def find_tlds(self):
        identified = []
        dom_list = [self.known_domain + '.' + tld for tld in self.tld_list]
        try:
            resolved = aBulkRecordLookup(unique_list(dom_list))
            for dom in unique_list(resolved):
                result = self.check_tld(dom['fqdn'])
                if result != 'unknown':
                    identified.append(dom)
                    logger.info("Found new TLD by %s: %s" % (result, dom['fqdn']))
            return unique_list(identified)
        except Exception as e:
            logger.info(repr(e))
            pass

    def run(self):
        self.confidence = 0.6
        self.setup(self.asset_dom)
        doms = self.find_tlds()
        if doms and len(doms) > 0:
            self.tlds = [dom['fqdn'] for dom in doms]
            self.discovered.extend(doms)

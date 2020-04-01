import requests
import time
import favicon
import hashlib
import re
import urllib3
from celery.utils.log import get_task_logger
from requests.exceptions import ConnectionError, HTTPError
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
                with open('/portal/pulsar/modules/tld.list', 'r') as tld_file:
                    self.tld_list = tld_file.read().split('\n')
            except OSError as e:
                logger.info('tld.list is missing!\n')
                logger.info(repr(e))
                raise
            self.domain = domain
            count = 0
            while True:
                try:
                    root_dom = aBulkRecordLookup([domain])
                    logger.info('GOR ROOT TLD RESOLV: %s' % repr(root_dom) )
                    self.known_ip = root_dom[0]['ip'][0]['ip']
                    break
                except Exception:
                    time.sleep(1)
                    count += 1
                    if count >= 5:
                        break
                    pass
            self.known_domain = domain.split('.')[0]
            self.known_fav = self.check_favicon(domain)
            logger.info('Gor ROOT TLD data: %s %s' % (self.known_domain, self.known_ip))
        except Exception as e:
            logger.info("Fatal error: " + repr(e))
            raise

    def check_favicon(self, dom):
        for proto in ['http', 'https']:
            try:
                fav = favicon.get(proto + '://' + dom + '/', stream=True, verify=False, proxies=proxies)
                r = requests.get(fav[0].url, verify=False, proxies=proxies)
                logger.info('Searching favicon...')
                return hashlib.sha1(r.text.encode('utf-8')).hexdigest()
            except (ConnectionError, IndexError, HTTPError):
                pass

    def check_links(self, new_domain):
        for vhost in ['', 'www.']:
            for proto in ['http', 'https']:
                try:
                    r = requests.get(proto + '://' + vhost + new_domain + '/', verify=False,
                                     allow_redirects=True, proxies=proxies)
                    logger.info('Searching links...')
                    if re.search(r'http.:\/\/.*' + self.domain, r.text):
                        return True
                    else:
                        return False
                except ConnectionError:
                    pass

    def check_tld(self, new_domain, ip):
        try:
            logger.info('Checking IP: %s == %s' % (ip, self.known_ip))
            if str(ip) == str(self.known_ip):
                return 'ipv4'
            else:
                fav = str(self.check_favicon(new_domain))
                links = self.check_links(new_domain)
                logger.info('Checking FAV: %s == %s' % (str(self.known_fav), fav))
                logger.info('Checking LINKS: %s ' % links)
                if fav and fav == str(self.known_fav):
                    return 'favicon'
                elif links:
                    return 'links'
                else:
                    return 'unknown'

        except Exception:
            return 'unknown'

    def find_tlds(self):
        identified = []
        dom_list = [self.known_domain + '.' + tld for tld in self.tld_list]
        try:
            resolved = aBulkRecordLookup(unique_list(dom_list))
            for dom in unique_list(resolved):
                logger.info("Checking TLD: %s %s" % (dom['fqdn'], repr(dom['ip'])))
                result = self.check_tld(dom['fqdn'], dom['ip'][0]['ip'])
                if result and result != 'unknown':
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
            self.tlds = unique_list([dom['fqdn'] for dom in doms])
            logger.info('FOUND TLDs: %s' % self.tlds)
            self.discovered.extend(doms)

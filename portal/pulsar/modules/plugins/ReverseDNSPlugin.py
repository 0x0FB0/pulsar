
import json
import requests
from billiard import pool
from celery.utils.log import get_task_logger
from netaddr import IPNetwork

from ..scanner_utils import BaseDiscoveryPlugin, aBulkRecordLookup, unique_list, Sandbox

logger = get_task_logger(__name__)
sandbox = Sandbox()

def ripe_resolve_ip(match_annd_ip):
    found = []
    match = match_annd_ip[0]
    ip = match_annd_ip[1]
    url = f'https://stat.ripe.net/data/dns-chain/data.json?sourceapp=OpenOSINT&resource={ip}'
    response = requests.get(url)
    result = response.text
    try:
        jresponse = json.loads(result)
        if 'reverse_nodes' in jresponse['data']:
            for key in jresponse['data']['reverse_nodes'].keys():
                    for dom in jresponse['data']['reverse_nodes'][key]:
                        logger.info("REVERSE DNS LOOKUP RESULT: %s (searching for %s)" % (dom, match))
                        if match in dom:
                            found.append(dom)
            return found
        else:
            return []
    except (json.JSONDecodeError, KeyError) as e:
        logger.info('RIPE REV RESOLVE FAILED %s ' % repr(e))
        return []


def revDNSFind(asset_name, asset_dom, nets, inscope):
    unresolved = []
    resolved = []
    work_data = []
    for net in nets:
        if inscope:
            work_data.extend([(asset_dom, ip) for ip in IPNetwork(net)])
        else:
            work_data.extend([(asset_name.lower().replace(' ', '-'), ip) for ip in IPNetwork(net)])
            work_data.extend([(asset_name.lower().replace(' ', '.'), ip) for ip in IPNetwork(net)])

    resolv_pool = pool.Pool(2)
    unresolved = resolv_pool.map(ripe_resolve_ip, [work for work in work_data])
    clean = [item for sublist in unresolved for item in sublist]
    resolved = aBulkRecordLookup(unique_list(clean))

    return unique_list(resolved)

class ReverseDNSPlugin(BaseDiscoveryPlugin):
    custom_discovery = True
    recursive = True
    name = 'Reverse DNS Discovery'
    short = 'Reverse DNS'
    def run(self):
        self.confidence = 0.4
        history = self.history
        doms = revDNSFind(self.asset_name, self.asset_dom, self.nets, self.policy.inscope)
        if len(history) > 0:
            new_doms = [x for x in doms if x not in history]
        else:
            new_doms = doms
        logger.info("FOUND DOMAINS: %s" % repr(new_doms))
        if len(new_doms) > 0:
            self.discovered.extend(new_doms)
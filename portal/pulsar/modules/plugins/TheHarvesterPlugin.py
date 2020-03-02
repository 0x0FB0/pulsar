
import collections
import json
import re

from celery.utils.log import get_task_logger

from ..scanner_utils import BaseDiscoveryPlugin, aBulkRecordLookup, unique_list, Sandbox

logger = get_task_logger(__name__)
sandbox = Sandbox()

def parseHosts(data, query):
    data.replace('<em>', '').replace('<b>', '').replace('</b>', '').replace('</em>', '')\
            .replace('%2f', '').replace('%3a', '').replace('<strong>', '').replace('</strong>', '')\
            .replace('<wbr>', '').replace('</wbr>', '')
    for search in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C', '/', '\\'):
        data = data.replace(search, ' ')
    find_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + query)
    hosts = find_hosts.findall(data)
    find_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + query.replace('www.', ''))
    hosts.extend(find_hosts.findall(data))
    return unique_list(hosts)

def getDNSDumpster(query):
    url = 'https://dnsdumpster.com/'
    filter_req = "| grep Set-Cookie | tr \" ;\" \"\n\" | grep csrf | tr \"=\" \" \" | awk '{print $2}'"
    cookie_cmd = f'wget {url} -O- -d 2>&1 {filter_req}'
    csrftoken = sandbox.exec_sandboxed(cookie_cmd).strip(';')
    data = {
        'Cookie': f'csfrtoken={csrftoken}', 'csrfmiddlewaretoken': csrftoken, 'targetip': query}
    result = sandbox.post_sandboxed(url, json.dumps(data), wget_args=f'--referrer-url={url}')
    return result

def getVirustotal(query):
    url = f'https://www.virustotal.com/ui/domains/{query}/subdomains?relationships=resolutions&cursor=STMwCi4%3D&limit=40'
    result = sandbox.get_sandboxed(url)
    jdata = json.loads(result)
    doms = []
    if 'data' in jdata:
        for key in jdata['data']:
            if 'type' in key:
                if key['type'] == 'domain':
                    doms.append(key['id'])
    return doms

def getThreatcrowd(query):
    url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={query}'
    result = sandbox.get_sandboxed(url)
    jdata = json.loads(result)
    doms = []
    if 'subdomains' in jdata:
        for dom in jdata['subdomains']:
            doms.append(dom)
    return doms

def getYahoo(query):
    total = ''
    for i in range(0, 120, 10):
        url = f'https://search.yahoo.com/search?p=%40{query}&b={i}&pz=10'
        result = sandbox.get_sandboxed(url)
        total += result
    return total

def theHarvesterSubFind(s_input):
    unresolved = []
    resolved = []

    unresolved.extend(getVirustotal(s_input))
    unresolved.extend(getThreatcrowd(s_input))

    unresolved.extend(parseHosts(getDNSDumpster(s_input), s_input))
    unresolved.extend(parseHosts(getYahoo(s_input), s_input))
    counter = collections.Counter([re.sub("\d+", "\\\\d+", x) for x in unresolved])
    repeats = [key for key in counter.keys() if counter[key] > 10]
    if len(repeats) > 0:
        combined = "(" + ")|(".join(repeats) + ")"
        cleared = [dom for dom in unresolved if not re.match(combined, dom)]
    else:
        cleared = unresolved

    resolved = aBulkRecordLookup(unique_list(cleared))

    return unique_list(resolved)

class TheHarvesterPlugin(BaseDiscoveryPlugin):
    custom_discovery = True
    name = 'TheHarvester Subdomain Discovery'
    short = 'The Harvester'
    reference = 'https://github.com/laramies/theHarvester'
    def run(self):
        self.confidence = 1.0
        history = self.history
        doms = theHarvesterSubFind(str(self.fqdn))
        if len(history) > 0:
            new_doms = [ x for x in doms if x not in history ]
        else:
            new_doms = doms
        logger.info("FOUND DOMAINS: %s" % repr(new_doms))
        if len(new_doms) > 0:
            self.discovered.extend(new_doms)
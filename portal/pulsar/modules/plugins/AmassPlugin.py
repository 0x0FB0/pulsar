import collections
import json
import re
import socket
import time

import validators
from celery.utils.log import get_task_logger

from ..scanner_utils import BaseDiscoveryPlugin, scan_settings, Sandbox

logger = get_task_logger(__name__)
sandbox = Sandbox()

def isWildcardDom(dom):
    try:
        socket.gethostbyname('thisshould-never-3xist10767.'+dom)
        return True
    except socket.gaierror:
        return False

def aMassSubFind(s_input, unique_id, active, history):
    doms = []
    wildcard = isWildcardDom(s_input)
    uploaded_known = ''
    known = '/opt/scan_data/' + unique_id + '_' + s_input + '_known.list'
    outfile = '/opt/scan_data/' + unique_id + '_' + s_input + '_amass_out.json'
    s_cmd = "amass enum -config /opt/scan_config/amass-config.ini " \
            "-blf /opt/scan_config/blacklist.txt " \
            f"-d {s_input} -src -timeout {scan_settings['amass_timeout']} " \
            f"{scan_settings['amass_flags']} -json " + outfile
    if active and not wildcard:
        s_cmd += " -active -brute "
    if len(history) > 0:
        uploaded_known = sandbox.upload_sandboxed_content(known, '\n'.join(history))
        s_cmd += " -nf " + known
    logger.info("AMASS START")
    sandbox.exec_sandboxed(s_cmd)
    results = sandbox.retrieve_sandboxed(outfile)
    logger.info("AMASS END")
    # make sure dns resolution cooldown
    counter = 0
    while True:
        try:
            socket.gethostbyname('www.google.com')
            break
        except socket.gaierror:
            counter += 1
            time.sleep(1)
            if counter == 360:
                return list()
    data_list = list()
    try:
        for line in results.split("\n"):
            try:
                data = json.loads(line)
                data_list.append(data)
            except ValueError as e:
                logger.info("AMASS PARSE ERROR: %s\n%s" % (repr(e), line))
                pass
    except AttributeError as e:
        logger.info("AMASS PARSE ERROR: %s" % repr(e))
        pass
    alldoms_list = list()
    for data in data_list:
        alldoms_list.append(data['name'])
    logger.info("FRESH DOMAINS: %s" % repr(alldoms_list))
    counter = collections.Counter([re.sub("\d+", "\\\\d+", x) for x in alldoms_list])
    repeats = [key for key in counter.keys() if counter[key] > 10]
    combined = "(" + ")|(".join(repeats) + ")"
    logger.info("COBINED: %s" % repr(combined))
    for data in data_list:
        if len(repeats) > 0 and not re.match(combined, data['name']):
            if 'addresses' in data and validators.domain(data['name']):
                doms.append({'fqdn': data['name'], 'ip': data['addresses']})
        else:
            if 'addresses' in data and validators.domain(data['name']):
                doms.append({'fqdn': data['name'], 'ip': data['addresses']})
    if len(history) > 0:
        sandbox.remove_sandboxed(uploaded_known)
        sandbox.remove_sandboxed(outfile)
    return doms

class AmassPlugin(BaseDiscoveryPlugin):
    custom_discovery = True
    name = 'OWASP Amass Subdomain Discovery'
    short = 'Amass Discovery'
    reference = 'https://github.com/OWASP/Amass/'
    confidence = 1.0
    def run(self):
        logger.info("GOT POLICY: %s" % repr(self.policy))
        doms = aMassSubFind(str(self.fqdn), str(self.task_id), self.policy.active, self.history)
        logger.info("FOUND DOMAINS: %s" % repr(doms))
        if len(doms) > 0:
            self.discovered.extend(doms)
import json

import xmltodict
from celery.utils.log import get_task_logger

from ..scanner_utils import ServiceDiscoveryPlugin, unique_list, Sandbox, scan_settings

logger = get_task_logger(__name__)
sandbox = Sandbox()

def getServices(nmap_record):
    svcs = dict()
    ports = list()
    addr = nmap_record['address']['@addr']
    if isinstance(nmap_record['ports']['port'], list):
        for port in nmap_record['ports']['port']:
            ports.append(port)
    elif isinstance(nmap_record['ports']['port'], dict):
        ports.append(nmap_record['ports']['port'])

    for port in ports:
        if '@product' in port['service'] and port['state']['@reason'] != 'no-response':
            desc = port['service']['@product']
        else:
            desc = 'Unknown'
        if addr in svcs:
            svcs[addr].append(
                {
                    'proto': port['service']['@name'],
                    'port': port['@portid'],
                    'desc': desc,
                    'banner': json.dumps(port),
                }
            )
        else:
            svcs[addr] = [
                {
                    'proto': port['service']['@name'],
                    'port': port['@portid'],
                    'desc': desc,
                    'banner': json.dumps(port),
                }
            ]
    return svcs

def udpScan(ip_list, unique_id, policy):
    discovered = list()
    ip_file = f'/opt/scan_data/nmap-{unique_id}-udp-ips.list'
    out_file = f'/opt/scan_data/nmap-{unique_id}-udp-out.xml'

    sandbox.upload_sandboxed_content(ip_file, '\n'.join(unique_list(ip_list)))

    cmd1 = f'nmap --host-timeout {scan_settings["nmap_host_timeout"]} ' + \
          f'{scan_settings["nmap_udp_flags"]} --top-ports {policy.top_ports} --open -iL {ip_file} | grep "udp open"'

    port_out = sandbox.exec_sandboxed(cmd1)
    ports = list()
    for line in port_out.split("\n"):
          ports.append(line.split('/')[0])
    cmd2 = f'nmap -iL {ip_file} --host-timeout {scan_settings["nmap_host_timeout"]}  -oX {out_file} ' + \
           f'-Pn -n -p {",".join(unique_list(ports))} -vv -sU -sV --open '
    debug = sandbox.exec_sandboxed(cmd2)
    result = sandbox.retrieve_sandboxed(out_file)
    try:
        all_data = xmltodict.parse(result)
    except Exception as e:
        logger.info("Nmap XML parse error.")
        all_data = {"nmaprun":""}
        pass

    sandbox.remove_sandboxed(out_file)
    sandbox.remove_sandboxed(ip_file)

    if 'host' in all_data['nmaprun']:
        if isinstance(all_data['nmaprun']['host'], list):
            for host in all_data['nmaprun']['host']:
                discovered.append(host)
        elif isinstance(all_data['nmaprun']['host'], dict):
                discovered.append(all_data['nmaprun']['host'])
    return discovered


class UdpServiceScanPlugin(ServiceDiscoveryPlugin):
    custom_discovery = True
    temp = {}
    name = 'UDP Service Discovery'
    short = 'Nmap UDP'

    def run(self):
        records = udpScan(self.ip_list, self.task_id, self.policy)
        for host in records:
            try:
                services = getServices(host)
                self.services.update(services)
            except KeyError:
                pass
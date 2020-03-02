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
        if '@product' in port['service']:
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

def tcpScan(ip_list, unique_id, policy):
    discovered = list()
    ip_file = f'/opt/scan_data/nmap-{unique_id}-tcp-ips.list'
    out_file = f'/opt/scan_data/nmap-{unique_id}-tcp-out.xml'

    cmd = f'nmap {scan_settings["nmap_tcp_flags"]} -sV ' + \
         f' --open --host-timeout {scan_settings["nmap_host_timeout"]} --top-ports {policy.top_ports} ' + \
         f'-iL {ip_file} -oX {out_file}'

    sandbox.upload_sandboxed_content(ip_file, '\n'.join(unique_list(ip_list)))
    sandbox.exec_sandboxed(cmd)
    result = sandbox.retrieve_sandboxed(out_file)
    try:
        all_data = xmltodict.parse(result)
    except Exception as e:
        logger.info("NMAP PARSE ERROR")
        all_data = {"nmaprun": ""}
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


class TcpServiceScanPlugin(ServiceDiscoveryPlugin):
    custom_discovery = True
    temp = {}
    name = 'TCP Service Discovery'
    short = 'Nmap TCP'

    def run(self):
        records = tcpScan(self.ip_list, self.task_id, self.policy)
        for host in records:
            try:
                services = getServices(host)
                self.services.update(services)
            except KeyError:
                pass
        #self.services
from celery.utils.log import get_task_logger

from ..scanner_utils import BaseScannerPlugin, unique_list

logger = get_task_logger(__name__)

class ServiceInfoPlugin(BaseScannerPlugin):
    custom_scanner = True
    plugin = 'Service Discovery Plugin'
    name = 'Service Discovery'
    short = 'Service Info'
    cvss = 'AV:N/AC:H/Au:N/C:N/I:N/A:N'
    info = True
    confidence = 0.0
    score = 0.0
    reference = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"

    def run(self):
        details = ''
        ports = list()
        cpes = list()

        for svc in self.services:
            if 'port' in svc:
                logger.info("SVC INFO GOT PORT: %s" % repr(svc['port']))
                self.found = True
                ports.append(svc['port'])
                details += f"Found {svc['proto'].upper()} service on port {str(svc['port'])}.\n"
                cpes = [cpe for cpe in svc['cpe'].split(';') if cpe != 'None']
                if len(cpes) > 0:
                    details += 'Common Platform Enumeration Details:\n'
                    details += '\n'.join(unique_list(cpes))
            self.description = f'Discovered {str(len(unique_list(ports)))} unique services.'
            self.details = details


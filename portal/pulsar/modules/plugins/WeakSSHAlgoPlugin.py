import json

from celery.utils.log import get_task_logger

from ..scanner_utils import BaseScannerPlugin, Sandbox

logger = get_task_logger(__name__)
sandbox = Sandbox()

class WeakSSHAlgoPlugin(BaseScannerPlugin):
    custom_scanner = True
    plugin = 'Weak SSH Algorithms Plugin'
    name = 'Weak SSH Algorithms'
    short = 'SSH Audit'
    cvss = 'AV:N/AC:H/Au:N/C:P/I:P/A:N'
    confidence = 0.6
    score = 4.0
    reference = "https://csrc.nist.gov/publications/detail/fips/140/3/final"

    def run(self):
        vports = []
        algos = []
        dom = self.fqdn
        for svc in self.services:
            try:
                svc_data = json.loads(svc['banner'])
                if svc_data['service']['@name'] == 'ssh':
                    logger.info("SSH AUDIT ON %s" % dom)
                    cmd = f'python3 /opt/ssh-audit/ssh-audit.py -l fail {dom} -p {svc["port"]} 2>&1 ' + \
                    "| grep '\[fail\]' | sed 's/\[0;31m//g' | sed 's/\[0m//g' "
                    result = sandbox.exec_sandboxed(cmd)
                    if len(result) > 0:
                        self.found = True
                        algos.append(result)
                        vports.append(svc['port'])
            except KeyError:
                pass
        details = ''
        for i in range(0, len(vports)):
            details += f'Port {vports[i]}:\n\n'
            details += algos[i]+'\n\n'
        self.details = details
        out_ports = ''
        for port in vports:
            out_ports += str(port)
            if vports.index(port) < len(vports):
                out_ports += ', '
        if len(vports) > 1:
            self.description = f"Weak SSH algorithms found on ports: {out_ports}."
        elif len(vports) == 1:
            self.description = f"Weak SSH algorithms found on port {str(vports[0])}."
        else:
            self.found = False
        if self.found:
            logger.info("SHOULD BE SAVED: %s " % self.description)

import json

from celery.utils.log import get_task_logger

from ..scanner_utils import HandMadeScannerPlugin, Sandbox

logger = get_task_logger(__name__)
sandbox = Sandbox()

class HandMadePlugin(HandMadeScannerPlugin):
    plugin = 'Hand Made Plugin'
    short = 'Hand Made'

    def run(self):
        dom_svcs = []
        dom = self.fqdn
        for svc in self.services:
            try:
                svc_data = json.loads(svc['banner'])
                dom_svcs.append(str(svc['port']) + '/' + str(svc_data['service']['@name']).upper())
            except KeyError:
                pass
        port_string = ','.join(dom_svcs)
        script_file = '/opt/scan_data/' + self.task_id + '-' + self.hmp_id + '.sh'
        sandbox.upload_sandboxed_content(script_file, self.script.replace('\r',''))
        cmd = f'chmod +x {script_file} && '
        cmd += f'echo -e "export DOM_SVCS={port_string}\\nexport DOM_FQDN={dom} " > ~/.bashrc && '
        cmd += f'{script_file} 2>&1'
        details = sandbox.exec_sandboxed(cmd)
        sandbox.remove_sandboxed(script_file)
        logger.info("HANDMADE SCRIPT OUT: %s" % details)
        if len(details) > 2:
            self.found = True
            self.details = details

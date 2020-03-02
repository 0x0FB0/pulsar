import json

from celery.utils.log import get_task_logger

from ..scanner_utils import BaseScannerPlugin, Sandbox

logger = get_task_logger(__name__)
sandbox = Sandbox()

def certCheck(dom, port):
    info_cmd = f'echo | openssl s_client -servername {dom} -connect {dom}:{port}' \
      ' 2>/dev/null | openssl x509 -noout -issuer -subject -dates -fingerprint'
    check_cmd = f'wget https://{dom}:{port}/ -O/dev/null -q 2>&1 | grep "ERROR: The certificate" || true'
    check_out = sandbox.exec_sandboxed(check_cmd)
    if 'ERROR:' in check_out:
        info_out = sandbox.exec_sandboxed(info_cmd)
        result = '# ' + check_cmd + '\n'
        result += check_out + '\n'
        result += '# ' + info_cmd + '\n'
        result += info_out + '\n'
        return result, check_out.strip('ERROR: ')
    else:
        return '', ''

class TLSCertVerifyPlugin(BaseScannerPlugin):
    custom_scanner = True
    plugin = 'TLS Certificate Validation Plugin'
    short = 'Certificate Check'
    name = 'Invalid Certificate'
    cvss = 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
    confidence = 0.9
    score = 5.9
    reference = "https://en.wikipedia.org/wiki/Certificate_authority"

    def run(self):
        vports = []
        curl_out = []
        details = ''
        logger.info("STARTING SCAN FOR %s" % self.fqdn)
        for svc in self.services:
            try:
                svc_data = json.loads(svc['banner'])
                if svc_data['service']['@name'] == 'http' and svc_data['service']['@tunnel'] == 'ssl':
                    (details, err) = certCheck(self.fqdn, svc['port'])
                    if len(err) > 0:
                        self.details = details
                        self.found = True
                        vports.append(svc['port'])
                        curl_out.append(err)
            except KeyError:
                pass
        if len(curl_out) > 1:
            word = 'ports'
        else:
            word = 'port'
        if len(vports) == 1:
            self.description = f"Invalid SSL certificate found on {word} found on port {vports[0]}."
        elif len(vports) > 1:
            self.description = f"Invalid SSL certificate found on {word}: {','.join(vports)}."
        else:
            self.found = False
        if self.found:
            logger.info("SHOULD BE SAVED: %s " % self.description)

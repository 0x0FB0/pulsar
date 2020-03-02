import json
import re

from celery.utils.log import get_task_logger

from ..scanner_utils import ServiceScannerPlugin, NVDSearchForCPE, updateCPE, Sandbox, CVE

logger = get_task_logger(__name__)
sandbox = Sandbox()

def getCPEs(dom, port, ssl, unique_id):
    result = ''
    logger.info("WHATWEB START")
    logger.info("RUNNING WHATWEB")
    out_file = f'/opt/scan_data/whatweb-{unique_id}-{port}-out.json'
    if ssl:
        prefix = 'https://'
    else:
        prefix = 'http://'
    cmd = f'whatweb --url-prefix {prefix} -a 3 {dom}:{port} --log-json={out_file}'
    # BROKEN WHATWEB?
    while result == None or result == '':
        sandbox.exec_sandboxed(cmd)
        result = sandbox.retrieve_sandboxed(out_file)
    cpes = list()
    try:
        contents = result.replace('\n', '')
        sandbox.remove_sandboxed(out_file)
        data = json.loads(contents)
        if len(data) > 0:
            for record in data:
                if 'plugins' in record:
                    cpes.extend(
                        [re.sub(r'[^A-Za-z0-9:\-_]+', '', cpe).replace('-', ':').lower() + \
                         ':' + '.'.join(record['plugins'][cpe]['version'][0].split('-')[0].split('.')[:3]) \
                         for cpe in record['plugins'].keys()
                            if 'version' in record['plugins'][cpe] and re.match(r'(\d+|\.+)',
                                record['plugins'][cpe]['version'][0])]
                    )

        return cpes
    except (json.JSONDecodeError, OSError) as e:
        logger.info("WHATWEB PARSE ERROR: %s" % e)
        return cpes

class WebComponentsPlugin(ServiceScannerPlugin):
    custom_scanner = True
    name = 'Vulnerable Web Components Plugin'
    short = 'What Web'
    reference = "https://nvd.nist.gov/vuln/search"

    def run(self):
        vports = {}
        logger.info("STARTING CVE SCAN FOR %s" % self.fqdn)
        for svc in self.services:
            try:
                svc_data = json.loads(svc['banner'])
                if svc_data['service']['@name'] == 'http':
                    if '@tunnel' in svc_data['service'] and svc_data['service']['@tunnel'] == 'ssl':
                        cpes = getCPEs(self.fqdn, str(svc['port']), True, self.task_id)
                        logger.info("GOT CPES: %s" % repr(cpes))
                    else:
                        cpes = getCPEs(self.fqdn, str(svc['port']), False, self.task_id)
                        logger.info("GOT CPES: %s" % repr(cpes))
                    if type(cpes) == str:
                        cpes = [cpes]
                    if len(cpes) > 0:
                        if str(svc['port']) in vports:
                            vports[str(svc['port'])].extend(cpes)
                        else:
                            vports[str(svc['port'])] = cpes
            except KeyError as e:
                logger.info("CPE ERROR: %s" % e)
                pass
        for port in vports.keys():
            for cpe in vports[port]:
                updateCPE(str(svc['port']), self.fqdn, self.task_id, cpe)
                cves = NVDSearchForCPE(cpe)
                logger.info("GOT CVES LEN: %s" % len(cves))
                if len(cves) > 0:
                    try:
                        for key in cves:
                            cve = json.loads(CVE.objects.get(id=key).data)
                            CVE.objects.get(id=key).delete()
                            logger.info("PROCESSING CVE: %s" % len(cves))
                            name = str(cve['cve']['CVE_data_meta']['ID'])
                            logger.info("GOT CVE: %s" % name)
                            description = 'Scan have identified a vulnerable web component on port %s. ' % port
                            description += 'Vulnerability have been found by detected software version'
                            description += ' and is prone to false positives.'
                            details = 'ID: ' + cve['cve']['CVE_data_meta']['ID'] + '\n'
                            if 'baseMetricV3' in cve['impact']:
                                if 'baseSeverity' in cve['impact']['baseMetricV3']['cvssV3']:
                                    details += 'Severity: ' + str(
                                        cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']) + '\n'
                                details += 'CVSSv3 Base Score: ' + str(
                                    cve['impact']['baseMetricV3']['cvssV3']['baseScore']) + '\n'
                                details += 'CVSSv3 Vector: ' + str(
                                    cve['impact']['baseMetricV3']['cvssV3']['vectorString']) + '\n'
                                cvss = str(cve['impact']['baseMetricV3']['cvssV3']['vectorString'])
                                score = float(cve['impact']['baseMetricV3']['cvssV3']['baseScore'])
                            elif 'baseMetricV2' in cve['impact']:
                                if 'baseSeverity' in cve['impact']['baseMetricV2']['cvssV2']:
                                    details += 'Severity: ' + str(
                                        cve['impact']['baseMetricV2']['cvssV2']['baseSeverity']) + '\n'
                                details += 'CVSSv2 Base Score: ' + str(
                                    cve['impact']['baseMetricV2']['cvssV2']['baseScore']) + '\n'
                                details += 'CVSSv2 Vector: ' + str(
                                    cve['impact']['baseMetricV2']['cvssV2']['vectorString']) + '\n'
                                cvss = str(cve['impact']['baseMetricV2']['cvssV2']['vectorString'])
                                score = float(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
                            details += 'Description: ' + str(
                                cve['cve']['description']['description_data'][0]['value']) + '\n'
                            if len(cve['cve']['references']['reference_data']) > 0:
                                reference = str(cve['cve']['references']['reference_data'][0]['url'])
                            self.vulnerabilities.append({
                                'name': name,
                                'cvss': cvss,
                                'plugin': self.name,
                                'details': details,
                                'score': score,
                                'confidence': 0.6,
                                'description': description,
                                'reference': reference,
                                'info': False
                            })
                    except KeyError as e:
                        logger.info("GOT ERROR!: %s in %s" % (e, repr(cve)))
                        pass



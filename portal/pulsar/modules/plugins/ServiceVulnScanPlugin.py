import json
from celery.utils.log import get_task_logger
from ..scanner_utils import ServiceScannerPlugin, NVDSearchForCPE, updateCPE, CVE

logger = get_task_logger(__name__)


class ServiceVulnScanPlugin(ServiceScannerPlugin):
    custom_scanner = True
    plugin = 'Vulnerable Services Plugin'
    name = 'Vulnerable Services'
    short = 'Vuln Scan'
    reference = "https://nvd.nist.gov/vuln/search"

    def run(self):
        vports = {}
        logger.info("STARTING CVE SCAN FOR %s" % self.fqdn)
        for svc in self.services:
            try:
                svc_data = json.loads(svc['banner'])
                if 'service' in svc_data and 'cpe' in svc_data['service']:
                    cpe = svc_data['service']['cpe']
                    if type(cpe) == str:
                        cpes = [cpe]
                    else:
                        cpes = cpe
                    if len(cpes) > 0:
                        if str(svc['port']) in vports:
                            vports[str(svc['port'])].extend(cpes)
                        else:
                            vports[str(svc['port'])] = cpes
            except KeyError as e:
                logger.info("CPE ERROR: %s" % e)
                pass
        logger.info("GOT CPES: %s" % repr(vports))
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
                            description = 'Scan have identified a vulnerable TCP service on port %s. ' % port
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
                                'plugin': self.plugin,
                                'details': details,
                                'score': score,
                                'confidence': 0.6,
                                'description': description,
                                'reference': reference,
                                'info': False
                            })
                    except KeyError as e:
                        logger.info("GOT ERROR: %s" % e)
                        pass



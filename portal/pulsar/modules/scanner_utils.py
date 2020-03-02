
import base64
import json
import os
import re
import time
import urllib.request
import uuid
import zipfile
from django.utils import timezone
import requests
from billiard import pool
from celery.utils.log import get_task_logger
from fabric import Connection, Config
from invoke.exceptions import UnexpectedExit

from .country_codes import country_codes
from ..models import *
from ..tasks import search_in_file

logger = get_task_logger(__name__)

scan_settings = {
    'heavy_processes': ['amass', 'zdns'], # consider Nmap
    'cmd_timeout': '2h', # linux timeout syntax i.e. 10s 10m 10h 10d
    'nmap_host_timeout': '10m',
    'amass_timeout': '20',
    'amass_flags': '-ipv4 -noalts ',
    'nmap_tcp_flags': '-Pn -n -T4 -sS -vv',
    'nmap_udp_flags': '-Pn -n -T4 -sU -vv',
}

class CVE(CVEEntry):
    pass

class NullConfig(Config):
    def load_base_conf_files(self):
        pass


class Sandbox():

    def connect(self, host='sandbox', user='root', connect_kwargs={'key_filename':'/etc/ssh/sandbox_key'}):
        conf = NullConfig()
        conn = Connection(host=host, user=user, connect_kwargs=connect_kwargs, config=conf)
        return conn

    def check_busy(self):
        c = self.connect()
        # check for heavy processes running
        while True:
            try:
                c.run('ls /opt/scan_mutex', pty=True)
            except UnexpectedExit:
                break
            logger.info('SANDBOX BUSY, WAITING..')
            time.sleep(13)
        # check for update pending
        while True:
            try:
                c.run('ls /portal/nvd/feeds/mutex', pty=True)
            except UnexpectedExit:
                break
            logger.info('SANDBOX BUSY, WAITING..')
            time.sleep(13)
        c.close()


    def exec(self, cmd):
        c = self.connect()
        logger.info('EXECUTING: %s' % repr(cmd))
        try:
            heavy = False
            self.check_busy()
            for hproc in scan_settings['heavy_processes']:
                if hproc + ' ' in cmd:
                    c.run('touch /opt/scan_mutex', pty=True)
                    logger.info('SANDBOX HEAVY LOADED')
                    heavy = True
            b64cmd = base64.b64encode(cmd.encode('utf-8'))
            logger.info('EXEC')
            result = c.run( f'echo {b64cmd.decode("utf-8")}| base64 -d | '\
                    f' timeout {scan_settings["cmd_timeout"]} bash ', pty=True)
            if heavy:
                logger.info('SANDBOX FREE NOW')
                c.run('rm /opt/scan_mutex', pty=True)
            c.close()
            return result.stdout.strip()
        except UnexpectedExit as e:
            logger.info("SANDBOX COMMAND ERROR: %s" % repr(e))
            if heavy:
                logger.info('SANDBOX FREE NOW')
                try:
                    c.run('rm /opt/scan_mutex', pty=True)
                except UnexpectedExit as e:
                    pass
            c.close()
            return ''

    def exec_sandboxed(self, cmd):
        fullcmd = 'export GOPATH=/opt/ && '
        fullcmd += 'export PATH=${PATH}:/usr/local/go/bin:/opt/bin && '
        fullcmd += cmd
        result = self.exec(fullcmd)
        return result

    def get_sandboxed(self, url, wget_args=''):
        agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'
        result = self.exec(f'wget --max-redirect 3 -q -U "{agent}" -O- "{url}" {wget_args}')
        return result

    def post_sandboxed(self, url, data, wget_args=''):
        agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'
        result = self.exec(f'wget --max-redirect 3 -q -U "{agent}" -O- "{url}" --post-data={data} {wget_args}')
        return result

    def upload_sandboxed_file(self, upfile):
        upfname = upfile.split('/')[-1]
        with open(upfile, 'r') as f:
            contents = f.read()
        self.exec(f'cat << EOF > /opt/scan_data/' + upfname + '\n' + contents + '\nEOF\n')
        return upfname

    def upload_sandboxed_content(self, upfname, contents):
        self.exec(f'cat << EOF > ' + upfname + '\n' + contents + '\nEOF\n')
        return f'{upfname}'

    def retrieve_sandboxed(self, remfile):
        result = self.exec(f'cat {remfile}')
        return result

    def remove_sandboxed(self, delfile):
        self.exec(f'rm -f {delfile}')
        return True

def updateCPE(port, fqdn, task_id, cpe):
    doms = DomainInstance.objects.filter(fqdn=fqdn, last_task=task_id)
    ips = IPv4AddrInstance.objects.filter(domain__in=doms, last_task=task_id)
    cpes = [cpe['cpe']
            for cpe in ServiceInstance.objects.filter(ip__in=ips, last_task=task_id, port=str(port)).values('cpe')
            if cpe['cpe'] != 'None']
    if len(cpes) > 0 and len(';'.join(cpes) + ';' + cpe) < 4096:

        ServiceInstance.objects.filter(ip__in=ips, last_task=task_id, port=str(port)).update(
            cpe=';'.join(cpes) + ';' + cpe
        )
    else:
        ServiceInstance.objects.filter(ip__in=ips, last_task=task_id, port=str(port)).update(
            cpe=cpe
        )

def downloadHelper(download_path, url):
    logger.info("NVD DOWNLOAD: %s" % url)
    durl = url
    dpath = download_path + url.split('/')[-1]
    try:
        urllib.request.urlretrieve(durl, dpath)
    except (urllib.error.URLError, OSError):
        pass

def updateNVDFeed():
    if not os.path.exists('/portal/nvd/feeds/mutex'):
        dpath = '/portal/nvd/download/'
        fpath = '/portal/nvd/feeds/'
        try:
            with open(fpath+'mutex', 'w'):
                pass
        except OSError:
            pass
        feeds = {
                "2002": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip"
                },
                "2003": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.zip"
                },
                "2004": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.zip"
                },
                "2005": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.zip"
                },
                "2006": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.zip"
                },
                "2007": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.zip"
                },
                "2008": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.zip"
                },
                "2009": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.zip"
                },
                "2010": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.zip"
                },
                "2011": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip"
                },
                "2012": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.zip"
                },
                "2013": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.zip"
                },
                "2014": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.zip"
                },
                "2015": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.zip"
                },
                "2016": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.zip"
                },
                "2017": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.zip"
                },
                "2018": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.zip"
                },
                "2019": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip"
                },
                "2020": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip"
                },
                "modified": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
                },
                "recent": {
                    "meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta",
                    "gz": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
                    "zip": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
                }
            }
        downloaded = list()
        try:
            for feed in feeds.keys():
                meta_file = feeds[feed]['meta'].split('/')[-1]
                try:
                    if os.path.isfile(dpath + meta_file):
                        with open(dpath + meta_file, 'r') as lf:
                            lhash = lf.read().replace('\r', '').split('\n')[4].split(':')[1]
                        rf = requests.get(feeds[feed]['meta'])
                        try:
                            rhash = rf.text.replace('\r','').split('\n')[4].split(':')[1]
                            if lhash != rhash:
                                downloadHelper(dpath, feeds[feed]['meta'])
                                downloadHelper(dpath, feeds[feed]['zip'])
                                downloaded.append(dpath + feeds[feed]['zip'].split('/')[-1])
                                try:
                                    os.system('rm -f /portal/nvd/cache/*')
                                except OSError:
                                    pass
                        except IndexError:
                            pass
                    else:
                        downloadHelper(dpath, feeds[feed]['meta'])
                        downloadHelper(dpath, feeds[feed]['zip'])
                        downloaded.append(dpath + feeds[feed]['zip'].split('/')[-1])
                except OSError:
                    downloadHelper(dpath, feeds[feed]['meta'])
                    downloadHelper(dpath, feeds[feed]['zip'])
                    downloaded.append(dpath + feeds[feed]['zip'].split('/')[-1])
            for df in downloaded:
                try:
                    logger.info("NVD EXTRACT: %s" % df)
                    with zipfile.ZipFile(df, 'r') as zip_ref:
                        zip_ref.extractall(fpath)
                except zipfile.BadZipFile:
                    pass
            try:
                os.remove(fpath+'mutex')
                os.system('rm -rf /portal/nvd/cache/*')
            except OSError:
                pass
        except Exception as e:
            try:
                logger.info("FATAL UPDATE ERROR: %s" % repr(e))
                os.remove(fpath + 'mutex')
            except OSError:
                pass
            raise

        return "NVD feeds downloaded: %s" % len(downloaded)


def NVDSearchForCPE(cpe):
    logger.info("RECEIVED CPE %s: %s" % (type(cpe), cpe))
    cache = '/portal/nvd/cache/'
    start = time.time()
    search_pool = pool.Pool(2)
    cve_list = list()
    clean = cpe.replace('cpe:','').replace('/','') + ':'
    if len(clean.split(':')) > 2 and re.match(r'.*:([\d+\.+]+)', clean):
        print("got correct cpe with version: %s" % clean)
        try:
            regex = r'.*:([\d+\.+]+)(.*):'
            badver = re.match(regex, clean)
            if badver:
                pieces = clean.split(':')
                clean = ':'.join(pieces[0:len(pieces)-2])
                clean += ':' + badver.group(1)
                clean += ':' + badver.group(2)
            if clean[len(clean)-1] != ':':
                clean += ':'
            print("fixed cpe: %s" % clean)
            cache_files = os.listdir(cache)
            b64clean = base64.b64encode(clean.encode())
            logger.info("SEARCHING %s IN CACHE: %s" % (b64clean, repr(cache_files)))
            if b64clean.decode('utf-8') in cache_files:
                with open(cache + b64clean.decode('utf-8'), 'r') as cache_file:
                    cve_list.append(json.loads(cache_file.read()))
                    logger.info("FOUND IN CACHE: %s" % repr(cve_list))
            else:
                logger.info('NOT FOUND IN CACHE, SEARCHING..')
                fdir = '/portal/nvd/feeds/'
                dfeeds = [f for f in os.listdir(fdir) if '.json' in f]
                cve_list = list()
                worker_data = []
                logger.info('SEARCHING %s...' % clean)
                for feed in dfeeds:
                    worker_data.append((fdir + feed, clean))
                cves = search_pool.map(search_in_file, [work for work in worker_data])
                search_pool.close()
                cve_list.extend([item for sublist in cves for item in sublist])
                logger.info('FOUND CVES: %s' % len(cve_list))
                logger.info('SEARCH TOOK: %s' % (time.time() - start))
                print('SEARCH TOOK: %s' % (time.time() - start))
                with open(cache + b64clean.decode('utf-8'), 'w') as cache_file:
                    cache_file.write(json.dumps(cve_list))
                return cve_list
        except (OSError, json.JSONDecodeError) as e:
            logger.info("CVE PARSE ERROR: %s, cves: %s" % (e, cve_list))
            pass
    return []


def getCountryData(ip):
    try:
        country = 'NA'
        while True:
            try:
                data = requests.get("https://stat.ripe.net/data/rir-geo/data.json?sourceapp=OpenOSINT&resource="+ip)
                break
            except Exception as e:
                logger.info("CONNECTION ERROR: %s" % repr(e))
                time.sleep(2)
                pass
        jdata = json.loads(data.content)
        answer = jdata['data']
        logger.info('GETTING COUNTRY DATA: %s ' % repr(answer) )
        if 'located_resources' in answer:
            if len(answer['located_resources']) > 0:
                logger.info('COUNTRY RETURN: %s' % answer['located_resources'][0]['location'])
                country = answer['located_resources'][0]['location']
            else:
                data = requests.get("https://stat.ripe.net/data/rir/data.json?sourceapp=OpenOSINT&lod=2&resource="+ip)
                logger.info('GETTING COUNTRY DATA: %s ' % repr(data))
                jdata = json.loads(data.content)
                if 'data' in jdata:
                    answer = jdata['data']
                    if 'rirs' in answer and len(answer['rirs']) > 0:
                        logger.info('COUNTRY RETURN: %s' % answer['rirs'][0]['country'])
                        country = answer['rirs'][0]['country']
                    else:
                        raise ValueError
        if country == None:
            found = 'NA'
        else:
            found = country_codes[country]
        return found
    except (ValueError, KeyError, ConnectionError):
        return 'NA'

def getIPData(ip):
    try:
        ip_data = {'ip': ip,
                   'asn': 0,
                   'cidr': 'NA',
                   'desc': 'NA',
                   }
        data = requests.get(f"https://stat.ripe.net/data/whois/data.json?sourceapp=OpenOSINT&resource={ip}")
        jdata = json.loads(data.content)
        if 'data' in jdata:
            if 'irr_records' in jdata['data']:
                for record in jdata['data']['irr_records']:
                    for k in record:
                        if k['key'] == 'origin':
                            ip_data['asn'] = int(k['value'])
                        elif k['key'] == 'descr':
                            ip_data['desc'] = k['value']
                        elif k['key'] == 'route':
                            ip_data['cidr'] = k['value']
            if ip_data['asn'] == 0 or ip_data['cidr'] == 'NA' or ip_data['desc'] == 'NA':
                if 'records' in jdata['data']:
                    for record in jdata['data']['records']:
                        for k in record:
                            if k['key'] == 'origin':
                                ip_data['asn'] = int(k['value'])
                            elif k['key'] == 'descr':
                                ip_data['desc'] = k['value']
                            elif k['key'] == 'route':
                                ip_data['cidr'] = k['value']
                else:
                    raise ValueError
            if ip_data['asn'] == 0 or ip_data['cidr'] == 'NA' or ip_data['desc'] == 'NA':
                raise ValueError
            return [ip_data, ]
    except (ValueError, ConnectionError):
        return [ip_data, ]

def aBulkRecordLookup(list_input):
    sandbox = Sandbox()
    logger.info("BULK DNS LOOKUP: %s" % repr(list_input))
    dom_list = '\\n'.join(list_input)
    doms = []
    with open('/portal/pulsar/modules/root_servers.list') as f:
        server_list = f.read().strip("\n")
    s_cmd = f'echo -e {dom_list} | zdns A -iterative -retries 3 --name-servers {server_list}'
    result = sandbox.exec_sandboxed(s_cmd)
    memory = {}
    for res in result.split('\n'):
        try:
            jdata = json.loads(res)
            if 'name' in jdata:
                name = jdata['name']
                data = jdata['data']
                if 'answers' in data:
                    if data['answers'] != None:
                        for ans in data['answers']:
                            if 'answer' in ans:
                                if ans['type'] == 'A':
                                    logger.info(f"GOT IP: {ans['answer']}")
                                    if ans['answer'] in memory:
                                        ip = memory[ans['answer']]
                                    else:
                                        ip = getIPData(ans['answer'])
                                        memory[ans['answer']] = ip
                                        logger.info(f'GOT NEW IP DATA: {ip}')
                                    doms.append({'fqdn':name, 'ip': ip})
                logger.info("GOT DOMAINS: %s" % repr(doms))
        except json.JSONDecodeError:
            pass
    return doms

def unique_list(process_list):
    uniq_list = []
    for a in process_list:
        if a not in uniq_list:
            uniq_list.append(a)
    return uniq_list

def checkForNewDomains(task_id):
    task = ScanTask.objects.get(id=task_id)
    prev_tasks = ScanTask.objects.filter(asset=task.asset) \
        .exclude(id=task.id) \
        .count()
    if prev_tasks > 0:
        old_doms = unique_list(DomainInstance.objects.filter(asset=task.asset)
                               .exclude(last_task=task)
                               .values('fqdn'))
        old_doms_list = [d['fqdn'] for d in old_doms]
        logger.info('PREV ITEMS: %s' % old_doms_list)
        new_doms = DomainInstance.objects.filter(asset=task.asset, last_task=task)\
            .exclude(fqdn__in=old_doms_list)
        new_doms_list = [str(d.id) for d in new_doms]
        logger.info('CURR ITEMS: %s' % new_doms_list)
        return new_doms_list
    else:
        return []

def checkForNewVuln(task_id):
    task = ScanTask.objects.get(id=task_id)
    prev_tasks = ScanTask.objects.filter(asset=task.asset)\
        .exclude(id=task.id)\
        .count()
    if prev_tasks > 0:
        asset = task.asset
        prev_hashes = list()
        prev_vulns = VulnInstance.objects.filter(asset=asset, false_positive=False, info=False)\
            .exclude(last_task=task)
        logger.info('PREV ITEMS: %s' % prev_vulns)
        curr_vulns = VulnInstance.objects.filter(last_task=task, false_positive=False, info=False)
        logger.info('CURR ITEMS: %s' % curr_vulns)
        for vuln in prev_vulns:
            prev_hashes.append(vuln.__sha__().hexdigest())
        new_vulns = [str(vuln.id) for vuln in curr_vulns if vuln.__sha__().hexdigest() not in prev_hashes]
        return new_vulns
    else:
        return []


def calc_asset_by_task(task_id):
    task = ScanTask.objects.get(id=uuid.UUID(task_id))
    dom_list = DomainInstance.objects.filter(asset=uuid.UUID(str(task.asset.id)),
                                             last_task=task,
                                             false_positive=False)
    false_pos_doms = [a['fqdn'] for a in list(
        DomainInstance.objects.filter(last_task=task, false_positive=True).values('fqdn')
    )]

    false_pos_vulns = [[str(vuln.domain.fqdn), str(vuln.plugin)] for vuln in
                       VulnInstance.objects.filter(last_task=task, false_positive=True)]

    asset_sum = asset_score = \
        dom_sum = dom_max = dom_score = \
        ip_sum = ip_max = ip_score = \
        vuln_sum = vuln_max = 0.0

    dom_count = 0
    dom_max = 0.0
    for dom in dom_list:
        dom_score = 0.0
        if dom.fqdn not in false_pos_doms:
            dom_count += 1
            dom_sum = 0.0
            ip_list = IPv4AddrInstance.objects.filter(domain=dom, last_task=task)
            ip_count = len(ip_list)
            for ip in ip_list:
                ip_score = 0.0
                ip_sum = 0.0
                ip_max = 0.0
                vuln_list = VulnInstance.objects.filter(ip=ip, last_task=task, false_positive=False)
                logger.info("VULN LIST FOR CALC: %s" % repr(vuln_list))
                vuln_count = 0
                vuln_max = 0.0
                for vuln in vuln_list:
                    vuln_score = 0.0
                    vuln_score = float(vuln.score) * float(vuln.confidence)
                    if [str(vuln.domain.fqdn), str(vuln.plugin)] not in false_pos_vulns and not vuln.info:
                        vuln_count += 1
                        ip_sum += vuln_score
                        if vuln_score > vuln_max:
                            vuln_max = vuln_score
                    elif [str(vuln.domain.fqdn), str(vuln.plugin)] in false_pos_vulns:
                        vuln.false_positive = True
                        vuln.save()
                    logger.info("CALC IP SUM: %s" % ip_sum)
                if ip_sum > 0 and vuln_count > 0:
                    ip_score = (float(ip_sum / float(vuln_count)) + float(vuln_max)) / 2
                    logger.info(
                        "CALC IP: %s = %s/%s +%s /2" % (ip_score, ip_sum, vuln_count, vuln_max))
                logger.info("CALC IP: %s" % ip_score)
                dom_sum += ip_score
                if ip_score > ip_max:
                    ip_max = ip_score
                ip.score = ip_score
                ip.save()
        if dom_sum > 0 and ip_count > 0:
            dom_score = ((float(dom_sum / float(ip_count)) + float(ip_max)) / 2) * dom.confidence
            logger.info(
                "CALC DOM: %s = %s/%s +%s /2 * %s" % (dom_score, dom_sum, ip_count, ip_max, dom.confidence))
        logger.info("CALC DOM: %s" % dom_score)
        asset_sum += dom_score
        if dom_score > dom_max:
            dom_max = dom_score
        dom.total_score = dom_score
        dom.save()
    if dom_count > 0:
        asset_score = (float(asset_sum / float(dom_count)) + float(dom_max)) / 2
        logger.info("CALC ASSET: %s = %s/%s +%s /2 " % (asset_score, asset_sum, dom_count, dom_max))
    logger.info("CALC ASSET: %s" % asset_score)

    scan = ScanInstance.objects.get(last_task=task)
    scan.status = 'SCANNED'
    scan.total_score = asset_score
    scan.scanned_date = timezone.now()
    scan.save()

    asset = scan.asset
    asset.current_score = asset_score
    asset.save()

    return asset_score


class BaseDiscoveryPlugin():
    fast = False
    recursive = False
    name = 'basic discovery'
    short = ''
    ptype = ''
    confidence = 0.9
    discovered = list()
    history = list()
    nets = list()
    ip = ''
    asset_name = ''
    asset_dom = ''
    policy = {}
    fqdn = ''
    asset_id = ''
    task_id = ''

    def create(self, asset_id, task_id):
        self.discovered = list()
        self.asset_id = asset_id
        self.task_id = task_id
        self.history = [d['fqdn'] for d in DomainInstance.objects.filter(asset=self.asset_id).values('fqdn')]
        self.ptype = self.__class__.__name__
        self.fqdn = AssetInstance.objects.filter(id=self.asset_id).values('domain').first()["domain"]
        scan = ScanInstance.objects.filter(last_task=task_id).first()
        if scan and scan.policy:
            self.policy = scan.policy
        asset = AssetInstance.objects.get(id=asset_id)
        self.asset_name = re.sub('[^A-Za-z0-9 \.]+', '', asset.name)
        self.asset_dom = asset.domain
        nets = [ip['cidr'] for ip in IPv4AddrInstance.objects.filter(asset=self.asset_id,
                                                                          desc__icontains=asset.name).values('cidr')]
        self.nets = unique_list([net for net in nets if int(net.split('/')[1]) >= 24])

    def run(self):
        pass

    def save(self):
        asset = AssetInstance.objects.get(id=uuid.UUID(str(self.asset_id)))
        task = ScanTask.objects.get(id=uuid.UUID(self.task_id))
        memory = {}
        for dom in self.discovered:
            countries = []
            country = 'NA'
            for ip in dom['ip']:
                if ip['ip'] not in memory:
                    country_data = getCountryData(ip['ip'])
                    countries.append(country_data)
                    memory[ip['ip']] = country_data
                else:
                    countries.append(memory[ip['ip']])
            country = max(set(countries), key=countries.count)
            logger.info("DUPLICATES SEARCH: %s" % repr(DomainInstance.objects.filter(fqdn=dom['fqdn'], last_task=task).values('fqdn')))
            duplicates = DomainInstance.objects.filter(fqdn=dom['fqdn'], last_task=task).count()
            if duplicates == 0:
                logger.info("PLUGIN SAVE: domain=%s for asset.id=%s task.id=%s" % (dom, asset.id, task.id))
                dom_instance = DomainInstance(last_task=task, asset=asset,
                                           fqdn=dom['fqdn'], confidence=self.confidence,
                                           plugin=self.name,
                                           country=country)
                dom_instance.save()
            elif duplicates > 0:
                dom_instance = DomainInstance.objects.filter(fqdn=dom['fqdn'], asset=asset, last_task=task).last()
            for ip in dom['ip']:
                try:
                    duplicates = IPv4AddrInstance.objects.filter(ip=ip['ip'], domain=dom_instance).count()
                    if duplicates == 0:
                        if ip['ip'] not in memory:
                            country = getCountryData(ip['ip'])
                            memory[ip['ip']] = country
                        else:
                            country = memory[ip['ip']]
                        IPv4AddrInstance.objects.create(ip=ip['ip'], cidr=ip['cidr'], asn=ip['asn'],
                                                desc=ip['desc'], last_task=task, asset=asset,
                                               domain=dom_instance, country=country)
                except TypeError:
                    pass


class ServiceDiscoveryPlugin():
    fast = True
    name = 'basic discovery'
    short = ''
    ptype = ''
    history = list()
    domain_list = []
    ip_list = []
    services = {}
    policy = {}
    fqdn = ''
    asset_id = ''
    task_id = ''

    def create(self, asset_id, task_id):
        self.services = {}
        self.asset_id = asset_id
        self.task_id = task_id
        self.ptype = self.__class__.__name__
        doms = DomainInstance.objects.filter(last_task=task_id)
        self.domain_list = unique_list([x['fqdn'] for x in doms.values('fqdn')])
        self.ip_list = unique_list([x['ip'] for x in IPv4AddrInstance.objects.filter(
            last_task=task_id, domain__in=doms
            ).values('ip')])
        self.fqdn = AssetInstance.objects.filter(id=self.asset_id).values('domain').first()["domain"]
        scan = ScanInstance.objects.filter(last_task=task_id).first()
        if scan and scan.policy:
            self.policy = scan.policy

    def run(self):
        pass

    def save(self):

        asset = AssetInstance.objects.get(id=uuid.UUID(str(self.asset_id)))
        task = ScanTask.objects.get(id=uuid.UUID(self.task_id))
        doms = DomainInstance.objects.filter(last_task=self.task_id)

        for dom in doms:
            for ip in self.ip_list:
                if ip in self.services:
                    dom_ips = IPv4AddrInstance.objects.filter(ip=ip, last_task=self.task_id, domain=dom)
                    for dom_ip in dom_ips:
                        for svc in self.services[ip]:
                            ServiceInstance.objects.create(
                                proto=svc['proto'],
                                port=svc['port'],
                                desc=svc['desc'],
                                banner=svc['banner'],
                                ip=dom_ip,
                                last_task=task,
                                asset=asset,
                            )

class BaseScannerPlugin():
    name = 'basic scanner'
    short = ''
    plugin = 'basic scanner'
    ptype = ''
    confidence = 1.0
    score = 8.9
    fast = True
    info = False
    oneshot = False
    found = False
    description = ''
    reference = ''
    fqdn = ''
    ip = ''
    details = ''
    cvss = ''
    services = {}
    policy = {}
    asset_name = ''
    asset_dom = ''
    scanned = list()
    domains = list()
    dom_id = ''
    task_id = ''
    ip_id = ''
    asset_id = ''

    def create(self, dom_id, ip_id, asset_id, task_id):
        from ..serializers import ServiceSerializer
        self.dom_id = dom_id
        self.ip_id = ip_id
        self.asset_id = asset_id
        self.task_id = task_id
        self.ptype = self.__class__.__name__

        scan = ScanInstance.objects.filter(last_task=task_id).first()
        if scan and scan.policy:
            self.policy = scan.policy
        self.asset_name = scan.asset.name
        self.asset_dom = scan.asset.domain
        self.fqdn = DomainInstance.objects.get(id=self.dom_id).fqdn
        self.ip = IPv4AddrInstance.objects.get(id=self.ip_id).ip
        services = ServiceInstance.objects.filter(last_task=task_id, ip=self.ip_id)
        service_serializer = ServiceSerializer(services, many=True)
        self.services = service_serializer.data

    def run(self):
        pass


    def save(self):
        if self.found:
            dom = DomainInstance.objects.get(id=uuid.UUID(self.dom_id))
            asset = AssetInstance.objects.get(id=uuid.UUID(str(self.asset_id)))
            ip = IPv4AddrInstance.objects.get(id=uuid.UUID(str(self.ip_id)))
            duplicates = VulnInstance.objects.filter(domain=dom, name=self.name, description=self.description,
                                                     last_task=dom.last_task, plugin=self.plugin,
                                                     confidence=self.confidence, score=self.score).count()
            if duplicates == 0:
                vuln = VulnInstance(domain=dom, ip=ip, name=self.name, description=self.description, score=self.score,
                                    confidence=self.confidence, plugin=self.plugin, asset=asset, last_task=dom.last_task,
                                    info=self.info, details=self.details, reference=self.reference, cvss=self.cvss)
                vuln.save()


class ServiceScannerPlugin():
    name = 'basic scanner'
    short = ''
    plugin = 'basic scanner'
    ptype = ''
    confidence = 1.0
    score = 8.9
    plan = 'free'
    fast = True
    info = False
    found = False
    description = ''
    reference = ''
    fqdn = ''
    ip = ''
    details = ''
    cvss = ''
    services = {}
    policy = {},
    vulnerabilities = []
    scanned = list()
    domains = list()
    dom_id = ''
    task_id = ''
    ip_id = ''
    asset_id = ''

    def create(self, dom_id, ip_id, asset_id, task_id):
        from ..serializers import ServiceSerializer
        self.vulnerabilities = list()
        self.dom_id = dom_id
        self.ip_id = ip_id
        self.asset_id = asset_id
        self.task_id = task_id
        self.ptype = self.__class__.__name__

        scan = ScanInstance.objects.filter(last_task=task_id).first()
        if scan and scan.policy:
            self.policy = scan.policy
        self.fqdn = DomainInstance.objects.get(id=self.dom_id).fqdn
        self.ip = IPv4AddrInstance.objects.get(id=self.ip_id).ip
        services = ServiceInstance.objects.filter(last_task=task_id, ip=self.ip_id)
        service_serializer = ServiceSerializer(services, many=True)
        self.services = service_serializer.data

    def run(self):
        pass


    def save(self):
        logger.info("SAVING WEB: %s" % self.vulnerabilities)
        for vuln in self.vulnerabilities:
            dom = DomainInstance.objects.get(id=uuid.UUID(self.dom_id))
            asset = AssetInstance.objects.get(id=uuid.UUID(str(self.asset_id)))
            ip = IPv4AddrInstance.objects.get(id=uuid.UUID(str(self.ip_id)))
            vuln = VulnInstance(domain=dom, ip=ip, name=vuln['name'], description=vuln['description'],
                                score=vuln['score'], confidence=vuln['confidence'], plugin=vuln['plugin'],
                                asset=asset, last_task=dom.last_task, info=vuln['info'], details=vuln['details'],
                                cvss=vuln['cvss'], reference=vuln['reference'])
            vuln.save()

class HandMadeScannerPlugin(ServiceScannerPlugin):
    script = ''
    def create(self, dom_id, ip_id, asset_id, task_id, plugin_id):
        from ..serializers import ServiceSerializer
        self.vulnerabilities = list()
        self.dom_id = dom_id
        self.ip_id = ip_id
        self.asset_id = asset_id
        self.task_id = task_id
        self.ptype = self.__class__.__name__
        scan = ScanInstance.objects.filter(last_task=task_id).first()
        if scan and scan.policy:
            self.policy = scan.policy
        self.fqdn = DomainInstance.objects.get(id=self.dom_id).fqdn
        self.ip = IPv4AddrInstance.objects.get(id=self.ip_id).ip
        services = ServiceInstance.objects.filter(last_task=task_id, ip=self.ip_id)
        service_serializer = ServiceSerializer(services, many=True)
        self.services = service_serializer.data
        hadnmade_plugin = HandMadePlugin.objects.get(id=plugin_id)
        self.hmp_id = str(hadnmade_plugin.id)
        self.name = hadnmade_plugin.name
        self.cvss = hadnmade_plugin.cvss
        self.description = hadnmade_plugin.description
        self.confidence = hadnmade_plugin.confidence
        self.score = hadnmade_plugin.score
        self.reference = hadnmade_plugin.reference
        self.info = hadnmade_plugin.info
        self.script = hadnmade_plugin.script

    def run(self):
        pass

    def save(self):
        logger.info("SAVING HANDMADE: %s" % self.details)
        dom = DomainInstance.objects.get(id=uuid.UUID(self.dom_id))
        asset = AssetInstance.objects.get(id=uuid.UUID(str(self.asset_id)))
        ip = IPv4AddrInstance.objects.get(id=uuid.UUID(str(self.ip_id)))
        vuln = VulnInstance(domain=dom, ip=ip, name=self.name, description=self.description,
                            score=self.score, confidence=self.confidence, plugin=self.plugin,
                            asset=asset, last_task=dom.last_task, info=self.info, details=self.details,
                            cvss=self.cvss, reference=self.reference)
        vuln.save()






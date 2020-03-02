import re

from celery.utils.log import get_task_logger

from ..scanner_utils import BaseScannerPlugin, unique_list, Sandbox

logger = get_task_logger(__name__)
sandbox = Sandbox()


class CloudEnumPlugin(BaseScannerPlugin):
    custom_scanner = True
    plugin = 'Cloud Enumeration Plugin'
    short = 'Cloud Enum'
    name = 'Sensitive Cloud Resources'
    cvss = 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'
    confidence = 0.5
    score = 8.6
    reference = "https://github.com/initstring/cloud_enum"

    def run(self):
        logger.info('SEARCHING CLOUD RESOURCES FOR: %s' % self.fqdn)
        s_mutations = list()
        cached = False
        patterns = ['OPEN S3 BUCKET', 'OPEN AZURE CONTAINER', 'OPEN GOOGLE BUCKET']
        asset_name = self.asset_name.split(' ')[0].lower()
        parts = self.fqdn.split('.')
        words = [word for word in parts if len(word) > 4 and parts.index(word) != len(parts)-1
                 and asset_name != word]
        words_hash = str(hash(frozenset(words)))
        cache_file = f'/opt/scan_data/cloud_enum{words_hash}.cache'
        result = sandbox.exec_sandboxed(f'touch {cache_file} && cat {cache_file}')
        for pattern in patterns:
            if pattern in result:
                cached = True
        if not cached:
            for word in words:
                s_mutations.append(word)
                s_mutations.append(asset_name + '.' + word)
                s_mutations.append(asset_name + '-' + word)
                s_mutations.append(word + '.' + asset_name)
                s_mutations.append(word + '-' + asset_name)
                s_mutations.append(word + '-' + asset_name)
            s_cmd = f'/opt/cloud_enum-0.2/cloud_enum.py -m /dev/null -b /dev/null | tee {cache_file}'
            for mut in unique_list(s_mutations):
                s_cmd += f'-k {mut} '
            result = sandbox.exec_sandboxed(s_cmd)
        for pattern in patterns:
            if pattern in result or cached:
                resource = re.search(pattern+'(.*?)'+'\n', result).group(1)
                self.found = True
                if asset_name in '\n'.join([line for line in result.split('\n') if 'Keywords:' not in line]):
                    self.confidence = 0.6
                else:
                    self.confidence = 0.3
                    self.score = 3.1
                self.details = result
                capitalized = ' '.join([p.capitalize() for p in pattern.lower().split(' ')])
                self.description = f"{capitalized} found at {resource} while searching by {self.fqdn}."
                break

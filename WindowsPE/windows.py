# XXX: Typing support
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

# XXX: Standard library imports
import html
import zipfile
from os import path
import os
import hashlib
import json
import urllib.parse
import re
import functools
import io
import subprocess as sub
import time
import random
import string

import malbook


# XXX: StringSifter breaks with LightGBM 3.3.2
# LightGBM needs to be installed first to ensure that
# version gets locked at 3.1.0
malbook.ensure_package('lightgbm==3.1.0')
malbook.ensure_package('stringsifter')

# XXX: Third-party imports that need to be installed first
malbook.ensure_package('beautifulsoup4')
import bs4
malbook.ensure_package('yara-python')
import yara
malbook.ensure_package('requests')
import requests as req
malbook.ensure_package('peid')
import peid
malbook.ensure_package('pyspamsum')
import spamsum
malbook.ensure_package('pefile')
import pefile
malbook.ensure_package('py-tlsh')
import tlsh
malbook.ensure_package('procmon-parser')
import procmon_parser


class _Cache:

    _sample: str
    _cache: Dict[str, Dict[str, Any]]
    _cache_file: Path

    def __init__(self, cache_file: Path):
        try:
            with open(cache_file, 'rt') as f:
                self._cache = json.load(f)
        except:
            self._cache = {}

        self._cache_file = cache_file

        # Init common cache
        if 'common' not in self._cache:
            self._cache['common'] = {}

    def save(self):
        if self._cache_file is None:
            return
        with open(self._cache_file, 'wt') as f:
            json.dump(self._cache, f)

    def set_current_sample(self, sample: str):
        self._sample = sample
        if sample not in self._cache:
            self._cache[sample] = {}

    def get(self, key: str):
        if key in self._cache[self._sample]:
            return self._cache[self._sample][key]
        return None

    def set(self, key: str, value: Any):
        self._cache[self._sample][key] = value

    def get_common(self, key: str):
        if key in self._cache['common']:
            return self._cache['common'][key]
        return None

    def set_common(self, key: str, value: Any):
        self._cache['common'][key] = value


_CWD = os.getcwd()


class Config:

    hashes: List[str] = ['md5', 'sha1', 'sha256', 'imphash', 'spamsum', 'tlsh']

    malware_bazaar: bool = True
    malware_bazaar_sha256: bool = True
    malware_bazaar_imphash: bool = True
    malware_bazaar_imphash_max: int = 100
    malware_bazaar_tlsh: bool = True
    malware_bazaar_tlsh_max: int = 100

    virustotal: bool = True
    virustotal_api_key: Optional[str] = None

    output_path: Path = path.join(_CWD, 'output')

    unzip: bool = True
    unzip_password: Optional[bytes] = b'infected'

    strings: bool = True
    strings_floss: Path = path.join(_CWD, 'bin', 'floss')
    strings_rank: bool = True

    strings_min_length: int = 8
    strings_regex_rules: Dict[str, re.Pattern] = {
        'http': re.compile(r'http.*'),
        'ipv4': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    }

    yara: bool = True
    yara_rules: Path = path.join(_CWD, 'yara')
    yara_ignore: List[str] = []

    packer: bool = True

    imports: bool = True
    imports_malapi: bool = True

    compare: bool = False
    compare_to: List[Path] = []

    virtualbox_procmon: bool = False
    virtualbox_vm_name: str = None

    cache: bool = True


def scan(sample: Path, config: Config) -> None:
    if config.cache:
        cache_path = path.join(config.output_path, 'cache.json')
        cache = _Cache(cache_path)
    else:
        # XXX: Create discardable cache not backed by a file
        cache = _Cache(None)

    if not path.exists(config.output_path):
        os.mkdir(config.output_path)

    # XXX: Spin up the VM as early as possible, since it takes a while
    # and lots of things can go wrong
    vm = None
    if config.virtualbox_procmon:
        vm = VirtualBoxVM(config.virtualbox_vm_name)

    if config.unzip:
        unzipped = _unzip(sample, config)
        for s in os.listdir(unzipped):
            sample_path = path.join(unzipped, s)
            _scan(sample_path, config, cache, vm)
    else:
        _scan(sample, config, cache, vm)

    vm.shutdown()
    cache.save()


def _scan(sample, config, cache, vm):
    name = path.basename(sample)
    _hdr('Report for ' + name, h=1)

    with open(sample, 'rb') as f:
        data = f.read()

    # XXX: Loading file as a PE and computing its hashes
    # are the only mandatory scan steps.
    pe = _pe(data)
    _checksums(data, pe, config, cache)

    if config.malware_bazaar:
        _bazaar(data, pe, config, cache)

    if config.strings:
        _strings(sample, config, cache)

    if config.yara:
        _yara(data, config, cache)

    if config.packer:
        _peid(sample, config, cache)

    if config.imports:
        _imports(pe, config, cache)

    if config.compare:
        _compare(data, config, cache)

    if config.virtualbox_procmon:
        _vbox_procmon(data, config, cache, vm)


def _virustotal(data: bytes, pe: pefile.PE, config: Config, cache: _Cache):
    if config.virustotal_api_key is None:
        raise malbook.Error('Need a valid VirusTotal API key')

    headers = {
        'x-apikey': config.virustotal_api_key,
        'Accept': 'application/json',
    }
    api = 'https://www.virustotal.com/api/v3'

    def make_request(endpoint: str, request: Dict[str, str]):
        resp = req.post(api + endpoint, data=request, headers=headers)
        if resp.status_code == 401:
            raise malbook.Error('VirusTotal API key is incorrect')
        elif resp.status_code == 429:
            raise malbook.Error('VirusTotal quota exceeded')
        elif not resp.ok:
            raise malbook.Error("Can't access VirusTotal")
        return resp.json()


def _bazaar(data: bytes, pe: pefile.PE, config: Config, cache: _Cache):
    api = 'https://mb-api.abuse.ch/api/v1/'
    def make_request(query):
        response = req.post(api, data=query)
        if not response.ok:
            raise malbook.Error("Can't access Malware Bazaar")
        return response.json()

    lis = ''
    n = 0
    if config.malware_bazaar_sha256:
        n += 1

        sha256 = cache.get('sha256')
        if sha256 is None:
            sha256 = _csum(hashlib.sha256, data)
            cache.set('sha256')
        query = {
            'query': 'get_info',
            'hash': sha256,
        }
        response = make_request(query)
        if response['query_status'] == 'hash_not_found':
            lis += '<li>There is no sample with matching sha256 on Malware Bazaar</li>'
        else:
            link = f'https://bazaar.abuse.ch/sample/{sha256}'
            lis += f'''<li><a href="{link}">Sample page</a> on Malware Bazaar</li>'''

    if config.malware_bazaar_imphash:
        n += 1

        imphash = cache.get('imphash')
        if imphash is None:
            imphash = pe.get_imphash()
            cache.set('imphash', imphash)
        query = {
            'query': 'get_imphash',
            'imphash': imphash,
            'limit': config.malware_bazaar_imphash_max,
        }
        response = make_request(query)
        if response['query_status'] == 'no_results':
            lis += '<li>There are no samples with matching imphash on Malware Bazaar</li>'
        else:
            inner = ''
            for sample in response['data']:
                link = f'https://bazaar.abuse.ch/sample{sample["sha256_hash"]}'
                inner += f'<li><a href="{link}">{sample["file_name"]}</a></li>'
            lis += f'''<li>These samples from Malware Bazaar had matching imphash:
                    <ul>
                        {inner}
                    </ul>
                   '''

    if config.malware_bazaar_tlsh:
        n += 1

        tlsh_ = cache.get('tlsh')
        if tlsh_ is None:
            tlsh_ = tlsh.hash(data)
            cache.set('tlsh', tlsh_)

        # XXX: Malware Bazaar errors out when it receives
        # TLSH with the version prefix (T1...), which is especially
        # strange, considering that they provide the TLSH _with_
        # the version prefix on the website.
        tlsh_ = tlsh_[2:]
        query = {
            'query': 'get_tlsh',
            'tlsh': tlsh_,
            'limit': config.malware_bazaar_tlsh_max,
        }
        response = make_request(query)
        if response['query_status'] == 'no_results':
            lis += '<li>There are no samples with matching TLSH on Malware Bazaar</li>'
        else:
            inner = ''
            for sample in response['data']:
                link = f'https://bazaar.abuse.ch/sample{sample["sha256_hash"]}'
                inner += f'<li><a href="{link}">{sample["file_name"]}</a></li>'
            lis += f'''<li>These samples from Malware Bazaar had matching TLSH:
                    <ul>
                        {inner}
                    </ul>
                   '''

    _hdr('Malware Bazaar')
    _ul(lis, n)


def _pe(data):
    try:
        pe = pefile.PE(data=data)
        pe.parse_data_directories()
        return pe
    except pefile.PEFormatError:
        raise malbook.Error('Sample is not a portable executable')


def _unzip(zip_path, config):
    with open(zip_path, 'rb') as f:
        data = f.read()

    sha256 = _csum(hashlib.sha256, data)
    zip_out = path.join(config.output_path, sha256)

    if path.exists(zip_out):
        # XXX: Got extracted previously
        return zip_out

    os.mkdir(zip_out)
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(zip_out, pwd=config.unzip_password)

    return zip_out


def _imports(pe, config, cache):
    imports = cache.get('imports')
    if imports is None:
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if hasattr(imp, 'name') and imp.name is not None:
                    name = imp.name.decode()
                    imports.append(name)
        cache.set('imports', imports)

    lis = []
    for imp in imports:
        quoted = urllib.parse.quote(imp)
        malapi_link = f'https://malapi.io/winapi/{quoted}'
        google_link = f'https://google.com/search?q={quoted}'

        if config.imports_malapi:
            cat = cache.get_common(imp)
            if cat is None:
                page = req.get(malapi_link)
                if not page.ok:
                    raise malbook.Error("Can't connect to MalAPI")
                soup = bs4.BeautifulSoup(page.content, 'html.parser')
                found = soup.find_all('span', class_='attack-container')
                if len(found) != 0:
                    cat = found[0].text.strip()
                else:
                    cat = 'none'
                cache.set_common(imp, cat)

            if cat == 'none':
                lis.append(f'<li>{_hesc(imp)} [<a href={_hesc(google_link)}>Google</a>]</li>')
            else:
                lis.append(f'<li>{_hesc(imp)} - <b>{_hesc(cat)}</b> [<a href={_hesc(google_link)}>Google</a>] [<a href={_hesc(malapi_link)}>MalAPI</a>]')

        else:
            # XXX: config.imports_malapi == False
            lis.append(f'<li>{_hesc(imp)} [<a href={_hesc(google_link)}>Google</a>]</li>')

    # HACK: If import was found on MalAPI, then make
    # sure it appears before the rest of the imports.
    def cmp_imports(i0, i1):
        ini0 = 'MalAPI' in i0
        ini1 = 'MalAPI' in i1
        if ini0 and ini1 and 'Helper' in i0:
            ini0 = False
        elif ini0 and ini1 and 'Helper' in i1:
            ini1 = False
        if ini0 and not ini1:
            return -1
        elif ini1 and not ini0:
            return 1
        else:
            return 0
    lis.sort(key=functools.cmp_to_key(cmp_imports))
    lis = ''.join(lis)

    _hdr('PE Imports')
    _ul(lis, len(imports))


def _peid(sample, config, cache):
    packer = cache.get('packer')
    if packer is None:
        try:
            packer = peid.identify_packer(sample)[0][1][0]
        except:
            packer = 'Could not detect packer/compiler'

        cache.set('packer', packer)

    _hdr('Packer/compiler detected by PEID')
    malbook.output(f'<p>{packer}</p>')


def _yara(data, config, cache):
    rules = os.listdir(config.yara_rules)

    if cache.get('yara') is None:
        cache.set('yara', [])

    matches = []
    for r in rules:
        if r in config.yara_ignore:
            continue
        if r in cache.get('yara'):
            matches.append(r)
        else:
            rule_path = path.join(config.yara_rules, r)
            with open(rule_path, 'rt') as f:
                src = f.read()
            rule = yara.compile(source=src)
            rms = rule.match(data=data)
            if len(rms) != 0:
                matches.append(r)
                cache.get('yara').append(r)

    lis = ''
    for m in matches:
        lis += f'<li>{_hesc(m)}</li>'

    _hdr('Matching Yara rules')
    _ul(lis, len(matches))


def _strings(sample, config, cache):
    strings = cache.get('strings')
    if strings is None:
        floss_exe = config.strings_floss
        out = sub.run(
            [floss_exe, '-n', str(config.strings_min_length), '-q', sample],
            capture_output=True,
        )
        if out.returncode != 0:
            raise malbook.Error('FLOSS returned non-zero exit code', out.stderr.decode())

        strings = out.stdout.decode().split('\n')
        cache.set('strings', strings)

    if config.strings_rank:
        ranked_strings = cache.get('ranked_strings')
        if ranked_strings is None:
            strs = '\n'.join(strings)
            ranked = sub.run(
                ['rank_strings'],
                capture_output=True, input=strs, encoding='utf-8'
            )
            if ranked.returncode != 0:
                raise malbook.Error('rank_strings returned non-zero exit code', ranked.stderr.decode())
            ranked_strings = ranked.stdout.split('\n')
            cache.set('ranked_strings', ranked_strings)
        strings = ranked_strings

    results = {}
    for s in strings:
        results[s] = []
        for name, rule in config.strings_regex_rules.items():
            if rule.match(s) is not None:
                results[s].append(name)

    # Format output
    lis = ''
    for s, rules in results.items():
        if len(rules) == 0:
            lis += f'<li>{_hesc(s)}</li>'
        else:
            lis += f'<li>{_hesc(s)}<ul>'
            for r in rules:
                lis += f'<li>{_hesc(r)}</li>'
            lis += '</ul></li>'

    _hdr('Strings')
    _ul(lis, len(results))


def _checksums(data, pe, config, cache):
    # XXX: The only hash that gets computed unconditionally
    # is SHA256, because we use it for cached result lookup
    sha256 = _csum(hashlib.sha256, data)
    cache.set_current_sample(sha256)
    cache.set('sha256', sha256)

    lis = ''
    for h in config.hashes:
        sum = ''

        # XXX: We support all hashlib algorithms, except for SHAKE_128
        # and SHAKE_256, since they require digest length.
        if hasattr(hashlib, h) and not h.startswith('shake'):
            sum = cache.get(h)
            if sum is None:
                alg = getattr(hashlib, h)
                sum = _csum(alg, data)

        elif h == 'imphash':
            sum = cache.get(h) or pe.get_imphash()
        elif h == 'spamsum':
            sum = cache.get(h) or spamsum.spamsum(data)
        elif h == 'tlsh':
            sum = cache.get(h) or tlsh.hash(data)
        else:
            if h == 'shake_128' or h == 'shake_256':
                raise malbook.Error('shake_128 and shake_256 are not supported')
            else:
                raise malbook.Error(f'Unknown hash algorithm {h}')

        cache.set(h, sum)

        lis += f'<li><b>{h}</b> - {sum}</li>'

    _hdr('Computed hashes')
    _ul(lis, len(config.hashes))


def _compare(data, config, cache):
    sample_ss = spamsum.spamsum(data)

    lis = ''
    n = 0

    if path.isdir(config.compare_to):
        root = config.compare_to
        for f in os.listdir(root):
            topath = path.join(root, f)
            with open(topath, 'rb') as fp:
                comp_data = fp.read()
            comp_ss = spamsum.spamsum(comp_data)
            match 

    lis = ''
    for f in config.compare_to:
        match = cache.get(f'compare-{f}')
        if match is None:
            with open(f, 'rb') as fp:
                comp_data = fp.read()
            h0 = spamsum.spamsum(data)
            h1 = spamsum.spamsum(comp_data)
            match = spamsum.match(h0, h1)
            cache.set(f'compare-{f}', match)
        lis += f'<li><b>{_hesc(f)}</b> - ({match}%)</li>'

    _hdr('Spamsum file similarity scores')
    _ul(lis, len(config.compare_to))


class VirtualBoxVM:

    def __init__(self, name, vboxmanage_path='vboxmanage', connection_attempts=30):
        self.vboxmanage_path = vboxmanage_path
        self.name = name
        self.connection_attempts = connection_attempts

        # Check vboxmanage
        try:
            self._cmd(['-v'])
        except:
            raise malbook.Error(f'{vboxmanage_path} does not exist. Is VirtualBox installed?')

        # Check VM config
        ok, out = self._cmd(['showvminfo', name, '--machinereadable'])
        if not ok:
            raise malbook.Error(f'Virtual machine "{name}" not found')
        for line in out.split('\n'):
            split = line.split('=')
            if len(split) != 2:
                continue
            key = split[0]
            val = split[1]
            if key == 'GuestOSType' and val != '"Windows10_64"':
                raise malbook.Error(f'OS "{val}" is not supported')

        # Get IP and set API address
        ok, out = self._cmd(['guestproperty', 'get', name, '/VirtualBox/GuestInfo/Net/0/V4/IP'])
        if not ok or not out.startswith('Value: '):
            raise malbook.Error('Virtual machine IPv4 not found')
        ip = out[len('Value: '):-1]
        api = 'http://' + ip + ':5000'
        self.api = api

        # run and try to connect
        self._cmd(['startvm', name, '--type', 'headless'])
        self._check_connection()

        # Take a base snapshot
        snapshot = ''.join(random.choice(string.ascii_letters) for _ in range(20))
        ok, err = self._cmd(['snapshot', name, 'take', snapshot])
        if not ok:
            raise malbook.Error(f'Cannot take snapshot: "{err}"')
        self.snapshot = snapshot

    def restore(self):
        ok, err = self._cmd(['controlvm', self.name, 'poweroff'])
        if not ok:
            raise malbook.Error(f'Cannot shutdown virtual machine: {err}')
        ok, err = self._cmd(['snapshot', self.name, 'restore', self.snapshot])
        if not ok:
            raise malbook.Error(f'Cannot restore snapshot: {err}')
        ok, err = self._cmd(['startvm', self.name, '--type', 'headless'])
        if not ok:
            raise malbook.Error(f'Cannot start the virtual machine: {err}')
        self._check_connection()

    def shutdown(self):
        self.restore()
        self._cmd(['snapshot', self.name, 'delete', self.snapshot])
        self._cmd(['controlvm', self.name, 'poweroff'])

    def _check_connection(self):
        resp = self._req('GET', '/status')
        if resp is None:
            raise malbook.Error(f'Cannot connect to virtual machine at {self.api}')
        elif resp.json()['status'] != 'ok':
            raise malbook.Error(f'Virtual machine error: {resp.json()["error"]}')

    def analyze(self, sample_bytes, sample_sha256, cache):
        request = {
            'sample': list(sample_bytes),
            'sha256': sample_sha256,
        }
        resp = self._req('POST', '/submit', request)
        if resp.json()['status'] != 'ok':
            raise malbook.Error(f'Cannot submit sample {sample_sha256} to the virtual machine.\n{resp.json()["error"]}')
        # TODO: This is the hardcoded guest timeout, but it doesn't have
        # to be.
        time.sleep(10)
        resp = self._req('GET', '/get_log', request)
        # XXX: This response is very large, since it contains the whole binary log.
        # De-serialize it once only.
        resp = resp.json()
        if resp['status'] != 'ok':
            raise malbook.Error(f'Error getting the log back from the virtual machine.\n{resp["error"]}')
        cache.set('procmon_log', resp['log'])
        cache.set('pid', resp['pid'])
        self.restore()

    def _req(self, method, endpoint, data=None) -> Optional[req.Response]:
        for _ in range(self.connection_attempts):
            try:
                resp = req.request(method, self.api + endpoint, json=data)
                return resp
            except Exception as e:
                print(e)
                time.sleep(1)
        return None

    def _cmd(self, cmd: List[str]) -> Tuple[bool, str]:
        full = [self.vboxmanage_path]
        full.extend(cmd)
        out = sub.run(full, capture_output=True)
        if out.returncode == 0:
            return True, out.stdout.decode('utf-8')
        else:
            return False, out.stderr.decode('utf-8')


def _vbox_procmon(data, config, cache, vm):
    events = cache.get('procmon_events')
    err = None
    n = 0
    if events is not None:
        n = cache.get('procmon_events_n')
    try:
        vm.analyze(data, cache.get('sha256'), cache)
        log = io.BytesIO(bytes(cache.get('procmon_log')))
        pid = cache.get('pid')
        reader = procmon_parser.ProcmonLogsReader(log)
        events = ''
        for event in reader:
            if event.process.pid == pid:
                events += f'<li>{_hesc(event.__str__())}</li>'
                n += 1
        cache.set('procmon_events', events)
        cache.set('procmon_events_n', n)
    except malbook.Error as e:
        err = f'Virtual machine error: {e}'
    except procmon_parser.PMLError:
        err = 'Procmon log file is corrupt'

    _hdr('Procmon events')
    if err is not None:
        _ul(f'<li>{err}</li>', 1)
    else:
        _ul(events, n)

# XXX Helpers


# Computes the checksum and returns the digest. Algorithm
# must be an instance of _hashlib.HASH
def _csum(algorithm, data):
    h = algorithm()
    h.update(data)
    return h.hexdigest()


# XXX: Output helpers


# Escapes HTML sequences in text
def _hesc(text):
    return html.escape(text)


# Outputs an HTML header
def _hdr(text, h=3):
    malbook.output(f'<b><hr /></b><h{h}>{text}:</h{h}>')


# Outputs an HTML list, hiding contents if there are more than
# hide number of elements
def _ul(lis, n, hide=10):
    if n == 0:
        malbook.output('<p><b>NONE</b></p>')
    elif n <= hide:
        malbook.output(f'<p><ul>{lis}</ul></p>')
    else:
        malbook.output(f'''
        <p>
            <details>
                <summary>
                    Click here to show all <b>{n}</b>
                </summary>
                <ul>
                    {lis}
                </ul>
            </details>
        </p>
        ''')

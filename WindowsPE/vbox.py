import subprocess as sub
import string
import random
from typing import List, Tuple
import requests as req
import time

import malbook


# XXX: Run command and return ($? == 0, stdout/stderr)
def _cmd(cmd: List[str]) -> Tuple[bool, str]:
    out = sub.run(cmd, capture_output=True)
    if out.returncode != 0:
        return False, out.stderr.decode('utf-8')
    else:
        return True, out.stdout.decode('utf-8')


class VirtualBoxVM:

    def __init__(self, name):
        self.name = name

        # XXX: Check if vboxmanage is accessible
        ok, _ = _cmd(['vboxmanage', '-v'])
        if not ok:
            raise malbook.Error('vboxmanage not found. Is VirtualBox installed?')

        # XXX: Check guest OS type
        ok, out = _cmd(['vboxmanage', 'showvminfo', name, '--machinereadable'])
        if not ok:
            raise malbook.Error(f'Virtual machine {name} not found')
        for line in out.split('\n'):
            split = line.split('=')
            if len(split) != 2:
                continue
            key = split[0]
            val = split[1]
            if key == 'GuestOSType' and val != 'Windows10_64':
                raise malbook.Error(f'Guest OS {val} is not supported')

        # XXX: Get VM IPv4
        ok, out = _cmd(['vboxmanage', 'guestproperty', 'get', name, '/VirtualBox/GuestInfo/Net/0/V4/IP'])
        if not ok or not out.startswith('Value: '):
            raise malbook.Error('Virtual machine IPv4 not found')
        ip = out[len('Value: '):-1]
        api = 'http://' + ip + ':5000/'
        self.api = api

        # XXX: Try to connect to the virtual machine guest server
        _cmd(['vboxmanage', 'controlvm', name, 'poweroff'])
        ok, _ = _cmd(['vboxmanage', 'startvm', name, '--type', 'headless'])
        if not ok:
            raise malbook.Error(f'Cannot start virtual machine {name}')
        guest_ok = False
        for _ in range(5):
            try:
                status = req.get(api + '/status')
                if status.json()['status'] == 'ok':
                    guest_ok = True
            except:
                # Otherwise the VM is still starting. Wait
                time.sleep(5)
        if not guest_ok:
            self.shutdown()
            raise malbook.Error('Cannot connect to the virtual machine.')

        # XXX: Everything seems fine. Generate the base snapshot to fall back
        # to.
        snapshot = ''.join(random.choice(string.ascii_letters) for _ in range(20))
        ok, _ = _cmd(['vboxmanage', 'snapshot', name, 'take', snapshot])
        if not ok:
            self.shutdown()
            raise malbook.Error(f'Cannot take snapshot of {name}')
        self.snapshot = snapshot

    def shutdown(self):
        if hasattr(self, 'snapshot'):
            _cmd(['vboxmanage', 'snapshot', self.name, 'delete', self.snapshot])
        _cmd(['vboxmanage', 'controlvm', self.name, 'poweroff'])


    # TODO: I just realized that we never get the PID back. This is necessary to filter out
    # logs
    def generate_procmon_log(self, sample_data: bytes, sample_sha256: str, log_path: str, retries: int = 5):
        request = {
            'sample': list(sample_data),
            'sha256': sample_sha256,
        }
        resp = req.post(self.api + '/submit', json=request)
        if not resp.ok or resp.json()['status'] == 'error':
            raise malbook.Error('Cannot send file to Virtual Machine for analysis')
        time.sleep(10)

        result = None
        for _ in range(retries):
            resp = req.get(self.api + '/get_log' , json={'sha256': sample_sha256})
            if not resp.ok or resp['status'] == 'error':
                time.sleep(5)
            else:
                result = resp.json()['log']
                break
        if result is None:
            raise malbook.Error(f'Cannot get results from the Virtual machine')

        with open(log_path, 'wb') as f:
            f.write(bytes(result))

        # XXX: Restore the pre-analysis snapshot
        ok, _ = _cmd(['vboxmanage', 'snapshot', self.name, 'restore', self.snapshot])
        if not ok:
            raise malbook.Error(f'Cannot restore snapshot {self.snapshot}')

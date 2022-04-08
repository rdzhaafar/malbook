import platform
from flask import Flask, request
import os
import sys
from os import path
import json
from multiprocessing import Process, Lock
import time
import subprocess as sub
import ctypes


HOME = path.expanduser('~')
PROCMON = path.join(HOME, 'Procmon64.exe')
SAMPLES = path.join(HOME, 'Samples')
LOGS = path.join(HOME, 'ProcmonLogs')
FATAL_ERROR = None
TIMEOUT = 10

# XXX: Perform pre-flight checks
if platform.system() != 'Windows':
    FATAL_ERROR = f'{sys.argv[0]} must be run from Windows'
elif not path.exists(PROCMON):
    FATAL_ERROR = f'Procmon executable not found in {PROCMON}'
elif not path.exists(SAMPLES) or not path.isdir(SAMPLES):
    FATAL_ERROR = f'Samples directory not found in {SAMPLES}'
elif not path.exists(LOGS) or not path.isdir(LOGS):
    FATAL_ERROR = f'Logs directory not found in {LOGS}'
elif ctypes.windll.shell32.IsUserAnAdmin() == 0:
    FATAL_ERROR = f'{sys.argv[0]} must be run as admin'
# XXX: The analysis and the web server run in 2 separate processes to avoid
# blocking on long timeouts.
LOGS_LOCK = Lock()

app = Flask(__name__)


def json_reply_ok(reply = {}):
    reply['status'] = 'ok'
    return json.dumps(reply)


def json_reply_error(err, reply = {}):
    reply['status'] = 'error'
    reply['error'] = err
    return json.dumps(reply)


def generate_log(sample_path, log_path):
    # NOTE: Procmon is a stupid, buggy, inconsistent piece of shit
    # utility maintained by the largest, richest software company in 
    # the world.

    # XXX: Create lockfile
    lockfile = log_path + '.lock'
    with open(lockfile, 'wt') as f:
        f.write('LOCKED')

    # XXX: Begin the stupid Procmon dance
    sub.Popen([PROCMON, '/AcceptEula', '/Terminate'])
    time.sleep(1)
    sub.Popen([PROCMON, '/AcceptEula', '/Minimized', '/Quiet', '/BackingFile', log_path])
    sample_proc = sub.Popen([sample_path])
    time.sleep(TIMEOUT)
    sample_proc.kill()
    time.sleep(1)
    sub.Popen([PROCMON, '/AcceptEula', '/Terminate'])
    time.sleep(1)

    # XXX: Unlock log after Procmon terminates to avoid corruption
    os.remove(lockfile)


@app.route('/status')
def status():
    if FATAL_ERROR is None:
        return json_reply_ok()
    else:
        return json_reply_error(FATAL_ERROR)


@app.route('/submit', methods=['POST'])
def submit():
    if FATAL_ERROR is not None:
        return json_reply_error(FATAL_ERROR)

    req = request.get_json()
    sample = req['sample']
    sha256 = req['sha256']
    # XXX: This is needed mostly for development, but 
    # a good security practice nonetheless. A relative path
    # may arrive from a non-Windows machine confusing the hell
    # out of our poor server
    sample_path = path.join(SAMPLES, sha256)
    if path.exists(sample_path):
        return json_reply_error(f'sample {sha256} has already been submitted')
    with open(sample_path, 'wb') as f:
        f.write(bytes(sample))

    log_path = path.join(LOGS, sha256)

    # XXX: Run analysis in a separate process
    log_gen = Process(target=generate_log, args=(sample_path, log_path))
    log_gen.run()

    return json_reply_ok()


@app.route('/get_log')
def get_log():
    if FATAL_ERROR is not None:
        return json_reply_error(FATAL_ERROR)

    req = request.get_json()
    sha256 = req['sha256']
    log_path = path.join(LOGS, sha256 + '.PML')
    log_lock = path.join(LOGS, sha256) + '.lock'

    if path.exists(log_lock):
        return json_reply_error('busy...')
    if not path.exists(log_path):
        return json_reply_error('no such sample!')

    # Otherwise, send the log
    with open(log_path, 'rb') as f:
        log_bytes = list(f.read())

    return json_reply_ok({'log': log_bytes})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
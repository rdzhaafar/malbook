from pathlib import Path
from os import path
import os
import sys
import subprocess as subp
import venv
from tempfile import TemporaryDirectory
import shutil

from .errors import *


_BASE_PACKAGES = []
# XXX: This is necessary for testing dev builds only.
# `test.sh` script exports `MALBOOK_WHEEL_PATH`, which is set
# to the freshly built malbook wheel path. This way, we install
# the local wheel package instead of going to PyPi.
_BASE_PACKAGES.append(os.getenv('MALBOOK_WHEEL_PATH', 'malbook'))


def check_compat() -> None:
    # XXX: Check Python version
    major = sys.version_info.major
    minor = sys.version_info.minor
    if major < 3 or minor < 9:
        raise Error(f'Python 3.9 or newer is required to run malbook')

    # Check OS type
    os_name = os.name
    if os_name != 'posix' and os_name != 'nt':
        raise Error(f"Operating system '{os_name}' is not supported")

    # There is not much that we expect on Linux/macOS, other
    # than a shell
    if os_name != 'nt':
        return

    # On Windows we need to make sure that ExecutionPolicy is set to
    # either AllSigned or Unrestricted to ensure that we can activate the
    # virtual environment later
    out = subp.run(['powershell', 'Get-ExecutionPolicy'], capture_output=True)
    execpolicy = out.stdout

    if execpolicy not in [b'AllSigned\r\n', b'Unrestricted\r\n']:
        raise Error(
            f"You need to set execution policy to either 'AllSigned'\n"
            "or 'Unrestricted' before proceeding. For more information\n"
            "about PowerShell execution policy visit\n"
            "https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy")


class Environment:

    root: Path
    virtualenv: Path
    virtualenv_activate: str
    packages_file: Path
    os_name: str

    def __init__(self, root: Path = '.'):
        # Don't bother loading if environment is not supported
        check_compat()

        canonical = path.realpath(root)
        self.root = canonical
        dot_dir = path.join(canonical, '.malbook')

        if not path.isdir(dot_dir):
            raise Error(f"No malbook found in {canonical}")

        self.virtualenv = path.join(dot_dir, 'virtualenv')
        self.packages_file = path.join(dot_dir, 'pip.packages')
        self.os_name = os.name

        # XXX: MacOS, Linux
        if self.is_posix():
            virtualenv_script = path.join(self.virtualenv, 'bin', 'activate')
            self.virtualenv_activate = f'source {virtualenv_script}; '
        # XXX: Windows
        else:
            virtualenv_script = path.join(
                self.virtualenv, 'Scripts', 'Activate.ps1')
            self.virtualenv_activate = f'{virtualenv_script}; '

    def is_posix(self) -> bool:
        return self.os_name == 'posix'

    def is_windows(self) -> bool:
        return self.os_name == 'nt'

    # XXX: The internal version captures and returns process output, whilst the
    # public version redirects STDOUT/STDERR to their respective fds.
    def _run_command_in_venv(self, cmd) -> subp.CompletedProcess[bytes]:
        virtualenv_cmd = self.virtualenv_activate + cmd
        if self.is_posix():
            # XXX: MacOS, Linux
            out = subp.run(['sh', '-c', virtualenv_cmd],
                           check=False, capture_output=True)
        else:
            # XXX: Windows
            out = subp.run(['powershell', virtualenv_cmd],
                           check=False, capture_output=True)
        return out

    # XXX: See the note for the internal version
    def run_command_in_venv(self, cmd: str):
        virtualenv_cmd = self.virtualenv_activate + cmd

        if self.is_posix():
            # XXX: MacOS, Linux
            _ = subp.run(['sh', '-c', virtualenv_cmd])
        else:
            # XXX: Windows
            _ = subp.run(['powershell', virtualenv_cmd])

    def _wrap_cmd(self, cmd):
        out = self._run_command_in_venv(cmd)
        code = out.returncode
        if code != 0:
            raise CommandError(
                f"Command failed with return code {code}",
                out.stderr.decode('utf-8')
            )

    def _dump_package_list(self):
        cmd = f"pip freeze > {self.packages_file}"
        self._wrap_cmd(cmd)

    def list_installed_pip_packages(self) -> str:
        cmd = 'pip freeze'
        out = self._run_command_in_venv(cmd)

        code = out.returncode

        if code != 0:
            raise CommandError(
                f'Command failed with return code {code}', out.stderr.decode('utf-8'))

        return out.stdout.decode('utf-8')

    def _install_pip_package(self, package, installing_requirements=False):
        if package in _BASE_PACKAGES and not installing_requirements:
            raise Error(f"Base package {package} is already installed")

        cmd = f"pip install {package}"
        self._wrap_cmd(cmd)
        self._dump_package_list()

    def package_is_installed(self, package: str) -> bool:
        with open(self.packages_file, 'rt') as f:
            packages = f.read()
        for p in packages:
            if package in p:
                return True
        return False

    def install_pip_package(self, package: str) -> None:
        self._install_pip_package(package)

    def remove_pip_package(self, package: str) -> None:
        if package in _BASE_PACKAGES:
            raise Error(f"Can't remove base package {package}")

        cmd = f"pip uninstall -y {package}"
        self._wrap_cmd(cmd)
        self._dump_package_list()

    def dump_as_template(self, where: Path) -> None:
        canonical = path.realpath(where)

        if not canonical.endswith('.zip'):
            raise Error(f"Template name must end in '.zip'")

        if path.exists(canonical):
            raise Error(f"File {canonical} already exists")

        ignore_file = path.join(self.root, '.ignore')

        # XXX: Ignore the malbook hidden folder by default
        ignore = ['.malbook']
        if path.exists(ignore_file):
            with open(ignore_file, 'rt') as f:
                text = f.read()
                for i in text.split('\n'):
                    ignore.append(i)

        # XXX: Strip the '.zip' ending, because shutil.make_archive
        # adds it automatically.
        canonical = canonical[:-4]

        with TemporaryDirectory() as td:
            packages = path.join(td, 'pip.packages')
            shutil.copy2(self.packages_file, packages)

            root = path.join(td, 'files')
            os.mkdir(root)

            for dirent in os.listdir(self.root):
                # XXX: Check if entry should be ignored
                if dirent in ignore:
                    continue

                src = path.join(self.root, dirent)
                dst = path.join(root, dirent)

                if path.isdir(dirent):
                    shutil.copytree(src, dst, symlinks=False)
                elif path.isfile(dirent):
                    shutil.copy2(src, dst, follow_symlinks=False)

            shutil.make_archive(canonical, 'zip', td)

    def run_jupyter_notebook(self) -> None:
        cmd = self.virtualenv_activate + 'jupyter notebook'
        os.chdir(self.root)
        if self.is_posix():
            subp.Popen(['sh', '-c', cmd],
                       stdout=subp.DEVNULL, stderr=subp.DEVNULL)
        else:
            subp.Popen(['powershell', cmd],
                       stdout=subp.DEVNULL, stderr=subp.DEVNULL)

    def stop_jupyter_notebook(self) -> None:
        cmd = self.virtualenv_activate + 'jupyter notebook stop'
        os.chdir(self.root)
        if self.is_posix():
            subp.Popen(['sh', '-c', cmd],
                       stdout=subp.DEVNULL, stderr=subp.DEVNULL)
        else:
            subp.Popen(['powershell', cmd],
                       stdout=subp.DEVNULL, stderr=subp.DEVNULL)


def make_environment(root: Path = '.') -> Environment:
    # XXX: Don't bother creating a malbook in an uncompatible environment
    check_compat()

    canonical = path.realpath(root)
    if path.exists(canonical) and not path.isdir(canonical):
        raise Error(f"Can't create malbook in {canonical}: not a directory")

    if not path.exists(canonical):
        os.makedirs(canonical, exist_ok=True)

    dot_dir = path.join(canonical, '.malbook')
    if path.exists(dot_dir):
        raise Error(f"{canonical} already contains a malbook")

    # Create the hidden malbook directory
    os_name = os.name
    os.mkdir(dot_dir)
    if os_name == 'nt':
        # Make sure the directory is hidden on Windows too
        proc = subp.Popen(["attrib", "+H", dot_dir],
                          stdout=subp.DEVNULL, stderr=subp.DEVNULL)
        proc.communicate()

    # Create the virtual environment
    virtualenv = path.join(dot_dir, 'virtualenv')
    venv.create(virtualenv, with_pip=True)

    # Load the freshly created environment
    env = Environment(canonical)

    # Install the base packages
    for package in _BASE_PACKAGES:
        env._install_pip_package(package, installing_requirements=True)

    return env


def load_from_template(template: Path, where: Path) -> Environment:
    canonical_template = path.realpath(template)
    if not path.exists(canonical_template):
        raise Error(f"Can't find {canonical_template}")

    canonical_where = path.realpath(where)
    if path.exists(canonical_where):
        raise Error(f"{canonical_where} already exists")

    os.mkdir(canonical_where)
    env = make_environment(canonical_where)

    try:
        with TemporaryDirectory() as td:
            extracted = path.join(td, 'extracted')
            shutil.unpack_archive(canonical_template, extracted, 'zip')

            files = path.join(extracted, 'files')
            shutil.copytree(files, canonical_where,
                            symlinks=False, dirs_exist_ok=True)

            packages = path.join(extracted, 'pip.packages')
            env._wrap_cmd(f"pip install -r {packages}")

    except Exception as _:
        shutil.rmtree(where)
        raise Error(f"Couldn't load template {template}")

    return env

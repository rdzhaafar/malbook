from argparse import ArgumentParser
import os
from os import path, PathLike
from pathlib import Path
import subprocess as subp
from typing import Callable, Any
import sys
import venv
import shutil
import tempfile as temp

from . import __version__


_DOT_DIR = '.malbook'
_BASE_PACKAGES = ['jupyter', 'malbook']
_DEBUG = False


class _Error(BaseException):
    _message: str

    def __init__(self, message: str):
        self._message = message

    def __str__(self) -> str:
        return self._message


class _CommandError(_Error):
    _output: str

    def __init__(self, message: str, output: str):
        super().__init__(message)
        self._output = output

    def __str__(self) -> str:
        return f'{self._message}\noutput:\n{self._output}'


def _check_compat() -> None:
    # Check python version
    major = sys.version_info.major
    minor = sys.version_info.minor
    if major < 3 or minor < 9:
        raise _Error(f'Python 3.9 or newer is required')

    # Check OS
    os_name = os.name
    if os_name != 'posix' and os_name != 'nt':
        raise _Error(f'Operating system `{os_name}` is not supported')

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
        raise _Error(
            f"You need to set execution policy to either 'AllSigned'\n"
            "or 'Unrestricted' before proceeding. For more information\n"
            "about PowerShell execution policy visit\n"
            "https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy")


class _Environment:
    root: PathLike
    virtualenv: PathLike
    root: PathLike
    virtualenv: PathLike
    virtualenv_activate: str
    packages: PathLike
    osname: str

    def is_posix(self) -> bool:
        return self.osname == 'posix'

    def is_windows(self) -> bool:
        return self.osname == 'nt'


def _load(root: PathLike = '.') -> _Environment:
    canonical = path.realpath(root)
    dot_dir = path.join(canonical, _DOT_DIR)

    if not path.isdir(dot_dir):
        raise _Error(f"Couldn't find a notebook in {canonical}")

    virtualenv = path.join(dot_dir, 'virtualenv')
    packages = path.join(dot_dir, 'pip.packages')
    osname = os.name

    # MacOS, Linux
    if osname == 'posix':
        virtualenv_script = path.join(virtualenv, 'bin', 'activate')
        virtualenv_activate = f'source {virtualenv_script}; '

    # Windows
    elif osname == 'nt':
        virtualenv_script = path.join(virtualenv, 'Scripts', 'Activate.ps1')
        # Virtualenv script path must start with '.\' if the path to it
        # is relative, since it must be invoked as standalone script on
        # Windows.
        if path.isabs(virtualenv_script):
            virtualenv_activate = f'{virtualenv_script}; '
        else:
            virtualenv_activate = f'.\\{virtualenv_script}; '

    # Some other os
    else:
        # XXX: Unreachable
        pass

    env = _Environment()
    env.root = root
    env.virtualenv = virtualenv
    env.virtualenv_activate = virtualenv_activate
    env.packages = packages
    env.osname = osname

    return env


def _run_in(env: _Environment, cmd: str) -> subp.CompletedProcess[bytes]:
    virtualenv_cmd = env.virtualenv_activate + cmd
    if env.is_posix():
        out = subp.run(['sh', '-c', virtualenv_cmd],
                       check=False, capture_output=True)
    elif env.is_windows():
        out = subp.run(['powershell', virtualenv_cmd],
                       check=False, capture_output=True)

    return out


def _wrap_pip(env: _Environment, cmd: str) -> None:
    out = _run_in(env, cmd)

    if out.returncode != 0:
        raise _CommandError(
            f'An error occurred while running pip', out.stderr.decode('utf-8'))


def _dump_pip_packages(env: _Environment) -> None:
    cmd = f'pip freeze > {env.packages}'
    _wrap_pip(env, cmd)


def _install_pip_package(env: _Environment, package: str, installing_requirements: bool = False) -> None:
    # XXX: The only time we're allowed to install base packages is
    # when we're creating a new environment.
    if package in _BASE_PACKAGES and not installing_requirements:
        raise _Error(f'Base package {package} is already installed')

    cmd = f'pip install {package}'
    _wrap_pip(env, cmd)
    _dump_pip_packages(env)


def _remove_pip_package(env: _Environment, package: str) -> None:
    if package in _BASE_PACKAGES:
        raise _Error(f"Can't remove base package {package}")

    cmd = f'pip uninstall -y {package}'
    _wrap_pip(env, cmd)
    _dump_pip_packages(env)


def _new(root: PathLike = '.') -> None:
    canonical = path.realpath(root)

    if not path.isdir(canonical):
        raise _Error(f'{canonical} is not a directory')

    dot_dir = path.join(canonical, _DOT_DIR)
    if path.exists(dot_dir):
        raise _Error(f'Cannot create another notebook in {canonical}')

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
    env = _load(canonical)

    # Install the base packages
    for package in _BASE_PACKAGES:
        _install_pip_package(env, package, installing_requirements=True)


def _run(env: _Environment) -> None:
    cmd = env.virtualenv_activate + 'jupyter notebook'

    # XXX: Change the current directory to `root` in case
    # -d option was used
    os.chdir(env.root)

    if env.is_posix():
        subp.Popen(['sh', '-c', cmd], stdout=subp.DEVNULL, stderr=subp.DEVNULL)
    elif env.is_windows():
        subp.Popen(['powershell', cmd],
                   stdout=subp.DEVNULL, stderr=subp.DEVNULL)


def _stop(env: _Environment) -> None:
    cmd = env.virtualenv_activate + 'jupyter notebook stop'

    if env.is_posix():
        subp.Popen(['sh', '-c', cmd], stdout=subp.DEVNULL, stderr=subp.DEVNULL)
    elif env.is_windows():
        subp.Popen(['powershell', cmd],
                   stdout=subp.DEVNULL, stderr=subp.DEVNULL)


def _dump_template(env: _Environment, where: PathLike = 'malbook') -> None:
    canonical = path.realpath(where)

    if path.exists(canonical + '.zip'):
        raise _Error(f'File {where}.zip already exists')

    with temp.TemporaryDirectory() as td:
        # Copy the pip packages list
        packages = path.join(td, 'pip.packages')
        shutil.copy2(env.packages, packages)

        # Copy the rest of the files
        root = path.join(td, 'files')
        os.mkdir(root)
        for dirent in os.listdir(env.root):
            # XXX: Skip the virtual environment
            if dirent == _DOT_DIR:
                continue

            src = path.join(env.root, dirent)
            dst = path.join(root, dirent)

            if path.isdir(dirent):
                shutil.copytree(src, dst, symlinks=False)
            elif path.isfile(dirent):
                shutil.copy2(src, dst, follow_symlinks=False)

        # Zip all the files
        shutil.make_archive(canonical, 'zip', td)


def _load_template(where: PathLike, template: PathLike = 'malbook.zip') -> None:
    if not path.exists(template):
        raise _Error(f"Couldn't find template '{template}'")

    if path.exists(where):
        raise _Error(f"{where} already exists")

    # First, create a new malbook notebook
    os.mkdir(where)
    _new(where)
    env = _load(where)

    # Then, try to load the template normally. If anything goes wrong here,
    # assume that it's because the template is not valid.
    try:
        with temp.TemporaryDirectory() as td:
            extracted = path.join(td, 'extracted.template')
            shutil.unpack_archive(template, extracted, 'zip')

            files = path.join(extracted, 'files')
            # XXX: There shouldn't be any symlinks at this point, but
            # ignore them just in case
            shutil.copytree(files, where, symlinks=False, dirs_exist_ok=True)

            # Install all the requirements
            packages = path.join(extracted, 'packages.pip')
            _run_in(env, f'pip install -r {packages}')

    except Exception as _:
        # TODO: `Exception as _` is only necessary for debugging.
        shutil.rmtree(where)
        raise _Error(f"{template} is not a valid malbook template")


def _wrap(func: Callable[..., Any], *args) -> Any:
    try:
        return func(*args)
    except _Error as e:
        print(f'error: {e}')
        sys.exit(1)
    except Exception as e:
        print(f'internal error: {e}')
        # XXX: It's worth it to get full traceback for unexpected
        # internal errors
        if _DEBUG:
            import traceback
            print('Traceback:')
            print(traceback.format_exc())
        sys.exit(2)


def _main() -> None:
    # XXX: Don't bother going any further if environment is
    # incompatible
    _wrap(_check_compat)

    # XXX: Main parser and global options
    parser = ArgumentParser(description='manage malbook notebooks')
    parser.add_argument(
        '-n', '--notebook',
        type=Path,
        default='.',
        metavar='PATH',
        help='run as if malbook was started in <PATH> instead of the current working directory'
    )
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='enable debugging output'
    )
    commands = parser.add_subparsers(
        help='command',
        dest='command',
        metavar='COMMAND',
        required=True
    )

    # XXX: New
    command_new = commands.add_parser(
        'new',
        help='create a new notebook'
    )
    command_new.add_argument(
        '-d', '--directory',
        type=Path,
        default='.',
        metavar='PATH',
        help="create the notebook in <PATH>, creating <PATH> if it doesn't exist"
    )

    # XXX: Template subcommands
    command_template = commands.add_parser(
        'template',
        help='manage malbook templates',
    )
    template_commands = command_template.add_subparsers(
        dest='template_command',
        help='template command',
        metavar='COMMAND',
        required=True
    )

    # XXX: Template create
    command_template_create = template_commands.add_parser(
        'create',
        help='create a new template',
    )
    command_template_create.add_argument(
        'file',
        type=Path,
        metavar='FILE',
        help='save template to <FILE>'
    )

    # XXX: Template load
    command_template_load = template_commands.add_parser(
        'load',
        help='load a notebook from a template'
    )
    command_template_load.add_argument(
        'file',
        type=Path,
        metavar='FILE',
        help='template file to load the notebook from'
    )
    command_template_load.add_argument(
        'where',
        type=Path,
        metavar='PATH',
        help='create notebook in <PATH>'
    )

    # XXX: Run
    command_run = commands.add_parser(
        'run',
        help='run jupyter notebook'
    )

    # XXX: Stop
    command_stop = commands.add_parser(
        'stop',
        help='stop jupyter notebook'
    )

    # XXX: Install
    command_install = commands.add_parser(
        'install',
        help='install a Python package to the notebook virtual environment'
    )
    command_install.add_argument(
        'packages',
        type=str,
        nargs='*',
        metavar='PACKAGES',
        help='packages to install'
    )

    # XXX: Remove
    command_remove = commands.add_parser(
        'remove',
        help='uninstall a Python package from the notebook virtual environment'
    )

    # XXX: Version
    command_version = commands.add_parser(
        'version',
        help='print version string and exit'
    )

    # XXX: Parse args
    args = parser.parse_args()
    if args.debug:
        _DEBUG = True

    # XXX: Dispatch command
    if args.command == 'new':
        os.makedirs(args.directory, exist_ok=True)
        _wrap(_new, args.directory)

    elif args.command == 'template':
        if args.template_command == 'create':
            env = _wrap(_load, args.notebook)
            _wrap(_dump_template, env, args.file)

        elif args.template_command == 'load':
            _wrap(_load_template, args.where, args.file)

    elif args.command == 'run':
        env = _wrap(_load, args.notebook)
        _wrap(_run, env)

    elif args.command == 'stop':
        env = _wrap(_load, args.notebook)
        _wrap(_stop, env)

    elif args.command == 'install':
        env = _wrap(_load, args.notebook)
        for package in args.packages:
            _wrap(_install_pip_package, env, package)

    elif args.command == 'remove':
        env = _wrap(_load, args.notebook)
        for package in args.packages:
            _wrap(_remove_pip_package, env, package)

    elif args.command == 'version':
        print(f'malbook {__version__}')


# XXX: Entry point
if __name__ == '__main__':
    _main()

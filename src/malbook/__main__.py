import os
from os import path, PathLike
import subprocess as subp
from typing import Callable, Any, NoReturn
import sys
import venv
import shutil
import tempfile as temp


_DOT_DIR = '.malbook'
_BASE_PACKAGES = ['jupyter', 'malbook']


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
        print('Traceback:')

        # TODO: This is for debugging only, remove
        import traceback
        print(traceback.format_exc())

        sys.exit(2)


def _usage(exit: int) -> NoReturn:
    print(
        f'usage: [global options] {sys.argv[0]} <command> [command options]\n\n'
        'global options:\n'
        '   -d/--dir                               specify malbook directory\n\n'
        'commands:\n'
        '   new [directory]                        creates a new empty notebook in `directory`.\n'
        '                                          `directory` defaults to `.`\n'
        '   dump-template [template-file]          creates a template from the current notebook\n'
        '                                          `template-file` defaults to malbook.zip\n'
        '   load-template <where> [template-file]  loads a notebook from a template\n'
        '                                          `template-file` defaults to malbook.zip,\n'
        '   run                                    runs the notebook\n'
        '   stop                                   stops the running notebook\n'
        '   install <packages...>                  installs Python package(s) to notebook virtual environment\n'
        '   remove <packages...>                   removes Python package(s) from notebook virtual environment\n'
        '   help                                   print this help message\n'
    )
    sys.exit(exit)


def _args_error(err: str) -> NoReturn:
    print(f'error: {err}')
    _usage(1)


def _main() -> None:
    # XXX: Don't bother going any further if environment is
    # incompatible
    _wrap(_check_compat)

    # XXX: Parse command-line arguments
    args = sys.argv[1:]

    # Parse optional `-d/--dir` option
    root = '.'
    explicit_root = False
    if len(args) > 0 and (args[0] == '--dir' or args[0] == '-d'):
        if len(args) < 2:
            _args_error('-d requires a positional `dir` argument')
        root = args[1]
        args = args[2:]
        explicit_root = True

    if len(args) == 0:
        _args_error('No command supplied')

    cmd = args[0]
    args = args[1:]

    # XXX: Dispatch command
    if cmd == 'new':
        if explicit_root:
            _args_error(f'-d/--dir option is ignored by `{cmd}`')

        if len(args) == 0:
            _wrap(_new)
        elif len(args) == 1:
            # XXX: The directory must be created in case it doesn't
            # already exist
            root = args[0]
            os.makedirs(root, exist_ok=True)
            _wrap(_new, args[0])
        else:
            _args_error('Invalid usage')

    elif cmd == 'dump-template':
        env = _wrap(_load, root)
        if len(args) == 0:
            _wrap(_dump_template, env)
        elif len(args) == 1:
            _wrap(_dump_template, env, args[0])
        else:
            _args_error('Invalid usage')

    elif cmd == 'load-template':
        if explicit_root:
            _args_error(f'-d/--dir option is ignored by `{cmd}`')
        if len(args) == 1:
            _wrap(_load_template, args[0])
        elif len(args) == 2:
            _wrap(_load_template, args[0], args[1])
        else:
            _args_error(f'Invalid options for `{cmd}`')

    elif cmd == 'run' and len(args) == 0:
        env = _wrap(_load, root)
        _wrap(_run, env)

    elif cmd == 'stop' and len(args) == 0:
        env = _wrap(_load, root)
        _wrap(_stop, env)

    elif cmd == 'install':
        env = _wrap(_load, root)

        if len(args) == 0:
            _args_error('No packages specified')

        for package in args:
            print(f'installing {package}...')
            _wrap(_install_pip_package, env, package)

    elif cmd == 'remove':
        env = _wrap(_load, root)

        if len(args) == 0:
            _args_error('No packages specified')

        for package in args:
            print(f'removing {package}...')
            _wrap(_remove_pip_package, env, package)

    elif cmd == 'help' and len(args) == 0:
        if explicit_root:
            _args_error(f'-d/--dir option is ignored by `{cmd}`')
        _usage(0)

    else:
        if cmd in ['new', 'dump-template', 'load-template', 'run', 'stop', 'install', 'remove', 'help']:
            _args_error(f'Invalid options for `{cmd}`')
        else:
            _args_error(f'unknown command {cmd}')


# XXX: Entry point
_main()

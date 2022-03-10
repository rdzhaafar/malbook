from argparse import ArgumentParser
from pathlib import Path
import sys
from typing import Callable, Any
import os

from . import __version__
from .environment import *
from .errors import *


def _wrap(func: Callable[..., Any], *args, **kwargs) -> Any:
    try:
        return func(*args, **kwargs)
    except Error as e:
        print(f"error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"error: internal: {e}")
        sys.exit(2)


def _main() -> None:
    # XXX: Don't bother going any further if environment is
    # incompatible
    _wrap(check_compat)

    # XXX: Main parser and global options
    parser = ArgumentParser(description='manage malbook notebooks')
    parser.add_argument(
        '-n', '--notebook',
        type=Path,
        default='.',
        metavar='PATH',
        help='run as if malbook was started in <PATH> instead of the current working directory'
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

    # Package commands
    command_package = commands.add_parser(
        'package',
        help='manage pip packages'
    )
    package_commands = command_package.add_subparsers(
        dest='package_command',
        help='package command',
        metavar='COMMAND',
        required=True
    )

    # Package install
    command_package_install = package_commands.add_parser(
        'install',
        help='install a pip package'
    )
    command_package_install.add_argument(
        'packages',
        type=str,
        nargs='*',
        metavar='PACKAGES',
        help='pip packages'
    )

    # Package remove
    command_package_remove = package_commands.add_parser(
        'remove',
        help='remove a pip package'
    )
    command_package_remove.add_argument(
        'packages',
        type=str,
        nargs='*',
        metavar='PACKAGES',
        help='pip packages'
    )

    # Package list
    command_package_list = package_commands.add_parser(
        'list',
        help='list installed pip packages'
    )

    # XXX: Version
    command_version = commands.add_parser(
        'version',
        help='print version string and exit'
    )

    # XXX: Cmd
    command_cmd = commands.add_parser(
        'cmd',
        help='run a command inside malbook virtual environment'
    )
    command_cmd.add_argument(
        'cmd_command',
        metavar='CMD',
        help='command to run',
        type=str,
    )

    # XXX: Parse args
    args = parser.parse_args()

    # XXX: Dispatch command
    if args.command == 'new':
        os.makedirs(args.directory, exist_ok=True)
        _wrap(make_environment, args.directory)

    elif args.command == 'template':
        if args.template_command == 'create':
            env = _wrap(Environment, args.notebook)
            _wrap(env.dump_as_template, args.file)

        elif args.template_command == 'load':
            _wrap(load_from_template, args.file, args.where)

    elif args.command == 'package':
        env = _wrap(Environment, args.notebook)

        if args.package_command == 'install':
            for package in args.packages:
                print(f'Installing {package}...')
                _wrap(env.install_pip_package, package)

        elif args.package_command == 'remove':
            for package in args.packages:
                print(f'Removing {package}...')
                _wrap(env.remove_pip_package, package)

        elif args.package_command == 'list':
            packages = _wrap(env.list_installed_pip_packages)
            print(packages)

    elif args.command == 'run':
        env = _wrap(Environment, args.notebook)
        _wrap(env.run_jupyter_notebook)

    elif args.command == 'stop':
        env = _wrap(Environment, args.notebook)
        _wrap(env.stop_jupyter_notebook)

    elif args.command == 'version':
        print(f'{__version__}')

    elif args.command == 'cmd':
        env: Environment = _wrap(Environment, args.notebook)
        cmd = args.cmd_command
        env.run_command_in_venv(cmd)

if __name__ == '__main__':
    _main()

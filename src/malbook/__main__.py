from argparse import ArgumentParser
from pathlib import Path
import sys
from typing import Callable, Any
import os

from . import __version__
from .environment import *
from .errors import *


_DEBUG_MODE = False


def _wrap(func: Callable[..., Any], *args, **kwargs) -> Any:
    try:
        return func(*args, **kwargs)
    except Error as e:
        print(f"error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"error: internal: {e}")
        if _DEBUG_MODE:
            import traceback
            print('traceback:')
            print(traceback.format_exc())
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
    command_remove.add_argument(
        'packages',
        type=str,
        nargs='*',
        metavar='PACKAGES',
        help='packages to remove'
    )

    # XXX: Version
    command_version = commands.add_parser(
        'version',
        help='print version string and exit'
    )

    # XXX: Parse args
    args = parser.parse_args()
    _DEBUG_MODE = args.debug

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

    elif args.command == 'run':
        env = _wrap(Environment, args.notebook)
        _wrap(env.run_jupyter_notebook)

    elif args.command == 'stop':
        env = _wrap(Environment, args.notebook)
        _wrap(env.stop_jupyter_notebook)

    elif args.command == 'install':
        env = _wrap(Environment, args.notebook)
        for package in args.packages:
            _wrap(env.install_pip_package, package)

    elif args.command == 'remove':
        env = _wrap(Environment, args.notebook)
        for package in args.packages:
            _wrap(env.remove_pip_package, package)

    elif args.command == 'version':
        print(f'malbook version {__version__}')


if __name__ == '__main__':
    _main()
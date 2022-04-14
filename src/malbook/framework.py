from os import environ
from typing import List, Any, Optional, Type, Dict
from types import ModuleType
from importlib import import_module

from IPython.display import display_markdown, Markdown
import IPython.display as display

from .errors import *
from .environment import Environment


def ensure_package(package: str, environment: Environment = None) -> None:
    if environment is None:
        environment = Environment()

    if not environment.package_is_installed(package):
        environment.install_pip_package(package)


def safe_import(module: str, package: str = None, environment: Environment = None) -> ModuleType:
    '''
    Imports a module into the current namespace, installing the
    providing package in case it's not already installed.

    Parameters:
        module (str): name of the module
        package (str): name of providing pip package
        environment (malbook.Environment): malbook virtual environment

    Returns:
        the imported module
    '''
    if package is None:
        package = module

    if environment is None:
        environment = Environment()

    ensure_package(package, environment)

    return import_module(module)


def output(text: str, kind: str = 'html'):
    if kind == 'markdown':
        display.display_markdown(display.Markdown(text))
    elif kind == 'html':
        display.display_html(display.HTML(text))
    else:
        raise Error(f"'{kind}' is not a known output kind")


class _Notebook:

    task_provided: List[str]
    task_needed: List[str]

    def __init__(self, variables, debug):
        self.variables = variables
        self._debug = debug
        self.task = None

    def debug(self, message):
        if self._debug:
            print(f"\x1b[31mDebug\x1b[0m: {message}")

    def print(self, message):
        md = Markdown(message)
        display_markdown(md)

    def set(self, variable, value):
        if variable not in self.task_provided:
            self.task_provided.append(variable)
        if variable in self.variables:
            self.debug(f"Overriding '{variable}'")
        self.variables[variable] = value

    def get(self, variable):
        if variable not in self.task_needed:
            self.task_needed.append(variable)
        try:
            return self.variables[variable]
        except KeyError:
            self.debug(f"'{variable}' is not defined")
            return None

    def start_task(self, task):
        self.task = task
        self.task_provided = list()
        self.task_needed = list()
        self.debug(f"Running {task.name}")

    def finish_task(self):
        if not self._debug:
            return
        for variable in self.task.provides:
            if variable not in self.task_provided:
                self.debug(
                    f"Task {self.task.name} didn't provide '{variable}'")
        for variable in self.task.needs:
            if variable not in self.task_needed:
                self.debug(f"Task {self.task.name} didn't need '{variable}'")


class Task:

    _order: int
    name: str
    needs: List[str]
    provides: List[str]
    __notebook: _Notebook
    required_packages: List[str]

    def __init__(self):
        if not hasattr(self, 'name'):
            self.name = self.__class__.__name__
        if not hasattr(self, 'needs'):
            self.needs = list()
        if not hasattr(self, 'provides'):
            self.provides = list()
        if not hasattr(self, 'required_packages'):
            self.required_packages = list()

        self.__notebook = None
        self._order = -1

    def print(self, message: str) -> None:
        self.__notebook.print(message)

    def debug(self, message: str) -> None:
        self.__notebook.debug(message)

    def get(self, variable: str) -> Optional[Any]:
        return self.__notebook.get(variable)

    def set(self, variable: str, value: Any) -> None:
        self.__notebook.set(variable, value)

    def _set_notebook(self, notebook) -> None:
        self.__notebook = notebook

    def import_module(self, name: str) -> ModuleType:
        return import_module(name)

    def __repr__(self) -> str:
        class_ = self.__class__.__name__
        return f"{class_}(needs={self.needs}, provides={self.provides}, "\
               f"_order={self._order})"


class Pipeline:

    __tasks: List[Task]
    _variables: Dict[str, Any]
    __environment: Environment

    def __init__(self):
        self.__tasks = list()
        self._variables = dict()
        try:
            self.__environment = Environment()
        except:
            self.__environment = None

    def add(self, *tasks: List[Type[Task]]) -> None:
        for task in tasks:
            self.__tasks.append(task())

    def define(self, variable: str, value: Any) -> None:
        self._variables[variable] = value

    def __install_all_required_packages(self, notebook):
        if self.__environment is None:
            notebook.debug("Can't find an environment to install packages to")
            return

        notebook.debug('Checking if any packages need to be installed')
        for task in self.__tasks:
            for req in task.required_packages:
                if not self.__environment.package_is_installed(req):
                    notebook.debug(
                        f"Package {req} is not found. Installing...")
                    self.__environment.install_pip_package(req)

    def run(self, debug_output: bool = False) -> None:
        # XXX: A 'root' task is just a wrapper around the
        # pre-defined variables that has 0 dependencies
        class RootTask(Task):
            provides = [var for var in self._variables]
        self.add(RootTask)

        # XXX: Resolve the order of execution and sort
        # tasks by that order
        _resolve_execution_order(self.__tasks)
        self.__tasks.sort(key=lambda x: x._order)

        notebook = _Notebook(self._variables, debug_output)
        self.__install_all_required_packages(notebook)

        for task in self.__tasks:
            if isinstance(task, RootTask):
                continue
            # FIXME: The whole '_set_notebook', 'start_task',
            # and 'finish_task' dance is stupid. Figure out a
            # better way track a task.
            task._set_notebook(notebook)
            notebook.start_task(task)
            task.run()
            notebook.finish_task()


def _resolve_execution_order(tasks):
    # XXX: Check if all needed variables are provided by other tasks
    all_needed = list()
    all_provided = list()

    for task in tasks:
        for variable in task.needs:
            all_needed.append(
                (task.name, variable)
            )
        for variable in task.provides:
            all_provided.append(variable)

    for (task_name, dependency) in all_needed:
        if dependency not in all_provided:
            raise DependencyError(f"Task {task_name} needs {dependency}, "
                                  "but it's not defined or provided by any "
                                  "other task")

    # XXX: Helper functions for cycle detection algorithm
    # XXX: get_dependents returns a list of tasks that need
    #      some variable

    def get_dependents(variable):
        dependents = list()
        for task in tasks:
            if variable in task.needs:
                dependents.append(task)
        return dependents

    # XXX: get_providers returns a list of tasks that provide a
    #      variable
    def get_providers(variable):
        providers = list()
        for task in tasks:
            if variable in task.provides:
                providers.append(task)
        return providers

    # XXX: This is only necessary because Python is neither
    # pass by value nor pass by reference.
    class Stack:
        def __init__(self):
            self.stack = list()

        def push(self, item):
            self.stack.append(item)

        def pop(self):
            self.stack = self.stack[:-1]

        def __contains__(self, item):
            return item in self.stack

    # XXX: Recursive DFS part of cycle searching algorithm
    def has_cycles_to_self(task, stack=None):
        if stack is None:
            stack = Stack()
        if task in stack:
            return True
        stack.push(task)

        dependents = list()
        for variable in task.provides:
            dependents.extend(get_dependents(variable))

        for dependent in dependents:
            if has_cycles_to_self(dependent, stack):
                return True

        stack.pop()
        return False

    # XXX: Detect cycles
    for task in tasks:
        if has_cycles_to_self(task):
            raise DependencyError('Dependency cycle detected in tasks')

    # XXX: Helper functions for execution order assignment algorithm

    # XXX: Assign execution orders
    assigned = 0
    for task in tasks:
        if len(task.needs) == 0:
            task._order = 0
            assigned += 1

    while assigned != len(tasks):
        for task in tasks:
            if task._order != -1:
                continue

            high_order = -1
            for dependency in task.needs:
                providers = get_providers(dependency)
                low_order = min(providers, key=lambda x: x._order)._order
                if low_order > high_order:
                    high_order = low_order

            if high_order != -1:
                task._order = high_order + 1
                assigned += 1

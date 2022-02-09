from typing import Callable, List, Optional, Dict, Any, Tuple
from IPython.display import Markdown, display


class Error(BaseException):
    pass


class Notebook:

    def print(self, markdown: str) -> None:
        raise NotImplementedError(f"{self.__class__.__name__} doesn't implement Notebook.print()")

    def get(self, key: str) -> Optional[Any]:
        raise NotImplementedError(f"{self.__class__.__name__} doesn't implement Notebook.get()")

    def set(self, key: str, value: Any) -> None:
        raise NotImplementedError(f"{self.__class__.__name__} doesn't implement Notebook.set()")


Callback = Callable[[Notebook], None]


class Pipeline:

    def define(self, key: str, value: Any) -> None:
        raise NotImplementedError(f"{self.__class__.__name__} doesn't implement Pipeline.add_task()")

    def add_task(self, func: Callback, depends: List[str] = [], name: str = '') -> None:
        raise NotImplementedError(f"{self.__class__.__name__} doesn't implement Pipeline.add_task()")

    def run(self) -> None:
       raise NotImplementedError(f"{self.__class__.__name__} doesn't implement Pipeline.run()")


class _NotebookImpl(Notebook):

    current_task: str
    variables: Dict[str, Any]
    debug: bool

    def __init__(self, debug: bool, variables: Dict[str, Any]):
        self.debug = debug
        self.current_task = 'None'
        self.variables = variables

    def log(self, msg: str) -> None:
        if self.debug:
            prefix = '\x1b[31mDEBUG\x1b[0m: '
            if self.current_task != '':
                prefix += f'{self.current_task}: '
            print(f'{prefix} {msg}')

    def print(self, markdown: str) -> None:
        display(Markdown(markdown))

    def get(self, key: str) -> Optional[Any]:
        if key not in self.variables:
            self.log(f'Variable {key} is not defined')
            return None
        return self.variables[key]

    def set(self, key: str, value: Any) -> None:
        if key in self.variables:
            self.log(f'Overriding variable {key}')
        self.variables[key] = value

    def start_task(self, name: str) -> None:
        self.log(f'Running task {name}...')
        self.current_task = name


class _Task:
    name: str
    func: Callback
    depends: List[str]
    order: int

    def __init__(self, func: Callback, depends: List[str], name: str = ''):
        self.name = name if name != '' else func.__name__ 
        self.func = func
        self.depends = depends
        self.order = -1

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(name={self.name}, depends={self.depends}, order={self.order})>'


class _NodeStack:

    stack: List[str]

    def __init__(self):
        self.stack = list()

    def push(self, node: str) -> None:
        self.stack.append(node)

    def pop(self) -> None:
        self.stack = self.stack[:-1]

    def __contains__(self, node: str) -> bool:
        return node in self.stack


class _DependencyGraph:

    edges: List[Tuple[str, str]]

    def __init__(self):
        self.edges = list()

    def are_connected(self, src: str, dst: str) -> bool:
        return (src, dst) in self.edges

    def add_edge(self, src: str, dst: str) -> None:
        if not self.are_connected(src, dst):
            self.edges.append((src, dst))

    def get_connected_nodes(self, root: str) -> List[str]:
        nodes = []
        for (src, dst) in self.edges:
            if src == root:
                nodes.append(dst)
        return nodes

    def get_direct_dependents_of(self, node: str) -> List[str]:
        dependents = list()
        for (src, dst) in self.edges:
            if dst == node:
                dependents.append(src)
        return dependents

    def has_cycles(self) -> bool:
        # XXX: Recursive DFS search part of the algorithm
        def _has_cycle_to_self(root: str, stack: _NodeStack = None) -> bool:
            if stack is None:
                stack = _NodeStack()
            if root in stack:
                return True
            nodes = self.get_connected_nodes(root)
            stack.push(root)
            for node in nodes:
                if _has_cycle_to_self(node, stack):
                    return True
            stack.pop()

            return False

        # XXX: Non-recursive part
        # XXX: Get all nodes in graph
        nodes = []
        for (src, dst) in self.edges:
            if src not in nodes:
                nodes.append(src)
            if dst not in nodes:
                nodes.append(dst)

        # XXX: Run DFS on all nodes to determine if there are cycles
        for node in nodes:
            if _has_cycle_to_self(node):
                return True
        return False


class _PipelineImpl(Pipeline):

    tasks_dict: Dict[str, _Task]
    tasks: List[_Task]
    variables: Dict[str, Any]
    debug: bool

    def __init__(self, debug: bool):
        self.tasks = list()
        self.variables = dict()
        self.tasks_dict = dict()
        self.debug = debug

    def define(self, key: str, value: Any) -> None:
        if key in self.variables:
            raise Error(f'Variable {key} is already defined')

        self.variables[key] = value

    def add_task(self, func: Callback, depends: List[str] = [], name: str = '') -> None:
        name = func.__name__ if name == '' else name
        if name in self.tasks_dict:
            raise Error(f'Task {name} is already defined')

        task = _Task(func, depends, name)
        self.tasks_dict[name] = task
        self.tasks.append(task)

    def resolve_dependencies(self) -> None:
        # XXX: Check if all required dependencies exist
        for task in self.tasks:
            for dep in task.depends:
                if dep not in self.tasks_dict:
                    raise Error(f'Dependency {dep} required by {task.name} is not defined')

        # XXX: Build dependency graph
        graph = _DependencyGraph()
        for task in self.tasks:
            for dep in task.depends:
                graph.add_edge(task.name, dep)

        # XXX: Check for dependency cycles
        if graph.has_cycles():
            # TODO: Come up with a better error message
            raise Error('Dependency cycles detected in tasks')

        # XXX: Get root tasks (tasks without dependencies)
        root = []
        for task in self.tasks:
            if len(task.depends) == 0:
                root.append(task)

        # XXX: If there are no root tasks, then there is nothing that we
        # can run first
        if len(root) == 0:
            # TODO: Come up with a better error message
            raise Error('No root tasks defined')

        # XXX: Assign lowest possible order to root tasks
        order = 0
        for task in root:
            task.order = order

        # XXX: Assign task execution orders
        total_assigned = len(root)
        while total_assigned != len(self.tasks):
            for task in self.tasks:
                if task.order != -1:
                    continue

                order = -1
                seen_unassigned = False
                for dependency_name in task.depends:
                    dependency = self.tasks_dict[dependency_name]
                    dependency_order = dependency.order
                    if dependency_order == -1:
                        seen_unassigned = True
                    if dependency_order > order:
                        order = dependency_order

                if not seen_unassigned:
                    task.order = order + 1
                    total_assigned += 1

        # XXX: Finally, sort the tasks by ascending order of execution
        self.tasks.sort(key=lambda x: x.order)

    def run(self) -> None:
        self.resolve_dependencies()
        notebook = _NotebookImpl(self.debug, self.variables)

        for task in self.tasks:
            notebook.start_task(task.name)
            task.func(notebook)


def make_pipeline(debug: bool = False) -> Pipeline:
    return _PipelineImpl(debug)

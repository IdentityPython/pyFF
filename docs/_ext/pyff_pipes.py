"""
Sphinx directive that documents every registered pyFF pipe from its docstring.

Usage in a document::

    .. pyff-pipes::

Pipes are listed by the name used in pipeline YAML (the key in
:py:data:`pyff.pipes.registry`), not by the name of the Python function.
"""

import inspect
import re

from docutils import nodes
from docutils.statemachine import StringList
from sphinx.util.docutils import SphinxDirective
from sphinx.util.nodes import nested_parse_with_titles

# Field lines describe the Python signature, which is irrelevant for pipeline authors.
_PYTHON_FIELDS = re.compile(r'^\s*:(param|type|return|returns|rtype)\b')


def _pipe_docs():
    import pyff.builtins  # noqa: F401  (importing registers the pipes)
    from pyff.pipes import registry

    for name, func in sorted(registry.items()):
        doc = inspect.getdoc(func)
        # Deprecated pipes are wrapped and end up without a docstring.
        if doc:
            yield name, doc


def _strip_python_fields(doc):
    return '\n'.join(line for line in doc.splitlines() if not _PYTHON_FIELDS.match(line))


class PyffPipes(SphinxDirective):
    has_content = False

    def run(self):
        lines = []
        for name, doc in _pipe_docs():
            lines += [name, '-' * len(name), '', _strip_python_fields(doc), '']

        node = nodes.section()
        node.document = self.state.document
        content = StringList('\n'.join(lines).splitlines(), source=f'<{self.name}>')
        nested_parse_with_titles(self.state, content, node)
        return node.children


def setup(app):
    app.add_directive('pyff-pipes', PyffPipes)
    return {'parallel_read_safe': True, 'parallel_write_safe': True}

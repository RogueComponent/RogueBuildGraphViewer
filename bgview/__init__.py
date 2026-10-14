"""bgview -- static analysis for Unreal Engine BuildGraph scripts.

Makes BuildGraph's invisible semantics (tag dataflow, parse-time property
expansion, agent=machine boundaries) visible so defects die at review
instead of shipping silently. See SPEC.md at the repo root.

Deliberately does not import submodules here: bgview.* modules land
incrementally task-by-task (see SPEC.md §T), and eagerly re-exporting them
from this file would make __init__.py a piece of shared, contended surface
that every later task has to touch. Import what you need directly, e.g.
`from bgview.loader import load` or `from bgview.schema import Schema`.
"""

__version__ = "0.3.0"

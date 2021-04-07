# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
to_add = os.path.abspath('../../neo3')
# print(f"Path adding! {to_add}")
sys.path.insert(0, to_add)
sys.path.append(os.path.abspath("./_ext"))
sys.path.append(os.path.abspath("./_theme"))
from neo3 import version


# -- Project information -----------------------------------------------------

project = 'neo-mamba'
copyright = '2019-2021, COZ - Erik van den Brink'
author = 'Erik van den Brink'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
'sphinx.ext.autodoc',
'sphinx.ext.napoleon',
'sphinx_autodoc_typehints',
'sphinx.ext.intersphinx',
'classoverview'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.

# use a modified 'classic' theme, can be found in the _theme directory.
html_theme = 'neo3'
# provide our own landing page
html_additional_pages = {'index': 'index.html'}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# napoleon specific configuration
napoleon_numpy_docstring = False
# don't include dunder methods
napoleon_include_special_with_doc = False
# must be set to True or param types get stripped from the documentation
napoleon_use_param = True

# autodoc specific configuration
# set typing.TYPE_CHECKING to True to enable “expensive” typing imports
set_type_checking_flag = True
autoclass_content = 'both'
autodoc_member_order = 'groupwise'

# intersphinx configuratin
intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}

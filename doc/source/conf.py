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
# NOTE: if you want to build the docs without installing in-toto, uncomment the
# three lines below
import os
import sys

import sphinx_rtd_theme

# sys.path.insert(0, os.path.abspath(os.path.join('..', '..')))

sys.path.append(os.path.abspath("./_ext"))

import in_toto

# -- Project information -----------------------------------------------------

project = "in-toto"
copyright = "2019, NYU Secure Systems Lab"
author = "NYU Secure Systems Lab"

# The full version, including alpha/beta/rc tags
release = in_toto.__version__


# -- General configuration ---------------------------------------------------

# The master toctree document.
master_doc = "index"


# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinxarg.ext",
    "argparse_epilog",
    "sphinx.ext.todo",
    "sphinx_rtd_theme",
    "myst_parser",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "logo_only": True,
    "collapse_navigation": False,
    "navigation_depth": 3,
}
html_logo = "in-toto-horizontal-white.png"
html_favicon = "in-toto-icon-color.png"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = ['_static']

todo_include_todos = True

napoleon_custom_sections = [("Side Effects", "returns_style")]

rst_prolog = """
:github_url: https://github.com/in-toto/in-toto/blob/develop/doc/source/CONTRIBUTING.md#build-documentation
"""

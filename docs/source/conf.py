# to generate documentation when modules are added, run:
# sphinx-apidoc --separate --force -o source ../autorop
# to build documentation locally, run ``make html``

import sphinx_rtd_theme

# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

sys.path.insert(0, os.path.abspath("../../"))


# -- Project information -----------------------------------------------------

project = "autorop"
copyright = "2020-2021, Mariusz Skoneczko"
author = "Mariusz Skoneczko"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_rtd_theme",
    "sphinx_autodoc_typehints",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []

# List some special members
autodoc_default_options = {
    "special-members": "__init__,__call__",
}

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "collapse_navigation": False,
    "navigation_depth": 5,
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# -- Automatically generate apidocs ------------------------------------------
# Based on https://github.com/readthedocs/readthedocs.org/issues/1139#issuecomment-215689182


def run_apidoc(_):
    from sphinx.ext.apidoc import main

    cur_dir = os.path.abspath(os.path.dirname(__file__))
    output_dir = cur_dir
    module_dir = os.path.join(cur_dir, "..", "..", "autorop")
    main(["-f", "-o", output_dir, module_dir])


def setup(app):
    app.connect("builder-inited", run_apidoc)

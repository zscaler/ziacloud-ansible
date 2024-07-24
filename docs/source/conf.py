##############################################################################
# (C) Copyright Zscaler Inc, 2024                                           #
##############################################################################

##############################################################################
#                 Sphinx documentation Configuration                         #
##############################################################################
# Configuration file for the Sphinx documentation builder, for more follow link:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
# ``sphinx-build``` options follow link:
# https://www.sphinx-doc.org/en/latest/man/sphinx-build.html
##############################################################################

##############################################################################
# Project information
##############################################################################

project = "Zscaler Internet Access Ansible Collection"
copyright = "2024, Zscaler Inc"
author = "Zscaler Inc"
html_title = "Ansible Collections Documentation"

# The full version, including alpha/beta/rc tags
release = "1.2.0"

# Disable the Copyright footer for Read the docs at the bottom of the page
# by setting property html_show_copyright = False
html_show_copyright = True

# Disable showing Sphinx footer message:
# "Built with Sphinx using a theme provided by Read the Docs. "
html_show_sphinx = False

##############################################################################
# General configuration
##############################################################################

# Add any Sphinx extension module names here, as strings. They can be extensions
# coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    "sphinx.ext.intersphinx",
    "sphinx.ext.autodoc",
    "sphinx_antsibull_ext",
    "sphinx.ext.todo",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx_ansible_theme",
]

# Add any paths that contain templates here, relative to this directory.
# This sites template is ../templates/module.rst.j2
templates_path = ["../templates"]

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
#
# source_suffix = ['.rst', '.md']
source_suffix = ".rst"

# The master toctree document.
master_doc = "index"

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = "en"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = None

##############################################################################
# Options for HTML output
##############################################################################

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes such 'alabaster'. Currently this site uses the
# sphinx_rtd_theme HTML theme.
html_theme = "sphinx_ansible_theme"
# html_theme = "sphinx_rtd_theme"
# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the built-in "default.css".
# html_static_path = ['_static']

# Github options used with Sphinx
html_context = {
    "display_github": True,
    "github_user": "zscaler",
    "github_repo": "ziacloud-ansible",
    "github_version": "master",
    "conf_py_path": "/docs/source/",
}

# Sort versions by one or more values. Valid values are semver, alpha, and time.
# Semantic is referred to as 'semver', this would ensure our latest VRM is
# the first in the list of documentation links.
scv_sort = ("semver",)

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
# html_theme_options = {
#     "sidebar_hide_name": True,
# }

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = ["_static"]

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself.  Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
# html_sidebars = {}

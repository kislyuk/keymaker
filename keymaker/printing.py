"""
Printing helper functions for Keymaker
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys

use_color = True if sys.stdout.isatty() else False

def CYAN(message=None):
    if message is None:
        return '\033[36m' if use_color else ''
    else:
        return CYAN() + message + ENDC()

def BLUE(message=None):
    if message is None:
        return '\033[34m' if use_color else ''
    else:
        return BLUE() + message + ENDC()

def YELLOW(message=None):
    if message is None:
        return '\033[33m' if use_color else ''
    else:
        return YELLOW() + message + ENDC()

def GREEN(message=None):
    if message is None:
        return '\033[32m' if use_color else ''
    else:
        return GREEN() + message + ENDC()

def RED(message=None):
    if message is None:
        return '\033[31m' if use_color else ''
    else:
        return RED() + message + ENDC()

def WHITE(message=None):
    if message is None:
        return '\033[37m' if use_color else ''
    else:
        return WHITE() + message + ENDC()

def UNDERLINE(message=None):
    if message is None:
        return '\033[4m' if use_color else ''
    else:
        return UNDERLINE() + message + ENDC()

def BOLD(message=None):
    if message is None:
        return '\033[1m' if use_color else ''
    else:
        return BOLD() + message + ENDC()

def ENDC():
    return '\033[0m' if use_color else ''

def KEYMAKER_LOGO():
    return BOLD() + GREEN() + "Keymaker:" + ENDC()

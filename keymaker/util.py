import os
from collections import namedtuple

try:
    from shutil import which
except ImportError:

    def which(name):
        if os.path.exists("/usr/local/bin/" + name):
            return "/usr/local/bin/" + name
        elif os.path.exists("/usr/bin/" + name):
            return "/usr/bin/" + name


class ARN(namedtuple("ARN", "partition service region account resource")):
    def __str__(self):
        return ":".join(["arn"] + list(self))


ARN.__new__.__defaults__ = ("aws", "", "", "", "")


def from_bytes(data, big_endian=False):
    """Used on Python 2 to handle int.from_bytes"""
    if isinstance(data, str):
        data = bytearray(data)
    if big_endian:
        data = reversed(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num

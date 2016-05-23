#!/usr/bin/env python

import os.path
import sys
import unittest

sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import keymaker

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

class KeymakerTests(unittest.TestCase):

    key = 'AKIAIJLRCB5E7CGTDF5A'

    @unittest.skipUnless(USING_PYTHON2, "Skipping Python 2 specific test")
    def test_from_bytes(self):
        """Test the Python 2 version of int.from_bytes"""
        result = keymaker.from_bytes(self.key)
        assert result == 372272460710313033966036665003922315590817631041
        assert type(result) == long

    def test_aws_to_unix_id(self):
        """Access key ID must always convert to the same UID number"""
        result = keymaker.aws_to_unix_id(self.key)
        assert result == 26594
        assert type(result) == int

if __name__ == "__main__":
    unittest.main()

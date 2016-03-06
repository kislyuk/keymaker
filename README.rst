Keymaker: Lightweight SSH key management on AWS EC2
===================================================

Keymaker is **the missing link between SSH and IAM accounts on Amazon AWS**. It's a stateless synchronization engine
that securely manages the process of SSH public key sharing and verification, user and group synchronization, and home
directory sharing (via optional `EFS <https://aws.amazon.com/efs/>`_ integration). You, the AWS account administrator,
define or import user and group identities in IAM, and instances in your account dynamically retrieve and use those
identities to authenticate your users. Keymaker is the modern, minimalistic alternative to **LDAP** or **Active
Directory** authentication.

Installation
------------
::

    pip install keymaker
    keymaker install

Principle of operation
----------------------

TODO

Authors
-------
* Andrey Kislyuk

Links
-----
* `Project home page (GitHub) <https://github.com/kislyuk/keymaker>`_
* `Documentation (Read the Docs) <https://keymaker.readthedocs.org/en/latest/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/keymaker>`_

Bugs
~~~~
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/kislyuk/keymaker/issues>`_.

License
-------
Licensed under the terms of the `Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_.

.. image:: https://travis-ci.org/kislyuk/keymaker.svg
        :target: https://travis-ci.org/kislyuk/keymaker
.. image:: https://coveralls.io/repos/kislyuk/keymaker/badge.svg?branch=master
        :target: https://coveralls.io/r/kislyuk/keymaker?branch=master
.. image:: https://pypip.in/version/keymaker/badge.svg
        :target: https://pypi.python.org/pypi/keymaker
.. image:: https://pypip.in/download/keymaker/badge.svg
        :target: https://pypi.python.org/pypi/keymaker
.. image:: https://pypip.in/py_versions/keymaker/badge.svg
        :target: https://pypi.python.org/pypi/keymaker
.. image:: https://readthedocs.org/projects/keymaker/badge/?version=latest
        :target: https://keymaker.readthedocs.org/

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

Amazon Web Services `IAM <https://aws.amazon.com/iam/>`_ user accounts provide the ability to add SSH public keys to
their metadata (up to 5 keys can be added; individual keys can be disabled). Keymaker provides an integrated way for a
user to upload their public SSH key with ``keymaker upload_key``.

Run ``keymaker install`` on instances that you want your users to connect to. This installs three components:

* An ``AuthorizedKeysCommand`` sshd configuration directive, which acts as a login event hook and dynamically retrieves
  public SSH keys from IAM for the user logging in, using the default `boto3 <https://github.com/boto/boto3>`_
  credentials (which default to the instance's IAM role credentials).

* A ``pam_exec`` PAM configuration directive, which causes sshd to call ``keymaker-create-account-for-iam-user`` early
  in the login process. This script detects if a Linux user account does not exist for the authenticating principal but
  an authorized IAM account exists with the same name, and creates the account on demand.

* A cron job that runs on your instance once an hour and synchronizes IAM group membership information. Only IAM groups
  that start with a configurable prefix (by default, ``keymaker_``) are synchronized as Linux groups.

As a result, users who connect to your instances over SSH are given access based on information centralized in your AWS
account. Users must have an active IAM account with active matching SSH public keys in order for authentication to
succeed. Users' UIDs and group memberships are also synchronized across your instances, so any UID-based checks or
group-based privileges remain current as well.

TODO
----

- integration with watchtower and/or cloudtrail
- when setting up a user, warn about any UID/GID collisions
- warn or fail on any UID or custom GID hash mismatches
- cron mode for group synchronization
- include docs for installing daemon via userdata/cloud-init


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

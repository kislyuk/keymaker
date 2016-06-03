Keymaker: Lightweight SSH key management on AWS EC2
===================================================
.. image:: /keymaker.jpg?raw=true

Keymaker is **the missing link between SSH and IAM accounts on Amazon AWS**. It's a stateless synchronization engine
that securely manages the process of SSH public key sharing and verification, user and group synchronization, and home
directory sharing (via optional `EFS <https://aws.amazon.com/efs/>`_ integration). You, the AWS account administrator,
define or import user and group identities in IAM, and instances in your account dynamically retrieve and use those
identities to authenticate your users. Keymaker is the modern, minimalistic alternative to **LDAP** or **Active
Directory** authentication.

Installation
------------
Run ``pip install keymaker``.

On instances that accept SSH logins:

- Run ``keymaker install``.
- Ensure processes launched by sshd have read-only access to IAM (most easily done by launching the instance with an
  instance profile/IAM role that has the IAMReadOnlyAccess policy attached).

Usage
-----
Run ``keymaker`` with no arguments to get usage information. In client mode (running on a computer that you will connect
from), you can run ``keymaker <subcommand>``, where subcommand is::

    upload_key          Upload public SSH key for a user. Run this command for each user who will be accessing EC2 hosts.
    list_keys           Get public SSH keys for a given or current IAM/SSH user.
    disable_key         Disable a given public SSH key for a given or current IAM/SSH user.
    enable_key          Enable a given public SSH key for a given or current IAM/SSH user.
    delete_key          Delete a given public SSH key for a given or current IAM/SSH user.

Principle of operation
----------------------

Amazon Web Services `IAM <https://aws.amazon.com/iam/>`_ user accounts provide the ability to add SSH public keys to
their metadata (up to 5 keys can be added; individual keys can be disabled). Keymaker uses this metadata to authenticate
SSH logins. Keymaker provides an integrated way for a user to upload their public SSH key to their IAM account
with ``keymaker upload_key``.

Run ``keymaker install`` on instances that you want your users to connect to. This installs three components:

* An ``AuthorizedKeysCommand`` sshd configuration directive, which acts as a login event hook and dynamically retrieves
  public SSH keys from IAM for the user logging in, using the default `boto3 <https://github.com/boto/boto3>`_
  credentials (which default to the instance's IAM role credentials).

* A ``pam_exec`` PAM configuration directive, which causes sshd to call ``keymaker-create-account-for-iam-user`` early
  in the login process. This script detects if a Linux user account does not exist for the authenticating principal but
  an authorized IAM account exists with the same name, and creates the account on demand.

* A cron job that runs on your instance once an hour and synchronizes IAM group membership information. Only IAM groups
  whose names start with a configurable prefix (by default, ``keymaker_*``) are synchronized as Linux groups.

As a result, users who connect to your instances over SSH are given access based on information centralized in your AWS
account. Users must have an active IAM account with active matching SSH public keys in order for authentication to
succeed. Users' UIDs and group memberships are also synchronized across your instances, so any UID-based checks or
group-based privileges remain current as well.

Example: launching an instance with IAM read-only access
--------------------------------------------------------
TODO

EFS integration
---------------
Email kislyuk@gmail.com for details on the EFS integration.

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
.. image:: https://img.shields.io/pypi/v/keymaker.svg
        :target: https://pypi.python.org/pypi/keymaker
.. image:: https://img.shields.io/pypi/dm/keymaker.svg
        :target: https://pypi.python.org/pypi/keymaker
.. image:: https://img.shields.io/pypi/l/keymaker.svg
        :target: https://pypi.python.org/pypi/keymaker
.. image:: https://readthedocs.org/projects/keymaker/badge/?version=latest
        :target: https://keymaker.readthedocs.org/

Changes for v1.0.9 (2019-07-10)
===============================

-  Look up keymaker executables in path using shutil.which and fallback
   (#56)

Changes for v1.0.8 (2019-01-22)
===============================

-  Provide more feedback when managing keys

Changes for v1.0.7 (2018-07-16)
===============================

-  Avoid trimming username if the suffix length is zero (#47)

Changes for v1.0.6 (2018-05-25)
===============================

-  Fix logic error in keymaker sync_groups

-  Allow username suffix to be set in keymaker configure

Changes for v1.0.5 (2018-05-21)
===============================

Fixup for get_uid with user suffix

Changes for v1.0.4 (2018-05-18)
===============================

-  Allow configurable username suffix in keymaker role config

-  Auto-configure assume role permissions in keymaker configure

-  Add missing iam:GetGroup permission for keymaker sync_groups (#42)

Changes for v1.0.3 (2018-04-13)
===============================

-  Remove unused dependency

Changes for v1.0.2 (2018-04-12)
===============================

-  Produce more readable log line when no config is found in role
   description

Changes for v1.0.1 (2018-04-12)
===============================

-  Fix user autovivification

Changes for v1.0.0 (2018-04-05)
===============================

-  For the avoidance of doubt, this tool is stable.

Changes for v0.5.3 (2018-04-05)
===============================

-  Remove unnecessary PAM config. Fixes #23

-  Fix group sync on default iam_linux_group_prefix. Fixes #40

Changes for v0.5.2 (2018-03-26)
===============================

-  Make get_user, get_group, sync_groups cross account aware (#38)

-  Add keymaker –version

Changes for v0.5.1 (2018-02-05)
===============================

-  keymaker configure: account autoconfiguration support (#30)

Changes for v0.5.0 (2017-12-21)
===============================

-  Introduce cross-account auth capability and group membership
   requirement (#29)

-  PAM JIT user vivifier: Change 'requisite' to 'optional' (#22)

-  Changing PAM behaviour to stop ugly output on first connection (#19)

-  Adding shell and create-home to useradd command (#18)

Changes for v0.4.3 (2017-05-25)
===============================

-  Make the SSH hook work with RHEL-based distributions (#16)

-  Test and documentation improvements




Changes for v0.3.3 (2016-09-25)
===============================

-  Fix release script

Changes for v0.3.0 (2016-09-25)
===============================

-  Python 2.7 support

Version 0.2.1 (2016-03-09)
--------------------------
- Further cleanup and documentation improvements.

Version 0.2.0 (2016-03-09)
--------------------------
- Cleanup and documentation improvements.

Version 0.1.0 (2016-03-06)
--------------------------
- Complete work on first iteration of CodeDeploy-compatible SSH public key API.

Version 0.0.2 (2016-03-06)
--------------------------
- Begin work on CodeDeploy-compatible SSH public key API.

Version 0.0.1 (2015-04-11)
--------------------------
- Initial release.

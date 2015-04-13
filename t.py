#!/usr/bin/env python3

from keymaker import get_bucket, set_permissions

bucket = get_bucket()
set_permissions(bucket)
#watch(bucket)


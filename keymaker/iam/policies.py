trust_policy_template = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": None,
            "Action": "sts:AssumeRole"
        }
    ]
}

keymaker_instance_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetSSHPublicKey",
                "iam:ListSSHPublicKeys",
                "iam:GetUser",
                "iam:GetGroup",
                "iam:ListGroups",
                "iam:ListGroupsForUser",
                "iam:GetRole",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}

keymaker_instance_assume_role_statement = {
    "Action": "sts:AssumeRole",
    "Resource": None,
    "Effect": "Allow"
}

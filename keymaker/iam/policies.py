ec2_trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
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
                "iam:ListGroups",
                "iam:ListGroupsForUser",
                "iam:GetRole",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}

cross_account_trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": []
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

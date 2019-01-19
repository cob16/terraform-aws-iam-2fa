//password-policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 12
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}

//s3 public acess
resource "aws_s3_account_public_access_block" "secure_s3_public_acls" {
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

# groups

resource "aws_iam_group" "developer" {
  name = "developer"
}

resource "aws_iam_group" "admin" {
  name = "admin"
}

# conditions
locals {
  conditionIfMultiFactorAuthPresent = {
    test     = "Bool"
    variable = "aws:MultiFactorAuthPresent"

    values = [
      "true",
    ]
  }

  conditionRestrictRegion = {
    test     = "StringEquals"
    variable = "aws:RequestedRegion"

    values = [
      "eu-west-2",
    ]
  }
}

# get the curerent account arns ids and username for later
data "aws_caller_identity" "current" {}

# developer policys

data "aws_iam_policy_document" "AllowIndividualUserToManageTheirOwnMFA" {
  # based off https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html#MFAProtectedAPI-user-mfa
  statement {
    sid = "AllowIndividualUserToListOnlyTheirOwnMFA"

    actions = [
      "iam:ListMFADevices",
    ]

    resources = [
      "arn:aws:iam::*:mfa/*",
      "arn:aws:iam::*:user/$${aws:username}", ## $$ is used here to escape terrfarom parsing this aws var
    ]
  }

  statement {
    sid = "AllowIndividualUserToManageTheirOwnMFA"

    actions = [
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
    ]

    resources = [
      "arn:aws:iam::*:mfa/*",
      "arn:aws:iam::*:user/$${aws:username}", ## $$ is used here to escape terrfarom parsing this aws var
    ]
  }

  statement {
    sid = "AllowIndividualUserToDeactivateOnlyTheirOwnMFAOnlyWhenUsingMFA"

    actions = [
      "iam:DeactivateMFADevice",
    ]

    resources = [
      "arn:aws:iam::*:mfa/*",
      "arn:aws:iam::*:user/$${aws:username}", ## $$ is used here to escape terrfarom parsing this aws var
    ]

    condition = [
      "${local.conditionIfMultiFactorAuthPresent}",
    ]
  }
}

resource "aws_iam_policy" "AllowIndividualUserToManageTheirOwnMFA" {
  name   = "AllowIndividualUserToManageTheirOwnMFA"
  path   = "/"
  policy = "${data.aws_iam_policy_document.AllowIndividualUserToManageTheirOwnMFA.json}"
}

data "aws_iam_policy_document" "AllowIndividualUserToManageTheirOwnKeys" {
  statement {
    sid = "ManageSSHKeys"

    actions = [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:UpdateAccessKey",
    ]

    resources = [
      "arn:aws:iam::*:user/$${aws:username}", ## $$ is used here to escape terrfarom parsing this aws var
    ]
  }
}

resource "aws_iam_policy" "AllowIndividualUserToManageTheirOwnKeys" {
  name   = "AllowIndividualUserToManageTheirOwnKeys"
  path   = "/"
  policy = "${data.aws_iam_policy_document.AllowIndividualUserToManageTheirOwnKeys.json}"
}

data "aws_iam_policy_document" "AllowS3IfMfa" {
  statement {
    sid = "AllowS3IfMFA"

    actions = [
      "s3:*",
    ]

    resources = [
      "*",
    ]

    condition = [
      "${local.conditionIfMultiFactorAuthPresent}",
    ]
  }

  statement {
    sid    = "ForceS3Region"
    effect = "Deny"

    actions = [
      "s3:CreateBucket",
    ]

    resources = [
      "*",
    ]

    condition = [
      {
        test     = "StringNotEquals"
        variable = "aws:RequestedRegion"

        values = [
          "eu-west-2",
        ]
      },
    ]
  }

  statement {
    sid    = "DenyStateBucket" ## comment this statement out if not using state bucket
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      "arn:aws:s3:::ceb-terraform-remote-state-storage-s3/*",
      "arn:aws:s3:::ceb-terraform-remote-state-storage-s3",
    ]
  }
}

resource "aws_iam_policy" "AllowS3IfMfa" {
  name   = "AllowS3IfMfa"
  path   = "/"
  policy = "${data.aws_iam_policy_document.AllowS3IfMfa.json}"
}

data "aws_iam_policy_document" "AllowEC2IfMfa" {
  statement {
    sid = "AllowEC2General"

    actions = [
      "ec2:*",
      "elasticloadbalancing:*",
      "cloudwatch:*",
      "autoscaling:*",
    ]

    resources = [
      "*",
    ]

    condition = [
      "${local.conditionIfMultiFactorAuthPresent}",
      "${local.conditionRestrictRegion}",
    ]
  }

  statement {
    sid = "AllowEC2GeneralLinkedRoles"

    actions = [
      "iam:CreateServiceLinkedRole",
    ]

    resources = [
      "*",
    ]

    condition = [
      "${local.conditionIfMultiFactorAuthPresent}",
      "${local.conditionRestrictRegion}",
      {
        test     = "StringEquals"
        variable = "iam:AWSServiceName"

        values = [
          "autoscaling.amazonaws.com",
          "ec2scheduled.amazonaws.com",
          "elasticloadbalancing.amazonaws.com",
          "spot.amazonaws.com",
          "spotfleet.amazonaws.com",
          "transitgateway.amazonaws.com",
        ]
      },
    ]
  }
}

resource "aws_iam_policy" "AllowEC2IfMfa" {
  name   = "AllowEC2IfMfa"
  path   = "/"
  policy = "${data.aws_iam_policy_document.AllowEC2IfMfa.json}"
}

# admin policys

data "aws_iam_policy_document" "AllowAdminIfMFA" {
  statement {
    sid = "RequireAdminMFA"

    actions = [
      "*",
    ]

    resources = [
      "*",
    ]

    condition = [
      "${local.conditionIfMultiFactorAuthPresent}",
    ]
  }
}

resource "aws_iam_policy" "AllowAdminIfMFA" {
  name   = "AllowAdminIfMFA"
  path   = "/"
  policy = "${data.aws_iam_policy_document.AllowAdminIfMFA.json}"
}

data "aws_iam_policy_document" "AssumeRoleToAdmin" {
  statement {
    sid = "AssumeRoleToAdmin"

    actions = [
      "sts:AssumeRole",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/admin",
    ]

    condition = [
      "${local.conditionIfMultiFactorAuthPresent}",
    ]
  }
}

resource "aws_iam_policy" "AssumeRoleToAdmin" {
  name   = "AssumeRoleToAdmin"
  path   = "/"
  policy = "${data.aws_iam_policy_document.AssumeRoleToAdmin.json}"
}

# admin assume role
data "aws_iam_policy_document" "adminAssumeRolePolicy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "adminAssumeRole" {
  name               = "admin"
  assume_role_policy = "${data.aws_iam_policy_document.adminAssumeRolePolicy.json}"
}

resource "aws_iam_policy_attachment" "adminAssumeRolePolicy" {
  name       = "adminAssumeRolePolicy"
  roles      = ["${aws_iam_role.adminAssumeRole.name}"]
  policy_arn = "${aws_iam_policy.AllowAdminIfMFA.arn}"
}

# developer group policy-attachments
resource "aws_iam_group_policy_attachment" "DevelopersIAMReadOnlyAccess" {
  group      = "${aws_iam_group.developer.name}"
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

# only neded for codeDeploy
# resource "aws_iam_group_policy_attachment" "IAMSelfManageServiceSpecificCredentials" { 
#   group      = "${aws_iam_group.developer.name}"
#   policy_arn = "arn:aws:iam::aws:policy/IAMSelfManageServiceSpecificCredentials"
# }

resource "aws_iam_group_policy_attachment" "DevelopersIAMUserChangePassword" {
  group      = "${aws_iam_group.developer.name}"
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}

resource "aws_iam_group_policy_attachment" "DevelopersIAMUserSSHKeys" {
  group      = "${aws_iam_group.developer.name}"
  policy_arn = "arn:aws:iam::aws:policy/IAMUserSSHKeys"
}

resource "aws_iam_group_policy_attachment" "AllowIndividualUserToManageTheirOwnKeys" {
  group      = "${aws_iam_group.developer.name}"
  policy_arn = "${aws_iam_policy.AllowIndividualUserToManageTheirOwnKeys.arn}"
}

resource "aws_iam_group_policy_attachment" "DevelopersAllowIndividualUserToManageTheirOwnMFA" {
  group      = "${aws_iam_group.developer.name}"
  policy_arn = "${aws_iam_policy.AllowIndividualUserToManageTheirOwnMFA.arn}"
}

resource "aws_iam_group_policy_attachment" "DevelopersAllowS3IfMfa" {
  group      = "${aws_iam_group.developer.name}"
  policy_arn = "${aws_iam_policy.AllowS3IfMfa.arn}"
}

resource "aws_iam_group_policy_attachment" "DevelopersAllowEC2IfMfa" {
  group      = "${aws_iam_group.developer.name}"
  policy_arn = "${aws_iam_policy.AllowEC2IfMfa.arn}"
}

# admin group policy-attachments

resource "aws_iam_group_policy_attachment" "AssumeRoleToAdmin" {
  group      = "${aws_iam_group.admin.name}"
  policy_arn = "${aws_iam_policy.AssumeRoleToAdmin.arn}"
}

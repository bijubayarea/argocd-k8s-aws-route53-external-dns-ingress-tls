data "aws_iam_policy_document" "role" {

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${local.issuer_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${local.serviceaccount}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.issuer_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    principals {
      # OIDC Provider ARN is the principal
      #identifiers = ["arn:aws:iam::${var.aws_account_id}:oidc-provider/${var.issuer_url}"]
      identifiers = ["${local.issuer_arn}"]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "role" {

  assume_role_policy = data.aws_iam_policy_document.role.json
  name               = "${local.cluster}-${local.serviceaccount}-role"
}


data "aws_iam_policy_document" "route53_policy" {
  statement {
    actions = [
      "route53:ChangeResourceRecordSets",
    ]

    resources = [
      "arn:aws:route53:::hostedzone/*",
    ]
  }

  statement {
    actions = [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets"
    ]

    resources = [
      "*"
    ]
  }

}


resource "aws_iam_policy" "policy" {

  name   = "${local.cluster}-${local.serviceaccount}-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.route53_policy.json
}

resource "aws_iam_role_policy_attachment" "attach" {

  policy_arn = aws_iam_policy.policy.arn
  role       = aws_iam_role.role.name
}

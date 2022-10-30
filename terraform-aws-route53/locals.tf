
locals {
  cluster           = data.aws_eks_cluster.cluster.name
}

locals {
  issuer_arn        = data.aws_iam_openid_connect_provider.eks_oidc_provider.arn
}

locals  {
  issuer_url        = replace(data.aws_iam_openid_connect_provider.eks_oidc_provider.url, "https://", "")
}

locals  {
  iam_role          = aws_iam_role.role.arn
}


/*varaiabl "issuer_arn" {
  description = "EKS cluster OIDC ARN"
  type        = string
  default     = data.aws_iam_openid_connect_provider.eks_oidc_provider.arn
}

variable "issuer_url" {
  description = "EKS cluster OIDC ARN"
  type        = string
  default     = replace(data.aws_iam_openid_connect_provider.eks_oidc_provider.url, "https://", "")
}*/

#variable "iam_role" {
#  description = "iam role"
#  type        = string
#  default     = aws_iam_role.role[0].arn
#}

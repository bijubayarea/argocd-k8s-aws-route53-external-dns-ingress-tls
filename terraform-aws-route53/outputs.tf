output "namespace" {
  description = "The name of the related namespace"
  value       = var.namespace
}

output "serviceaccount" {
  description = "The name of the related serviceaccount"
  value       = local.serviceaccount
}

output "iam_role" {
  description = "The name of finegrained IAM role created"
  value       = aws_iam_role.role.arn
}


output "cluster_name" {
  description = "EKS Cluster Name"
  value       = data.aws_eks_cluster.cluster.name
}

output "oidc_provider_url" {
  description = "oidc provider url"
  #value       =  data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  value       =  replace(data.aws_iam_openid_connect_provider.eks_oidc_provider.url, "https://", "")
}

output "oidc_provider_arn" {
  description = "oidc provider arn"
  value       =  data.aws_iam_openid_connect_provider.eks_oidc_provider.arn
}


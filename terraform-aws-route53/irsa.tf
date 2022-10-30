resource "kubernetes_namespace" "ns" {

  metadata {
    labels = {
      name = var.namespace
    }
    name = var.namespace
  }
}

locals {
  serviceaccount = var.serviceaccount != "" ? var.serviceaccount : var.namespace
}

resource "kubernetes_service_account" "sa" {
  depends_on = [kubernetes_namespace.ns]
  automount_service_account_token = true

  metadata {
    name      = local.serviceaccount
    namespace = var.namespace

    annotations = {
      #"eks.amazonaws.com/role-arn" = "arn:aws:iam::${var.aws_account_id}:role/${var.cluster}-${local.serviceaccount}-role"
      "eks.amazonaws.com/role-arn" = "${local.iam_role}"
    }
  }

  lifecycle {
    ignore_changes = [
      metadata[0].labels,
    ]
  }
}

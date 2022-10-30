variable "namespace" {
  description = "Name of Kubernetes namespace"
  type        = string 
  default     = "external-dns"
}

variable "serviceaccount" {
  description = "Name of Kubernetes serviceaccount"
  type        = string
  default     = "external-dns"
}


variable "create_namespace" {
  description = "Enables creating the namespace"
  type        = bool
  default     = true
}


variable "policy" {
  description = "Policy json to apply to the irsa role"
  type        = string
  default     = ""
}


#######

variable "region" {
  description = "AWS Region"
  type        = string
  default     = "us-west-2"
}

/*
#SET THESE ROLES TO YOUR TERRAFORM ROLES PER ACCOUNT
variable "role_arn" {
  description = "Role ARN"
  type        = map(string)

  default = {
    test = "arn:aws:iam::<account_id>:role/devops"
    stg  = "arn:aws:iam::<account_id>:role/devops"
    prd  = "arn:aws:iam::<account_id>:role/devops"
  }
}

#SET THESE TO YOUR AWS ACCOUNT ID
variable "aws_account_id" {
  description = "Account ID"
  type        = map(string)

  default = {
    test = "<account_id>"
    stg  = "<account_id>"
    prd  = "<account_id>"
  }
}

variable "env" {
  description = "Environment"
  type        = string
  default     = "test"
}

variable "name" {
  description = "Name to be used"
  type        = string
  default     = "aws-vpc"
}
*/

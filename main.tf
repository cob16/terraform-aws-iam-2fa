provider "aws" {
  region = "eu-west-2"
}

terraform {
  backend "remote" {}
}

module "label" {
  source  = "cloudposse/label/terraform"
  version = "0.4.0"

  namespace = "cob16"
  stage     = terraform.workspace
  name      = "2fa"
}

module "iam" {
  source = "./iam"

  group_name_prefix = module.label.id
}

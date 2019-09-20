provider "aws" {
  region = "eu-west-2"
}

terraform {
  backend "remote" {}
}

module "iam" {
  source = "./iam"
}


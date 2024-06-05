provider "aws" {
  region = var.region

  default_tags {
    tags = {
      CreatedBy = "Terraform"
      Owner = var.owner
      Project = var.project
      Enviroment = var.enviroment
    }
  }
}

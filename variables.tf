variable "region" {
  description = "AWS region"
  type        = string
}

variable "enviroment" {
  description = "Enviroment tag for AWS resource"
  type        = string
}

variable "owner" {
  description = "Owner tag for AWS resource"
  type        = string
}

variable "project" {
    description = "Project name"
    type = string
}

variable "launch_template_instance_type" {
    description = "EC2 instance type for launch template"
    type = string
}

variable "cidr_block_igw" {
  description = "CIDR block of IGW"
  type = string
}

variable "enable_dns_support" {
  description = "enable_dns_support"
  type = bool
}

variable "enable_dns_hostnames" {
  description = "enable_dns_hostnames"
  type = bool
}

variable "vpc_name" {
    description = "VPC Name for Dev env"
    type = string
}

variable "public_route_table_name" {
    description = "Public-RouteTable Name for Dev env"
    type = string
}

variable "private_route_table_name" {
    description = "Private-RouteTable Name for Dev env"
    type = string
}

variable "public_subnet_name" {
    description = "Public subnet Name for Dev env"
    type = string
}

variable "private_subnet_name" {
    description = "Private subnet Name for Dev env"
    type = string
}

variable "vpc_cidr_block" {
    description = "VPC CIDR block"
    type = string
}

variable "public_subnet_1A_cidr_block" {
    description = "Public subnet 1A CIDR block"
    type = string
}

variable "public_subnet_1B_cidr_block" {
    description = "Public subnet 1B CIDR block"
    type = string
}

variable "private_subnet_1A_cidr_block" {
    description = "Private subnet 1A CIDR block"
    type = string
}

variable "private_subnet_1B_cidr_block" {
    description = "Private subnet 1B CIDR block"
    type = string
}

variable "eks_cluster_name" {
    description = "EKS cluster name"
    type = string
}

variable "eks_cluster_role_name" {
    description = "EKS cluster role name"
    type = string
}

variable "eks_policy_arn" {
    description = "EKS cluster policy arn"
    type = string
}
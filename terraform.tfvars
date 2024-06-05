# TAG input value
region = "ap-south-1"
owner = "Rushikesh"
project = "Terra POC"
enviroment = "Dev"

launch_template_instance_type = "t3a.nano"

#VPC input value
vpc_name = "TerraformVPC"
vpc_cidr_block = "10.0.0.0/16"
cidr_block_igw = "0.0.0.0/0"
public_subnet_1A_cidr_block = "10.0.1.0/24"
public_subnet_1B_cidr_block = "10.0.4.0/24"
private_subnet_1A_cidr_block = "10.0.2.0/24"
private_subnet_1B_cidr_block = "10.0.3.0/24"
enable_dns_support = true
enable_dns_hostnames = true
public_route_table_name = "PublicRouteTable"
private_route_table_name = "PrivateRouteTable"
public_subnet_name = "PublicSubnet"
private_subnet_name = "PriavteSubnet"

#eks input
eks_cluster_name = "TerraEKSCluster"
eks_cluster_role_name = "eks-cluster-role"
eks_policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
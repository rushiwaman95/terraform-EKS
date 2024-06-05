
#Get all available AZ's in VPC for master region
data "aws_availability_zones" "azs" {
  state = "available"
}


#Get main route table to modify
data "aws_route_table" "main_route_table" {
  filter {
    name   = "association.main"
    values = ["true"]
  }
  filter {
    name   = "vpc-id"
    values = [aws_vpc.vpc.id]
  }
}

#Create VPC in ap-south-1
resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames
  tags = {
    Name = var.vpc_name
  }
}

#Create IGW in ap-south-1
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
}

#Creating an Elastic IP for the NAT Gateway!
resource "aws_eip" "Nat_Gateway_EIP" {
  domain = "vpc"
}

# Creating a NAT Gateway!
resource "aws_nat_gateway" "NAT_GATEWAY" {
  depends_on = [
    aws_eip.Nat_Gateway_EIP
  ]
  # Allocating the Elastic IP to the NAT Gateway!
  allocation_id = aws_eip.Nat_Gateway_EIP.id
 
  # Associating it in the Public Subnet!
  subnet_id = aws_subnet.public-subnet.id
  tags = {
    Name = "Terra-NAT-Gateway"
  }
}


#RouteTable-Public
resource "aws_default_route_table" "Public-RouteTable" {
  default_route_table_id = data.aws_route_table.main_route_table.id
  route {
    cidr_block = var.cidr_block_igw
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = var.public_route_table_name
  }
}

#RouteTable-Private
resource "aws_route_table" "Private-RouteTable" {
  vpc_id = aws_vpc.vpc.id
  route {
    //associated subnet can reach everywhere uncoment when you want to create NAT or ther gateway.
    cidr_block = "0.0.0.0/0" //CRT uses this IGW to reach internet
    gateway_id = aws_nat_gateway.NAT_GATEWAY.id
  }
  tags = {
    Name = var.private_route_table_name
  }
}

#Create subnet Public AZ a in ap-south-1
resource "aws_subnet" "public-subnet" {
  availability_zone = element(data.aws_availability_zones.azs.names, 0)
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.public_subnet_1A_cidr_block
  tags = {
    Name = "${var.public_subnet_name}-1A"
  }
}

#Create subnet Public AZ b in ap-south-1
resource "aws_subnet" "public-subnet-b" {
  availability_zone = element(data.aws_availability_zones.azs.names, 1)
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "${var.public_subnet_1B_cidr_block}"
  tags = {
    Name = "${var.public_subnet_name}-1B"
  }
}

#Create subnet Private 1a in ap-south-1
resource "aws_subnet" "private-subnet" {
  vpc_id     = aws_vpc.vpc.id
  availability_zone = element(data.aws_availability_zones.azs.names, 0)
  cidr_block = var.private_subnet_1A_cidr_block
  tags = {
    Name = "${var.private_subnet_name}-1A"
  }
}

#Create subnet Private 1b in ap-south-1
resource "aws_subnet" "private-subnet-b" {
  vpc_id     = aws_vpc.vpc.id
  availability_zone = element(data.aws_availability_zones.azs.names, 1)
  cidr_block = var.private_subnet_1B_cidr_block
  tags = {
    Name = "${var.private_subnet_name}-1B"
  }
}

# Associate Private Subnet 1A with Private Route Table
resource "aws_route_table_association" "private_association_1a" {
  subnet_id      = aws_subnet.private-subnet.id
  route_table_id = aws_route_table.Private-RouteTable.id
}

# Associate Private Subnet 1B with Private Route Table
resource "aws_route_table_association" "private_association_1b" {
  subnet_id      = aws_subnet.private-subnet-b.id
  route_table_id = aws_route_table.Private-RouteTable.id
}

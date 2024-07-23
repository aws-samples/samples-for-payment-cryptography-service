# Create a VPC endpoint for Systems Manager
resource "aws_vpc_endpoint" "ssm_endpoint" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ssm"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.ssm_endpoint_sg.id,
  ]

  private_dns_enabled = true
  subnet_ids          = var.subnet_ids

  tags = {
    Name = "${var.application}-ssm-endpoint"
  }
}

resource "aws_vpc_endpoint" "ec2messages_endpoint" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.ssm_endpoint_sg.id,
  ]

  private_dns_enabled = true
  subnet_ids          = var.subnet_ids

  tags = {
    Name = "${var.application}-ssm-endpoint"
  }
}

resource "aws_vpc_endpoint" "ssmmessages_endpoint" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.ssm_endpoint_sg.id,
  ]

  private_dns_enabled = true
  subnet_ids          = var.subnet_ids

  tags = {
    Name = "${var.application}-ssm-endpoint"
  }
}

# Security group for the VPC endpoint
resource "aws_security_group" "ssm_endpoint_sg" {
  name_prefix = "${var.application}-ssm-endpoint-sg-"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.vpc_cidr_block
  }
  tags = {
    Name = "${var.application}-ssm-endpoint-sg"
  }
}

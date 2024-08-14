## SG For Endpoints
resource "aws_security_group" "this" {
  name_prefix = "payment-crypto-endpoint-"
  vpc_id      = var.vpc_id
  description = "Payment Cryptography Endpoint Security Group"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.vpc_cidr_block
    description = "Allow HTTPS traffic from VPC CIDR Block"

  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = ["${aws_security_group.thissg.id}"] # SG For instance
    description     = "Allow HTTPS traffic from EC2 instance Security Group"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.1.0/24"]
    description = "Allow all outbound traffic"

  }

  tags = {
    Name = "Payment Cryptography Endpoint Security Group"
  }
}

# Payment Cryptography Control Plane
resource "aws_vpc_endpoint" "thiscp" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.payment-cryptography.controlplane"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.this.id,
  ]

  subnet_ids = var.subnet_ids

  private_dns_enabled = true
}

# Payment Cryptography Data Plane
resource "aws_vpc_endpoint" "thisdp" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.payment-cryptography.dataplane"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.this.id,
  ]

  subnet_ids = var.subnet_ids

  private_dns_enabled = true
}

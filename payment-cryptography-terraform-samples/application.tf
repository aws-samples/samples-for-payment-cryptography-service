# Create a security group
# tfsec:ignore:AWS001
resource "aws_security_group" "thissg" {
  name_prefix = "${var.application}-security-group"
  vpc_id      = var.vpc_id
  description = "Security Group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.168.1.0/24"] # tfsec:ignore:AWS001 # Replace with your desired IP range
    description = "Allow SSH access from within the VPC"
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ssm_endpoint_sg.id]
    description     = "Allow HTTPS access from the SSM endpoint security group"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.1.0/24"] # tfsec:ignore:AWS001
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.application}-security-group"
  }
}

# Create an EC2 instance in a private subnet
resource "aws_instance" "thisinstance" {
  ami           = var.ami_id
  instance_type = var.instance_type

  subnet_id                   = var.subnet_ids[0] # Selected one of the subnets for testing purposes
  vpc_security_group_ids      = [aws_security_group.thissg.id]
  iam_instance_profile        = aws_iam_instance_profile.ssm_profile.name
  key_name                    = var.key_name
  associate_public_ip_address = false # No public IP for a private subnet

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
  }

  tags = {
    Name = "${var.application}-app-instance"
  }
  monitoring = true
  user_data  = <<-EOF
  #!/bin/bash
  # Install the latest SSM Agent
  mkdir /tmp/ssm
  cd /tmp/ssm
  sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
  systemctl enable amazon-ssm-agent
  systemctl start amazon-ssm-agent
  EOF
}

resource "aws_iam_instance_profile" "ssm_profile" {
  name = "SSMInstanceProfile_app_${var.application}"
  role = aws_iam_role.ssm_role.name
}

resource "aws_iam_role" "ssm_role" {
  name               = "SSMRole_app_${var.application}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = data.aws_iam_policy.ssm_managed_instance.arn
}

resource "aws_iam_role_policy_attachment" "payment_instance" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = aws_iam_policy.payment_cryptography_policy.arn
}

resource "aws_iam_policy" "payment_cryptography_policy" {
  name        = "PaymentCryptographyPolicy"
  description = "Policy for Payment Cryptography service and EC2 network interface management"
  policy      = data.aws_iam_policy_document.payment_cryptography_policy.json
}

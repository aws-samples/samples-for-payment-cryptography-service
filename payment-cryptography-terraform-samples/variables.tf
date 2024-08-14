## Networking variables

variable "vpc_id" {
  type        = string
  description = "Customers can pass the vpc_id here"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Eligible Subnets"
}

variable "vpc_cidr_block" {
  type        = list(string)
  description = "Eligible CIDR ranges"
}

## Log Archive variables

variable "s3_name" {
  type        = string
  description = "S3 Bucket name for APC Log Archive"
}

variable "trail_name" {
  type        = string
  description = "Trail name for APC Log Archive"
}

variable "trail_prefix" {
  type        = string
  description = "Trail prefix name for APC Log Archive"
}

## EC2 Instance variables

variable "key_name" {
  description = "Name of the EC2 key pair"
  type        = string
}

variable "application" {
  description = "Name of the application"
  type        = string
}

variable "ami_id" {
  description = "The ID of the Amazon Machine Image (AMI) to use for the EC2 instance"
  type        = string
}

variable "instance_type" {
  description = "The type of EC2 instance to launch"
  type        = string
  default     = "t2.micro"
}

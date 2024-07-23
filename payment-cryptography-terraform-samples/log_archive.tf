# tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "apc_trails_s3_bucket" {
  bucket        = var.s3_name
  force_destroy = true

}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.apc_trails_s3_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.apc_trails_s3_bucket.id

  ignore_public_acls      = true
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "apc_trails_s3_bucket" {
  bucket = aws_s3_bucket.apc_trails_s3_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_bucket_policy" {
  bucket = aws_s3_bucket.apc_trails_s3_bucket.id
  policy = data.aws_iam_policy_document.s3_iam_policy_document.json
}

# tfsec:ignore:aws-cloudtrail-enable-at-rest-encryption
# tfsec:ignore:aws-cloudtrail-ensure-cloudwatch-integration
resource "aws_cloudtrail" "apc_trails" {
  depends_on = [aws_s3_bucket_policy.s3_bucket_policy]

  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.apc_trails_s3_bucket.id
  s3_key_prefix                 = var.trail_prefix
  include_global_service_events = false
  enable_log_file_validation    = true
  is_multi_region_trail         = true
}
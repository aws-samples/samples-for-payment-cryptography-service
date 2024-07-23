resource "aws_s3_bucket" "apc_trails_s3_bucket" {
  bucket        = var.s3_name
  force_destroy = true
}

resource "aws_s3_bucket_policy" "s3_bucket_policy" {
  bucket = aws_s3_bucket.apc_trails_s3_bucket.id
  policy = data.aws_iam_policy_document.s3_iam_policy_document.json
}

resource "aws_cloudtrail" "apc_trails" {
  depends_on = [aws_s3_bucket_policy.s3_bucket_policy]

  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.apc_trails_s3_bucket.id
  s3_key_prefix                 = var.trail_prefix
  include_global_service_events = false
}
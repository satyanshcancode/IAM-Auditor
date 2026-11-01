# S3 Bucket for Security Audit Artifact Storage
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "audit_reports" {
  bucket        = "iam-auditor-reports-${random_id.bucket_suffix.hex}"
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

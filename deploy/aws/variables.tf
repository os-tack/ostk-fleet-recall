variable "aws_region" {
  description = "AWS region for the ECS deployment and model bucket."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "DNS- and IAM-safe deployment name."
  type        = string
  default     = "ostk-fleet-recall"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,31}$", var.name))
    error_message = "name must be 3-32 lowercase alphanumeric or hyphen characters."
  }
}

variable "vpc_id" {
  description = "Existing VPC containing the load balancer and ECS task subnets."
  type        = string
}

variable "alb_subnet_ids" {
  description = "At least two public subnet IDs in distinct availability zones."
  type        = list(string)

  validation {
    condition     = length(var.alb_subnet_ids) >= 2
    error_message = "alb_subnet_ids must contain at least two subnets."
  }
}

variable "task_subnet_ids" {
  description = "At least two private task subnet IDs with NAT or the required VPC endpoints."
  type        = list(string)

  validation {
    condition     = length(var.task_subnet_ids) >= 2
    error_message = "task_subnet_ids must contain at least two subnets."
  }
}

variable "assign_public_ip" {
  description = "Assign public IPs to tasks. Keep false for private subnets behind NAT."
  type        = bool
  default     = false
}

variable "alb_ingress_cidrs" {
  description = "IPv4 networks allowed to reach the ALB when CloudFront is disabled."
  type        = list(string)
  default     = []

  validation {
    condition     = var.enable_cloudfront || length(var.alb_ingress_cidrs) > 0
    error_message = "alb_ingress_cidrs must contain at least one IPv4 network when enable_cloudfront is false."
  }

  validation {
    condition     = alltrue([for cidr in var.alb_ingress_cidrs : can(cidrnetmask(cidr))])
    error_message = "alb_ingress_cidrs must contain only valid IPv4 CIDR networks."
  }
}

variable "enable_cloudfront" {
  description = "Put the ALB behind an HTTPS-only CloudFront distribution using its default cloudfront.net certificate."
  type        = bool
  default     = true

  validation {
    condition     = !var.enable_cloudfront || var.certificate_arn == null
    error_message = "enable_cloudfront and certificate_arn are mutually exclusive; use either the CloudFront front door or direct ALB TLS."
  }
}

variable "certificate_arn" {
  description = "Optional ALB ACM certificate ARN. When set without CloudFront, HTTP redirects to HTTPS."
  type        = string
  default     = null
  nullable    = true
}

variable "demo_hostname" {
  description = "Public DNS hostname covered by certificate_arn. Required when direct ALB TLS is enabled."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.demo_hostname == null || (
      length(var.demo_hostname) <= 253 && can(regex(
        "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$",
        var.demo_hostname,
      ))
    )
    error_message = "demo_hostname must be a fully qualified DNS hostname without a scheme or path."
  }
}

variable "database_url_secret_arn" {
  description = "Secrets Manager ARN whose raw value is the TLS CockroachDB runtime URL."
  type        = string
  sensitive   = true

  validation {
    condition = can(regex(
      "^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$",
      var.database_url_secret_arn,
    )) && !strcontains(var.database_url_secret_arn, "*")
    error_message = "database_url_secret_arn must be one concrete commercial-partition Secrets Manager ARN without wildcards."
  }
}

variable "migration_database_url_secret_arn" {
  description = "Required ARN for a DDL-capable URL that is distinct from the runtime secret."
  type        = string
  sensitive   = true

  validation {
    condition = (
      can(regex(
        "^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$",
        var.migration_database_url_secret_arn,
      )) &&
      !strcontains(var.migration_database_url_secret_arn, "*") &&
      var.migration_database_url_secret_arn != var.database_url_secret_arn
    )
    error_message = "migration_database_url_secret_arn must be one concrete commercial-partition Secrets Manager ARN, without wildcards, and distinct from database_url_secret_arn."
  }
}

variable "database_secret_kms_key_arns" {
  description = "Customer-managed KMS key ARNs used by either database secret."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.database_secret_kms_key_arns :
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$", arn)) &&
      !strcontains(arn, "*")
    ])
    error_message = "database_secret_kms_key_arns must contain only concrete commercial-partition KMS key ARNs without aliases or wildcards."
  }
}

variable "tenant_id" {
  description = "Trusted fleet tenant UUID bound by the deployment."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.tenant_id))
    error_message = "tenant_id must be a UUID."
  }
}

variable "project" {
  description = "Trusted project namespace bound by the deployment."
  type        = string
  default     = "hackathon-demo"
}

variable "agent" {
  description = "Trusted actor name used by the public read-only demo service."
  type        = string
  default     = "demo-http"
}

variable "max_database_connections" {
  description = "Maximum CockroachDB connections per task. Multiply by the maximum task count."
  type        = number
  default     = 8

  validation {
    condition     = var.max_database_connections >= 1 && var.max_database_connections <= 64
    error_message = "max_database_connections must be between 1 and 64."
  }
}

variable "embedding_model" {
  description = "Stable logical model name; no runtime registry lookup is performed."
  type        = string
  default     = "minishlab/potion-retrieval-32M"
}

variable "embedding_model_sha256" {
  description = "Versioned bundle digest printed by ostk-fleet-recall model-digest."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.embedding_model_sha256))
    error_message = "embedding_model_sha256 must contain 64 hexadecimal characters."
  }
}

variable "model_bucket_arn" {
  description = "ARN of the existing private S3 bucket that stores the model bundle."
  type        = string

  validation {
    condition = can(regex(
      "^arn:aws:s3:::[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?$",
      var.model_bucket_arn,
    )) && !can(regex("[.][.]", trimprefix(var.model_bucket_arn, "arn:aws:s3:::")))
    error_message = "model_bucket_arn must be a standard-partition ARN for a valid 3-63 character general-purpose S3 bucket name, without an object suffix."
  }
}

variable "model_object_prefix" {
  description = "S3 prefix containing config.json, model.safetensors, and tokenizer.json."
  type        = string
  default     = "models/potion-retrieval-32M"

  validation {
    condition = (
      length(trim(var.model_object_prefix, "/")) > 0 &&
      !can(regex("(^|/)[.][.](/|$)", var.model_object_prefix)) &&
      length(regexall("[?*\\\\]", var.model_object_prefix)) == 0 &&
      length(regexall("[[:cntrl:]]", var.model_object_prefix)) == 0
    )
    error_message = "model_object_prefix must be non-empty and cannot contain '..', IAM wildcards, backslashes, or control characters."
  }
}

variable "image_tag" {
  description = "ECR image tag. Use an immutable commit SHA or release tag."
  type        = string
  default     = "hackathon"

  validation {
    condition     = can(regex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", var.image_tag))
    error_message = "image_tag is not a valid OCI tag."
  }
}

variable "cpu_architecture" {
  description = "Fargate CPU architecture used by the pushed image."
  type        = string
  default     = "X86_64"

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be X86_64 or ARM64."
  }
}

variable "task_cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 4096
}

variable "ephemeral_storage_gib" {
  description = "Fargate ephemeral storage for the verified model download and runtime."
  type        = number
  default     = 21

  validation {
    condition     = var.ephemeral_storage_gib >= 21 && var.ephemeral_storage_gib <= 200
    error_message = "ephemeral_storage_gib must be between 21 and 200."
  }
}

variable "service_desired_count" {
  description = "Initial demo task count. Keep zero until the one-off migration succeeds."
  type        = number
  default     = 0

  validation {
    condition     = var.service_desired_count >= 0
    error_message = "service_desired_count cannot be negative."
  }
}

variable "autoscaling_min_capacity" {
  description = "Minimum demo tasks. Keep zero until the one-off migration succeeds."
  type        = number
  default     = 0
}

variable "autoscaling_max_capacity" {
  description = "Maximum demo tasks."
  type        = number
  default     = 2
}

variable "autoscaling_cpu_target" {
  description = "Target average CPU percentage for ECS target tracking."
  type        = number
  default     = 65
}

variable "log_retention_days" {
  description = "CloudWatch application log retention; the 60-day default preserves judging evidence."
  type        = number
  default     = 60

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731,
      1096, 1827, 2192, 2557, 2922, 3288, 3653,
    ], var.log_retention_days)
    error_message = "log_retention_days must be a retention period supported by CloudWatch Logs."
  }
}

variable "enable_container_insights" {
  description = "Enable ECS Container Insights for the cluster."
  type        = bool
  default     = true
}

variable "enable_deletion_protection" {
  description = "Protect the public ALB from accidental deletion during the judging window."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags applied through the AWS provider."
  type        = map(string)
  default     = {}
}

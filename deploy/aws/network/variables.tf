variable "aws_region" {
  description = "AWS region containing the existing VPC and public NAT subnet."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name prefix and Application tag for the managed network resources."
  type        = string
  default     = "ostk-fleet-recall"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,31}$", var.name))
    error_message = "name must be 3-32 lowercase alphanumeric or hyphen characters."
  }
}

variable "vpc_id" {
  description = "Existing VPC that will contain the private task subnets."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must be an AWS VPC ID."
  }
}

variable "nat_public_subnet_id" {
  description = "Existing public subnet in which to create the single public NAT gateway."
  type        = string

  validation {
    condition     = can(regex("^subnet-[0-9a-f]+$", var.nat_public_subnet_id))
    error_message = "nat_public_subnet_id must be an AWS subnet ID."
  }
}

variable "private_subnets" {
  description = "Two or more private task subnets keyed by a stable short name."
  type = map(object({
    availability_zone = string
    cidr_block        = string
  }))

  validation {
    condition = (
      length(var.private_subnets) >= 2 &&
      length(distinct([for subnet in values(var.private_subnets) : subnet.availability_zone])) == length(var.private_subnets) &&
      length(distinct([for subnet in values(var.private_subnets) : subnet.cidr_block])) == length(var.private_subnets) &&
      alltrue([for subnet in values(var.private_subnets) : can(cidrhost(subnet.cidr_block, 0))])
    )
    error_message = "private_subnets must contain at least two valid, distinct CIDRs in distinct availability zones."
  }
}

variable "hold_until" {
  description = "UTC timestamp before which judging infrastructure must not be destroyed."
  type        = string
  default     = "2026-09-15T21:00:00Z"

  validation {
    condition     = can(timecmp(var.hold_until, "2026-09-15T21:00:00Z")) && timecmp(var.hold_until, "2026-09-15T21:00:00Z") >= 0
    error_message = "hold_until must be RFC3339 and no earlier than the judging deadline."
  }
}

variable "tags" {
  description = "Additional tags applied through the AWS provider."
  type        = map(string)
  default     = {}
}

mock_provider "aws" {
  override_during = plan

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_data "aws_ec2_managed_prefix_list" {
    defaults = {
      id = "pl-cloudfront-origin-facing"
    }
  }

  mock_resource "aws_ecr_repository" {
    defaults = {
      repository_url = "123456789012.dkr.ecr.us-east-1.amazonaws.com/ostk-fleet-recall-test"
    }
  }

  mock_resource "aws_cloudfront_distribution" {
    defaults = {
      id          = "EDFDVBD6EXAMPLE"
      domain_name = "d111111abcdef8.cloudfront.net"
    }
  }
}

mock_provider "random" {
  override_during = plan

  mock_resource "random_password" {
    defaults = {
      result = "mock-origin-header-value-with-48-safe-characters-000"
    }
  }
}

variables {
  aws_region = "us-east-1"
  name       = "ostk-fleet-recall-test"

  vpc_id          = "vpc-0123456789abcdef0"
  alb_subnet_ids  = ["subnet-aaaaaaaaaaaaaaaaa", "subnet-bbbbbbbbbbbbbbbbb"]
  task_subnet_ids = ["subnet-ccccccccccccccccc", "subnet-ddddddddddddddddd"]

  database_url_secret_arn           = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-runtime-AbCdEf"
  migration_database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-migrator-GhIjKl"

  tenant_id = "0198a849-f6ae-7d61-9800-000000000001"
  project   = "terraform-test"
  agent     = "terraform-test"

  embedding_model_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  model_bucket_arn       = "arn:aws:s3:::fleet-recall-test-models"
  model_object_prefix    = "models/potion-retrieval-32M/release-1"
  image_tag              = "git-0123456789ab"
}

run "dormant_http_bootstrap" {
  command = plan

  assert {
    condition     = aws_ecs_service.app.desired_count == 0
    error_message = "the service must default to dormant before the first migration"
  }

  assert {
    condition = (
      aws_cloudwatch_log_group.app.retention_in_days == 60 &&
      aws_lb.app.enable_deletion_protection
    )
    error_message = "submission defaults must retain evidence and protect the public endpoint through judging"
  }

  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.reference_agent.container_definitions)[0].command ==
      ["reference-agent", "--step", "record-decision", "--run-id", "terraform-placeholder"]
    )
    error_message = "the one-off reference-agent task must default to the safe writer step"
  }

  assert {
    condition = (
      [for entry in jsondecode(aws_ecs_task_definition.reference_agent.container_definitions)[0].environment : entry.value if entry.name == "FLEET_RECALL_AGENT"] ==
      ["agent-a"]
    )
    error_message = "the reference-agent task default must be deployment-bound to agent-a"
  }

  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.reference_agent.container_definitions)[0].secrets[0].valueFrom ==
      var.database_url_secret_arn
    )
    error_message = "the reference agent must use the runtime DML credential"
  }

  assert {
    condition     = aws_appautoscaling_target.app.min_capacity == 0
    error_message = "autoscaling must not race the first migration"
  }

  assert {
    condition     = local.app_command == ["demo", "--listen", "0.0.0.0:8080"]
    error_message = "the ECS command must match the tested demo CLI contract"
  }

  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.seed.container_definitions)[0].command ==
      ["ingest", "--input", "/opt/ostk/demo/demo.ndjson"]
    )
    error_message = "the one-off seed task must ingest the immutable demo corpus bundled in the image"
  }

  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.seed.container_definitions)[0].secrets[0].valueFrom ==
      var.database_url_secret_arn
    )
    error_message = "the seed task must use the runtime DML credential, never the migration credential"
  }

  assert {
    condition = local.model_object_arns == [
      "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/config.json",
      "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/model.safetensors",
      "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/tokenizer.json",
    ]
    error_message = "the task role must target exactly the three runtime model files"
  }

  assert {
    condition     = startswith(output.demo_url, "http://")
    error_message = "a certificate-free bootstrap must advertise HTTP, not false TLS"
  }

  assert {
    condition = (
      length(aws_cloudfront_distribution.app) == 0 &&
      output.cloudfront_distribution_id == null &&
      aws_lb_listener.http[0].default_action[0].type == "forward"
    )
    error_message = "the default direct mode must preserve the existing forwarding HTTP listener without CloudFront"
  }
}

run "tls_uses_certificate_hostname" {
  command = plan

  variables {
    certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000001"
    demo_hostname   = "recall.example.com"
  }

  assert {
    condition     = output.demo_url == "https://recall.example.com"
    error_message = "TLS output must use the certificate-covered hostname, not the ALB hostname"
  }

  assert {
    condition = (
      length(aws_cloudfront_distribution.app) == 0 &&
      length(aws_lb_listener.https) == 1 &&
      aws_lb_listener.http_redirect[0].default_action[0].type == "redirect"
    )
    error_message = "the direct custom-ACM mode must remain available without creating CloudFront"
  }
}

run "cloudfront_https_front_door" {
  command = plan

  variables {
    enable_cloudfront = true
  }

  assert {
    condition = (
      output.demo_url == "https://d111111abcdef8.cloudfront.net" &&
      output.cloudfront_distribution_id == "EDFDVBD6EXAMPLE"
    )
    error_message = "CloudFront mode must advertise the generated HTTPS hostname and distribution ID"
  }

  assert {
    condition = (
      data.aws_ec2_managed_prefix_list.cloudfront_origin_facing[0].name == "com.amazonaws.global.cloudfront.origin-facing" &&
      length(aws_security_group.alb.ingress) == 1 &&
      toset(one(aws_security_group.alb.ingress).prefix_list_ids) == toset(["pl-cloudfront-origin-facing"]) &&
      one(aws_security_group.alb.ingress).cidr_blocks == null
    )
    error_message = "CloudFront mode must replace public ALB ingress with the AWS-managed origin-facing prefix list"
  }

  assert {
    condition = (
      aws_lb_listener.http[0].default_action[0].type == "fixed-response" &&
      aws_lb_listener.http[0].default_action[0].fixed_response[0].status_code == "403" &&
      aws_lb_listener_rule.cloudfront_origin[0].action[0].type == "forward" &&
      one(aws_lb_listener_rule.cloudfront_origin[0].condition).http_header[0].http_header_name == local.cloudfront_origin_header_name &&
      toset(one(aws_lb_listener_rule.cloudfront_origin[0].condition).http_header[0].values) == toset([random_password.cloudfront_origin[0].result])
    )
    error_message = "the ALB must deny requests by default and forward only the secret CloudFront origin header"
  }

  assert {
    condition = (
      random_password.cloudfront_origin[0].length == 48 &&
      !random_password.cloudfront_origin[0].special &&
      one(one(aws_cloudfront_distribution.app[0].origin).custom_header).name == local.cloudfront_origin_header_name &&
      one(one(aws_cloudfront_distribution.app[0].origin).custom_header).value == random_password.cloudfront_origin[0].result &&
      one(aws_cloudfront_distribution.app[0].origin).custom_origin_config[0].origin_protocol_policy == "http-only"
    )
    error_message = "CloudFront must use the generated secret header and HTTP-only ALB origin"
  }

  assert {
    condition = (
      aws_cloudfront_cache_policy.disabled[0].default_ttl == 0 &&
      aws_cloudfront_cache_policy.disabled[0].min_ttl == 0 &&
      aws_cloudfront_cache_policy.disabled[0].max_ttl == 0 &&
      aws_cloudfront_cache_policy.disabled[0].parameters_in_cache_key_and_forwarded_to_origin[0].cookies_config[0].cookie_behavior == "none" &&
      aws_cloudfront_cache_policy.disabled[0].parameters_in_cache_key_and_forwarded_to_origin[0].query_strings_config[0].query_string_behavior == "none" &&
      aws_cloudfront_origin_request_policy.minimal[0].cookies_config[0].cookie_behavior == "none" &&
      aws_cloudfront_origin_request_policy.minimal[0].query_strings_config[0].query_string_behavior == "none" &&
      aws_cloudfront_origin_request_policy.minimal[0].headers_config[0].header_behavior == "whitelist" &&
      toset(aws_cloudfront_origin_request_policy.minimal[0].headers_config[0].headers[0].items) == toset(["Content-Type"])
    )
    error_message = "CloudFront must disable caching and must not forward cookies, query strings, or authorization"
  }

  assert {
    condition = (
      toset(aws_cloudfront_distribution.app[0].default_cache_behavior[0].allowed_methods) == toset(["GET", "HEAD"]) &&
      aws_cloudfront_distribution.app[0].default_cache_behavior[0].viewer_protocol_policy == "https-only" &&
      aws_cloudfront_distribution.app[0].ordered_cache_behavior[0].path_pattern == "/api/recall" &&
      toset(aws_cloudfront_distribution.app[0].ordered_cache_behavior[0].allowed_methods) == toset(["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]) &&
      aws_cloudfront_distribution.app[0].ordered_cache_behavior[0].viewer_protocol_policy == "https-only" &&
      aws_cloudfront_distribution.app[0].viewer_certificate[0].cloudfront_default_certificate
    )
    error_message = "CloudFront must require HTTPS, expose only reads by default, and allow all methods only on /api/recall"
  }

  assert {
    condition = (
      aws_cloudfront_response_headers_policy.security[0].security_headers_config[0].content_type_options[0].override &&
      aws_cloudfront_response_headers_policy.security[0].security_headers_config[0].frame_options[0].frame_option == "DENY" &&
      aws_cloudfront_response_headers_policy.security[0].security_headers_config[0].strict_transport_security[0].access_control_max_age_sec == 63072000 &&
      one(aws_cloudfront_response_headers_policy.security[0].custom_headers_config[0].items).header == "Cache-Control" &&
      one(aws_cloudfront_response_headers_policy.security[0].custom_headers_config[0].items).value == "no-store, max-age=0" &&
      one(aws_cloudfront_response_headers_policy.security[0].custom_headers_config[0].items).override &&
      toset([for response in aws_cloudfront_distribution.app[0].custom_error_response : response.error_code]) == toset([500, 502, 503, 504]) &&
      alltrue([for response in aws_cloudfront_distribution.app[0].custom_error_response : response.error_caching_min_ttl == 0])
    )
    error_message = "CloudFront must add browser security headers and avoid caching transient origin errors"
  }
}

run "rejects_cloudfront_with_direct_alb_certificate" {
  command = plan

  variables {
    enable_cloudfront = true
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000001"
    demo_hostname     = "recall.example.com"
  }

  expect_failures = [var.enable_cloudfront]
}

run "rejects_iam_wildcards_in_model_prefix" {
  command = plan

  variables {
    model_object_prefix = "models/*"
  }

  expect_failures = [var.model_object_prefix]
}

run "rejects_wildcard_bucket_arn" {
  command = plan

  variables {
    model_bucket_arn = "arn:aws:s3:::*"
  }

  expect_failures = [var.model_bucket_arn]
}

run "rejects_nonstandard_bucket_partition" {
  command = plan

  variables {
    model_bucket_arn = "arn:aws-us-gov:s3:::fleet-recall-test-models"
  }

  expect_failures = [var.model_bucket_arn]
}

run "rejects_tls_without_hostname" {
  command = plan

  variables {
    certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000001"
  }

  expect_failures = [aws_lb_listener.https]
}

run "rejects_inverted_capacity" {
  command = plan

  variables {
    autoscaling_min_capacity = 3
    autoscaling_max_capacity = 2
  }

  expect_failures = [aws_appautoscaling_target.app]
}

run "rejects_unsupported_log_retention" {
  command = plan

  variables {
    log_retention_days = 61
  }

  expect_failures = [var.log_retention_days]
}

run "rejects_wildcard_database_secret" {
  command = plan

  variables {
    database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:*"
  }

  expect_failures = [var.database_url_secret_arn]
}

run "rejects_wildcard_migration_secret" {
  command = plan

  variables {
    migration_database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:*"
  }

  expect_failures = [var.migration_database_url_secret_arn]
}

run "rejects_wildcard_database_kms_key" {
  command = plan

  variables {
    database_secret_kms_key_arns = ["arn:aws:kms:us-east-1:123456789012:key/*"]
  }

  expect_failures = [var.database_secret_kms_key_arns]
}

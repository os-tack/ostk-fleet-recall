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

  assign_public_ip  = false
  alb_ingress_cidrs = []
  enable_cloudfront = true
  certificate_arn   = null
  demo_hostname     = null

  publication_database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-publication-MnOpQr"
  database_url_secret_arn             = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-writer-AbCdEf"
  migration_database_url_secret_arn   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-migrator-GhIjKl"
  publication_database_secret_kms_key_arns = [
    "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
    "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222",
  ]
  database_secret_kms_key_arns = [
    "arn:aws:kms:us-east-1:123456789012:key/33333333-3333-4333-8333-333333333333",
    "arn:aws:kms:us-east-1:123456789012:key/44444444-4444-4444-8444-444444444444",
  ]

  tenant_id                = "0198a849-f6ae-7d61-9800-000000000001"
  project                  = "terraform-test"
  agent                    = "terraform-test"
  max_database_connections = 8

  embedding_model        = "minishlab/potion-retrieval-32M"
  embedding_model_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  model_bucket_arn       = "arn:aws:s3:::fleet-recall-test-models"
  model_object_prefix    = "models/potion-retrieval-32M/release-1"
  image_tag              = "git-0123456789ab"

  cpu_architecture      = "X86_64"
  task_cpu              = 1024
  task_memory           = 4096
  ephemeral_storage_gib = 21

  service_desired_count      = 0
  autoscaling_min_capacity   = 0
  autoscaling_max_capacity   = 2
  autoscaling_cpu_target     = 65
  log_retention_days         = 60
  enable_container_insights  = true
  enable_deletion_protection = true
  tags                       = {}
}

run "dormant_cloudfront_bootstrap" {
  command = plan

  override_resource {
    target          = aws_iam_role.execution_publication
    override_during = plan
    values = {
      arn = "arn:aws:iam::123456789012:role/publication-execution"
      id  = "publication-execution"
    }
  }

  override_resource {
    target          = aws_iam_role.execution_runtime
    override_during = plan
    values = {
      arn = "arn:aws:iam::123456789012:role/runtime-execution"
      id  = "runtime-execution"
    }
  }

  override_resource {
    target          = aws_iam_role.execution_migration
    override_during = plan
    values = {
      arn = "arn:aws:iam::123456789012:role/migration-execution"
      id  = "migration-execution"
    }
  }

  override_resource {
    target          = aws_iam_role.task_publication
    override_during = plan
    values = {
      arn = "arn:aws:iam::123456789012:role/publication-task"
      id  = "publication-task"
    }
  }

  override_resource {
    target          = aws_iam_role.task
    override_during = plan
    values = {
      arn = "arn:aws:iam::123456789012:role/private-task"
      id  = "private-task"
    }
  }

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
      jsondecode(aws_ecs_task_definition.app.container_definitions)[0].secrets == [{
        name      = "FLEET_RECALL_PUBLICATION_DATABASE_URL"
        valueFrom = var.publication_database_url_secret_arn
      }] &&
      jsondecode(aws_ecs_task_definition.seed.container_definitions)[0].secrets == [{
        name      = "FLEET_RECALL_DATABASE_URL"
        valueFrom = var.database_url_secret_arn
      }] &&
      jsondecode(aws_ecs_task_definition.reference_agent.container_definitions)[0].secrets == [{
        name      = "FLEET_RECALL_DATABASE_URL"
        valueFrom = var.database_url_secret_arn
      }] &&
      jsondecode(aws_ecs_task_definition.migration.container_definitions)[0].secrets == [{
        name      = "FLEET_RECALL_DATABASE_URL"
        valueFrom = var.migration_database_url_secret_arn
      }]
    )
    error_message = "each task class must receive exactly its own database URL environment binding"
  }

  assert {
    condition = (
      aws_iam_role.execution_publication.name == "${var.name}-publication-execution" &&
      aws_iam_role.execution_runtime.name == "${var.name}-execution" &&
      aws_iam_role.execution_migration.name == "${var.name}-migration-execution" &&
      length(toset([
        aws_iam_role.execution_publication.name,
        aws_iam_role.execution_runtime.name,
        aws_iam_role.execution_migration.name,
      ])) == 3 &&
      aws_ecs_task_definition.app.execution_role_arn == aws_iam_role.execution_publication.arn &&
      aws_ecs_task_definition.seed.execution_role_arn == aws_iam_role.execution_runtime.arn &&
      aws_ecs_task_definition.reference_agent.execution_role_arn == aws_iam_role.execution_runtime.arn &&
      aws_ecs_task_definition.migration.execution_role_arn == aws_iam_role.execution_migration.arn
    )
    error_message = "publication, writer, and migration tasks must use isolated execution roles"
  }

  assert {
    condition = (
      aws_iam_role.task_publication.name == "${var.name}-publication-task" &&
      aws_iam_role.task.name == "${var.name}-task" &&
      aws_iam_role.task_publication.name != aws_iam_role.task.name &&
      aws_ecs_task_definition.app.task_role_arn == aws_iam_role.task_publication.arn &&
      aws_ecs_task_definition.seed.task_role_arn == aws_iam_role.task.arn &&
      aws_ecs_task_definition.reference_agent.task_role_arn == aws_iam_role.task.arn &&
      aws_ecs_task_definition.migration.task_role_arn == aws_iam_role.task.arn
    )
    error_message = "the publication app must have a distinct task role while private task-role flows remain unchanged"
  }

  assert {
    condition = (
      local.publication_database_secret_arns == [var.publication_database_url_secret_arn] &&
      local.runtime_database_secret_arns == [var.database_url_secret_arn] &&
      local.migration_database_secret_arns == [var.migration_database_url_secret_arn] &&
      length(toset(concat(
        local.publication_database_secret_arns,
        local.runtime_database_secret_arns,
        local.migration_database_secret_arns,
      ))) == 3 &&
      aws_iam_role_policy.publication_database_secret.role == aws_iam_role.execution_publication.id &&
      aws_iam_role_policy.runtime_database_secret.role == aws_iam_role.execution_runtime.id &&
      aws_iam_role_policy.migration_database_secret.role == aws_iam_role.execution_migration.id &&
      aws_iam_role_policy_attachment.execution_publication.role == aws_iam_role.execution_publication.name &&
      aws_iam_role_policy_attachment.execution_runtime.role == aws_iam_role.execution_runtime.name &&
      aws_iam_role_policy_attachment.execution_migration.role == aws_iam_role.execution_migration.name
    )
    error_message = "database-secret policies and ECS managed policies must have one exact execution-role edge each"
  }

  assert {
    condition = (
      jsondecode(nonsensitive(aws_iam_role_policy.publication_database_secret.policy)) == {
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "ReadPublicationDatabaseUrl"
            Effect   = "Allow"
            Action   = "secretsmanager:GetSecretValue"
            Resource = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-publication-MnOpQr"
          },
          {
            Sid    = "DecryptPublicationDatabaseSecret"
            Effect = "Allow"
            Action = "kms:Decrypt"
            Resource = [
              "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
              "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222",
            ]
            Condition = {
              StringEquals = {
                "kms:ViaService"                  = "secretsmanager.us-east-1.amazonaws.com"
                "kms:EncryptionContext:SecretARN" = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-publication-MnOpQr"
              }
            }
          },
        ]
      }
    )
    error_message = "the KMS-enabled publication policy must exactly bind its secret read and encryption-context-scoped decrypt"
  }

  assert {
    condition = (
      var.publication_database_secret_kms_key_arns == tolist([
        "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
        "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222",
      ]) &&
      var.database_secret_kms_key_arns == tolist([
        "arn:aws:kms:us-east-1:123456789012:key/33333333-3333-4333-8333-333333333333",
        "arn:aws:kms:us-east-1:123456789012:key/44444444-4444-4444-8444-444444444444",
      ]) &&
      alltrue([
        for arn in var.database_secret_kms_key_arns :
        !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), arn)
      ]) &&
      !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), nonsensitive(var.database_url_secret_arn)) &&
      !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), nonsensitive(var.migration_database_url_secret_arn)) &&
      !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), "*")
    )
    error_message = "the KMS-enabled publication policy must exclude writer, migrator, wildcard, and unconfigured KMS resources"
  }

  assert {
    condition = (
      aws_iam_role_policy.model_bundle_publication.role == aws_iam_role.task_publication.id &&
      aws_iam_role_policy.model_bundle.role == aws_iam_role.task.id &&
      aws_iam_role_policy.model_bundle_publication.role != aws_iam_role.task.id &&
      aws_iam_role_policy.model_bundle.role != aws_iam_role.task_publication.id
    )
    error_message = "model-object reads must be attached to the publication and private task roles without a cross-role edge"
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
      local.model_object_arns == [
        "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/config.json",
        "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/model.safetensors",
        "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/tokenizer.json",
      ] &&
      jsondecode(aws_iam_role_policy.model_bundle_publication.policy) == {
        Version = "2012-10-17"
        Statement = [{
          Sid    = "ReadPinnedModelBundle"
          Effect = "Allow"
          Action = ["s3:GetObject", "s3:GetObjectVersion"]
          Resource = [
            "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/config.json",
            "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/model.safetensors",
            "arn:aws:s3:::fleet-recall-test-models/models/potion-retrieval-32M/release-1/tokenizer.json",
          ]
        }]
      } &&
      jsondecode(aws_iam_role_policy.model_bundle.policy) ==
      jsondecode(aws_iam_role_policy.model_bundle_publication.policy)
    )
    error_message = "both task roles must share only exact versioned reads of the three pinned model files"
  }

  assert {
    condition = (
      var.enable_cloudfront &&
      length(var.alb_ingress_cidrs) == 0 &&
      startswith(output.demo_url, "https://") &&
      length(aws_cloudfront_distribution.app) == 1 &&
      output.cloudfront_distribution_id == "EDFDVBD6EXAMPLE"
    )
    error_message = "omitting front-door variables must default to the generated HTTPS CloudFront endpoint"
  }

  assert {
    condition = (
      length(aws_security_group.alb.ingress) == 1 &&
      toset(one(aws_security_group.alb.ingress).prefix_list_ids) == toset(["pl-cloudfront-origin-facing"]) &&
      one(aws_security_group.alb.ingress).cidr_blocks == null &&
      aws_lb_listener.http[0].default_action[0].type == "fixed-response" &&
      aws_lb_listener.http[0].default_action[0].fixed_response[0].status_code == "403"
    )
    error_message = "omitting front-door variables must never expose direct CIDR ingress or a forwarding ALB listener"
  }
}

run "publication_secret_without_customer_kms_keys" {
  command = plan

  variables {
    publication_database_secret_kms_key_arns = []
  }

  override_resource {
    target          = aws_iam_role.execution_publication
    override_during = plan
    values = {
      arn = "arn:aws:iam::123456789012:role/publication-execution-without-kms"
      id  = "publication-execution-without-kms"
    }
  }

  assert {
    condition = (
      jsondecode(nonsensitive(aws_iam_role_policy.publication_database_secret.policy)) == {
        Version = "2012-10-17"
        Statement = [{
          Sid      = "ReadPublicationDatabaseUrl"
          Effect   = "Allow"
          Action   = "secretsmanager:GetSecretValue"
          Resource = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-publication-MnOpQr"
        }]
      } &&
      !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), "kms:Decrypt") &&
      alltrue([
        for arn in var.database_secret_kms_key_arns :
        !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), arn)
      ]) &&
      !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), nonsensitive(var.database_url_secret_arn)) &&
      !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), nonsensitive(var.migration_database_url_secret_arn)) &&
      !strcontains(nonsensitive(aws_iam_role_policy.publication_database_secret.policy), "*")
    )
    error_message = "without customer KMS keys, the publication policy must contain only its exact secret read"
  }
}

run "tls_uses_certificate_hostname" {
  command = plan

  variables {
    enable_cloudfront = false
    alb_ingress_cidrs = ["198.51.100.0/24"]
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000001"
    demo_hostname     = "recall.example.com"
  }

  assert {
    condition     = output.demo_url == "https://recall.example.com"
    error_message = "TLS output must use the certificate-covered hostname, not the ALB hostname"
  }

  assert {
    condition = (
      length(aws_cloudfront_distribution.app) == 0 &&
      length(aws_lb_listener.https) == 1 &&
      aws_lb_listener.http_redirect[0].default_action[0].type == "redirect" &&
      alltrue([
        for ingress in aws_security_group.alb.ingress :
        toset(ingress.cidr_blocks) == toset(["198.51.100.0/24"]) && ingress.prefix_list_ids == null
      ])
    )
    error_message = "direct custom-ACM mode must use only the explicitly allowed ingress CIDR without creating CloudFront"
  }
}

run "rejects_direct_alb_without_ingress_allowlist" {
  command = plan

  variables {
    enable_cloudfront = false
  }

  expect_failures = [var.alb_ingress_cidrs]
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
    enable_cloudfront = false
    alb_ingress_cidrs = ["198.51.100.0/24"]
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000001"
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

run "rejects_wildcard_publication_database_secret" {
  command = plan

  variables {
    publication_database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:*"
  }

  expect_failures = [var.publication_database_url_secret_arn]
}

run "rejects_wildcard_writer_database_secret" {
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

run "rejects_shared_publication_and_writer_secret" {
  command = plan

  variables {
    database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-publication-MnOpQr"
  }

  expect_failures = [var.database_url_secret_arn]
}

run "rejects_shared_publication_and_migration_secret" {
  command = plan

  variables {
    migration_database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-publication-MnOpQr"
  }

  expect_failures = [var.migration_database_url_secret_arn]
}

run "rejects_shared_writer_and_migration_secret" {
  command = plan

  variables {
    migration_database_url_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fleet-writer-AbCdEf"
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

run "rejects_wildcard_publication_database_kms_key" {
  command = plan

  variables {
    publication_database_secret_kms_key_arns = ["arn:aws:kms:us-east-1:123456789012:key/*"]
  }

  expect_failures = [var.publication_database_secret_kms_key_arns]
}

run "rejects_shared_publication_and_private_database_kms_key" {
  command = plan

  variables {
    publication_database_secret_kms_key_arns = [
      "arn:aws:kms:us-east-1:123456789012:key/33333333-3333-4333-8333-333333333333",
    ]
  }

  expect_failures = [var.publication_database_secret_kms_key_arns]
}

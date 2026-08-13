mock_provider "aws" {
  override_during = plan

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
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
    condition     = aws_appautoscaling_target.app.min_capacity == 0
    error_message = "autoscaling must not race the first migration"
  }

  assert {
    condition     = local.app_command == ["demo", "--listen", "0.0.0.0:8080"]
    error_message = "the ECS command must match the tested demo CLI contract"
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

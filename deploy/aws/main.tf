locals {
  container_name       = "memory"
  container_port       = 8080
  app_command          = ["demo", "--listen", "0.0.0.0:8080"]
  model_bucket_name    = trimprefix(var.model_bucket_arn, "arn:aws:s3:::")
  model_prefix         = trim(var.model_object_prefix, "/")
  model_s3_uri         = "s3://${local.model_bucket_name}/${local.model_prefix}"
  model_bundle_path    = "/opt/ostk/models/potion-retrieval-32M"
  image_uri            = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
  migration_secret_arn = coalesce(var.migration_database_url_secret_arn, var.database_url_secret_arn)
  secret_arns          = distinct([var.database_url_secret_arn, local.migration_secret_arn])
  model_object_arns = [
    for filename in ["config.json", "model.safetensors", "tokenizer.json"] :
    "${var.model_bucket_arn}/${local.model_prefix}/${filename}"
  ]
  common_environment = [
    { name = "FLEET_RECALL_TENANT_ID", value = var.tenant_id },
    { name = "FLEET_RECALL_PROJECT", value = var.project },
    { name = "FLEET_RECALL_AGENT", value = var.agent },
    { name = "FLEET_RECALL_MAX_CONNECTIONS", value = tostring(var.max_database_connections) },
    { name = "FLEET_RECALL_EMBEDDING_MODEL", value = var.embedding_model },
    { name = "FLEET_RECALL_EMBEDDING_MODEL_PATH", value = local.model_bundle_path },
    { name = "FLEET_RECALL_EMBEDDING_MODEL_SHA256", value = lower(var.embedding_model_sha256) },
    { name = "FLEET_RECALL_MODEL_S3_URI", value = local.model_s3_uri },
    { name = "RUST_LOG", value = "ostk_fleet_recall=info" },
  ]
  log_configuration = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = aws_cloudwatch_log_group.app.name
      awslogs-region        = data.aws_region.current.name
      awslogs-stream-prefix = "fleet"
    }
  }
}

resource "aws_ecr_repository" "app" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain the ten newest release images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "app" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "database_secrets" {
  statement {
    sid       = "ReadDatabaseUrls"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.secret_arns
  }

  dynamic "statement" {
    for_each = length(var.database_secret_kms_key_arns) == 0 ? [] : [var.database_secret_kms_key_arns]
    content {
      sid       = "DecryptDatabaseSecrets"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = statement.value
    }
  }
}

resource "aws_iam_role_policy" "database_secrets" {
  name   = "database-secret-read"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.database_secrets.json
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "model_bundle" {
  statement {
    sid       = "ReadPinnedModelBundle"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = local.model_object_arns
  }
}

resource "aws_iam_role_policy" "model_bundle" {
  name   = "model-bundle-read"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.model_bundle.json
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Public ingress for the Fleet Recall demo"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.alb_ingress_cidrs
    content {
      description = "HTTP demo traffic"
      protocol    = "tcp"
      from_port   = 80
      to_port     = 80
      cidr_blocks = [ingress.value]
    }
  }

  dynamic "ingress" {
    for_each = var.certificate_arn == null ? [] : var.alb_ingress_cidrs
    content {
      description = "HTTPS demo traffic"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    description = "Forward HTTP only to application targets"
    protocol    = "tcp"
    from_port   = local.container_port
    to_port     = local.container_port
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "service" {
  name_prefix = "${var.name}-service-"
  description = "Fleet Recall tasks; no direct public ingress"
  vpc_id      = var.vpc_id

  ingress {
    description     = "HTTP from the application load balancer"
    protocol        = "tcp"
    from_port       = local.container_port
    to_port         = local.container_port
    security_groups = [aws_security_group.alb.id]
  }

  # Tasks need TLS egress to CockroachDB Cloud, ECR, S3, Secrets Manager,
  # CloudWatch Logs, and the ECS task metadata service. Restrict this further
  # with VPC endpoints, prefix lists, and the cluster endpoint in production.
  egress {
    description = "TLS and service egress"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb" "app" {
  name               = substr(var.name, 0, 32)
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.alb_subnet_ids

  enable_deletion_protection = var.enable_deletion_protection
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "app" {
  name        = substr("${var.name}-http", 0, 32)
  port        = local.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  deregistration_delay = 30

  health_check {
    enabled             = true
    path                = "/healthz"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  count = var.certificate_arn == null ? 1 : 0

  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count = var.certificate_arn == null ? 0 : 1

  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  count = var.certificate_arn == null ? 0 : 1

  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  lifecycle {
    precondition {
      condition     = var.demo_hostname != null
      error_message = "demo_hostname is required when certificate_arn is set; an ACM certificate normally does not cover the ALB's amazonaws.com hostname."
    }
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.task_cpu)
  memory                   = tostring(var.task_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  ephemeral_storage {
    size_in_gib = var.ephemeral_storage_gib
  }

  container_definitions = jsonencode([{
    name      = local.container_name
    image     = local.image_uri
    essential = true
    user      = "10001:10001"
    command   = local.app_command

    portMappings = [{
      name          = "http"
      containerPort = local.container_port
      hostPort      = local.container_port
      protocol      = "tcp"
      appProtocol   = "http"
    }]

    environment = local.common_environment
    secrets = [{
      name      = "FLEET_RECALL_DATABASE_URL"
      valueFrom = var.database_url_secret_arn
    }]

    readonlyRootFilesystem = false
    stopTimeout            = 30
    linuxParameters = {
      initProcessEnabled = true
    }
    healthCheck = {
      command     = ["CMD-SHELL", "curl --fail --silent --show-error http://127.0.0.1:${local.container_port}/healthz >/dev/null"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 120
    }
    logConfiguration = local.log_configuration
  }])

  depends_on = [
    aws_iam_role_policy.database_secrets,
    aws_iam_role_policy.model_bundle,
  ]
}

resource "aws_ecs_task_definition" "migration" {
  family                   = "${var.name}-migration"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.task_cpu)
  memory                   = tostring(var.task_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  ephemeral_storage {
    size_in_gib = var.ephemeral_storage_gib
  }

  container_definitions = jsonencode([{
    name        = local.container_name
    image       = local.image_uri
    essential   = true
    user        = "10001:10001"
    command     = ["migrate"]
    environment = local.common_environment
    secrets = [{
      name      = "FLEET_RECALL_DATABASE_URL"
      valueFrom = local.migration_secret_arn
    }]
    readonlyRootFilesystem = false
    stopTimeout            = 30
    linuxParameters = {
      initProcessEnabled = true
    }
    logConfiguration = local.log_configuration
  }])

  depends_on = [
    aws_iam_role_policy.database_secrets,
    aws_iam_role_policy.model_bundle,
  ]
}

resource "aws_ecs_service" "app" {
  name            = var.name
  cluster         = aws_ecs_cluster.app.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.service_desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 180
  enable_ecs_managed_tags            = true
  propagate_tags                     = "SERVICE"
  wait_for_steady_state              = true

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.task_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = local.container_name
    container_port   = local.container_port
  }

  depends_on = [
    aws_lb_listener.http,
    aws_lb_listener.http_redirect,
    aws_lb_listener.https,
  ]

}

resource "aws_appautoscaling_target" "app" {
  max_capacity       = var.autoscaling_max_capacity
  min_capacity       = var.autoscaling_min_capacity
  resource_id        = "service/${aws_ecs_cluster.app.name}/${aws_ecs_service.app.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  lifecycle {
    precondition {
      condition = (
        var.autoscaling_min_capacity <= var.autoscaling_max_capacity &&
        var.service_desired_count <= var.autoscaling_max_capacity
      )
      error_message = "autoscaling_min_capacity and service_desired_count must not exceed autoscaling_max_capacity."
    }
  }
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.app.resource_id
  scalable_dimension = aws_appautoscaling_target.app.scalable_dimension
  service_namespace  = aws_appautoscaling_target.app.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.autoscaling_cpu_target
    scale_in_cooldown  = 300
    scale_out_cooldown = 60

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

output "ecr_repository_url" {
  description = "Push the application image here before starting the service."
  value       = aws_ecr_repository.app.repository_url
}

output "demo_url" {
  description = "Public demo endpoint. With TLS this uses the certificate-covered application hostname, never the ALB hostname."
  value       = var.certificate_arn == null ? "http://${aws_lb.app.dns_name}" : "https://${coalesce(var.demo_hostname, "invalid.invalid")}"
}

output "cluster_name" {
  value = aws_ecs_cluster.app.name
}

output "service_name" {
  value = aws_ecs_service.app.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.app.name
}

output "migration_task" {
  description = "Machine-readable inputs consumed by run-migration.sh."
  value = {
    region           = data.aws_region.current.name
    cluster          = aws_ecs_cluster.app.name
    task_definition  = aws_ecs_task_definition.migration.arn
    container_name   = local.container_name
    subnets          = var.task_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = var.assign_public_ip ? "ENABLED" : "DISABLED"
    log_group        = aws_cloudwatch_log_group.app.name
  }
}

output "seed_task" {
  description = "Machine-readable inputs consumed by run-seed.sh."
  value = {
    region           = data.aws_region.current.name
    cluster          = aws_ecs_cluster.app.name
    task_definition  = aws_ecs_task_definition.seed.arn
    container_name   = local.container_name
    subnets          = var.task_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = var.assign_public_ip ? "ENABLED" : "DISABLED"
    log_group        = aws_cloudwatch_log_group.app.name
  }
}

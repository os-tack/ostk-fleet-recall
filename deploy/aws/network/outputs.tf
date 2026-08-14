output "private_subnet_ids" {
  description = "Private task subnet IDs, keyed like var.private_subnets."
  value       = { for key, subnet in aws_subnet.private : key => subnet.id }
}

output "private_subnet_id_list" {
  description = "Private task subnet IDs in stable key order for the application stack."
  value       = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
}

output "nat_gateway_id" {
  description = "Single public NAT gateway used by the private task subnets."
  value       = aws_nat_gateway.app.id
}

output "nat_public_ip" {
  description = "Stable IPv4 address to authorize as a /32 in CockroachDB Cloud."
  value       = aws_eip.nat.public_ip
}

output "private_route_table_id" {
  description = "Route table associated with every managed private subnet."
  value       = aws_route_table.private.id
}

output "hold_until" {
  description = "Judging hold copied into the resource tags."
  value       = var.hold_until
}

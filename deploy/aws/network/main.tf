data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_subnet" "nat" {
  id = var.nat_public_subnet_id
}

resource "aws_subnet" "private" {
  for_each = var.private_subnets

  vpc_id                  = data.aws_vpc.selected.id
  availability_zone       = each.value.availability_zone
  cidr_block              = each.value.cidr_block
  map_public_ip_on_launch = false

  tags = {
    Name    = "${var.name}-private-${each.key}"
    Network = "private-task"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name = "${var.name}-nat"
  }
}

resource "aws_nat_gateway" "app" {
  allocation_id = aws_eip.nat.id
  subnet_id     = data.aws_subnet.nat.id

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = data.aws_subnet.nat.vpc_id == data.aws_vpc.selected.id
      error_message = "nat_public_subnet_id must belong to vpc_id."
    }
  }

  tags = {
    Name = "${var.name}-nat"
  }
}

resource "aws_route_table" "private" {
  vpc_id = data.aws_vpc.selected.id

  tags = {
    Name    = "${var.name}-private"
    Network = "private-task"
  }
}

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.app.id
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

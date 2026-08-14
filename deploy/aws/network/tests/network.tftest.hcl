mock_provider "aws" {
  override_during = plan

  mock_data "aws_vpc" {
    defaults = {
      id         = "vpc-0123456789abcdef0"
      cidr_block = "172.31.0.0/16"
    }
  }

  mock_data "aws_subnet" {
    defaults = {
      id     = "subnet-0123456789abcdef0"
      vpc_id = "vpc-0123456789abcdef0"
    }
  }
}

variables {
  vpc_id               = "vpc-0123456789abcdef0"
  nat_public_subnet_id = "subnet-0123456789abcdef0"

  private_subnets = {
    a = {
      availability_zone = "us-east-1a"
      cidr_block        = "172.31.96.0/24"
    }
    b = {
      availability_zone = "us-east-1b"
      cidr_block        = "172.31.97.0/24"
    }
  }
}

run "plans_two_private_subnets_behind_one_nat" {
  command = plan

  assert {
    condition     = length(aws_subnet.private) == 2
    error_message = "the stack must create exactly the requested private subnets"
  }

  assert {
    condition = (
      aws_nat_gateway.app.subnet_id == var.nat_public_subnet_id &&
      length(aws_route_table_association.private) == 2
    )
    error_message = "the cost-conscious stack must route every private subnet through one shared NAT gateway"
  }

  assert {
    condition     = alltrue([for subnet in values(aws_subnet.private) : !subnet.map_public_ip_on_launch])
    error_message = "task subnets must not assign public IPs"
  }

  assert {
    condition     = aws_route.private_default.destination_cidr_block == "0.0.0.0/0"
    error_message = "the private route table must send Internet egress through the NAT"
  }
}

run "rejects_same_availability_zone" {
  command = plan

  variables {
    private_subnets = {
      a = {
        availability_zone = "us-east-1a"
        cidr_block        = "172.31.96.0/24"
      }
      b = {
        availability_zone = "us-east-1a"
        cidr_block        = "172.31.97.0/24"
      }
    }
  }

  expect_failures = [var.private_subnets]
}

run "rejects_early_teardown_hold" {
  command = plan

  variables {
    hold_until = "2026-09-15T20:59:59Z"
  }

  expect_failures = [var.hold_until]
}

run "rejects_nat_subnet_from_another_vpc" {
  command = plan

  override_data {
    target = data.aws_subnet.nat
    values = {
      id     = "subnet-0123456789abcdef0"
      vpc_id = "vpc-fffffffffffffffff"
    }
  }

  expect_failures = [aws_nat_gateway.app]
}

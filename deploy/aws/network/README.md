# Private task network

This standalone Terraform stack adds the minimum stable-egress network required
by the Fleet Recall ECS tasks to an existing VPC: two private subnets in distinct
availability zones, one shared public NAT gateway and Elastic IP, and one private
route table. The NAT public IP is the single `/32` that should be authorized in
CockroachDB Cloud.

Copy both examples to their ignored local counterparts. Fill the existing
VPC/public-subnet coordinates and the private, versioned S3 state bucket before
initializing:

```sh
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
# Edit backend.hcl and terraform.tfvars.
terraform init -backend-config=backend.hcl
terraform test
terraform plan -out=network.tfplan
terraform apply network.tfplan
terraform output -raw nat_public_ip
terraform output -json private_subnet_id_list
```

The stack deliberately uses one NAT gateway to control hackathon cost. Tasks in
the second availability zone depend on that gateway and can incur cross-AZ data
charges; this is not a production multi-AZ egress design.

Do not destroy the stack before the `hold_until` judging deadline. After the
application stack has been destroyed, evidence has been preserved, and the hold
has expired, remove the NAT `/32` from CockroachDB Cloud and run `terraform
destroy`. NAT gateway and unattached Elastic IP charges stop only after destroy
completes. The private, encrypted, versioned S3 object configured by
`backend.hcl` is the authoritative state; preserve its versions and access until
the network has been intentionally destroyed. The example enables Terraform's
native S3 lock file, which requires Terraform 1.10 or newer.

The NAT gateway and EIP also use Terraform `prevent_destroy` guards. After the
hold expires, remove those two guards in a reviewed change before running the
separate destroy plan. A timestamp tag alone is not a deletion control.

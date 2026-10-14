# Cross-variable checks. The terraform_data precondition fails the plan,
# the check block only warns.

resource "terraform_data" "validations" {
  lifecycle {
    precondition {
      condition     = (length(var.domains) > 0) != (var.existing_ssl_certificate_id != null)
      error_message = "Set exactly one of domains (Google-managed certificate) or existing_ssl_certificate_id."
    }

    precondition {
      # Two CIDRs overlap when they are the same network at the shorter prefix.
      condition = (
        cidrhost("${cidrhost(var.public_subnet_cidr, 0)}/${min(tonumber(split("/", var.public_subnet_cidr)[1]), tonumber(split("/", var.private_subnet_cidr)[1]))}", 0) !=
        cidrhost("${cidrhost(var.private_subnet_cidr, 0)}/${min(tonumber(split("/", var.public_subnet_cidr)[1]), tonumber(split("/", var.private_subnet_cidr)[1]))}", 0)
      )
      error_message = "public_subnet_cidr and private_subnet_cidr must not overlap."
    }

    precondition {
      condition     = startswith(var.zone, "${var.region}-")
      error_message = "zone must be inside region."
    }
  }
}

check "ssh_range_is_narrow" {
  assert {
    condition = alltrue([
      for c in var.trusted_ssh_cidrs :
      tonumber(split("/", c)[1]) >= 16
    ])
    error_message = "A trusted SSH range wider than /16 is allowed but very broad. Prefer office or VPN egress addresses, or enable_iap_ssh."
  }
}

# Cross-variable checks that fail the plan.

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

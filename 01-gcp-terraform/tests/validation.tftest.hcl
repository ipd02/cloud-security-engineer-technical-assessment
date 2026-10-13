# Bad input must be rejected before anything is planned.
mock_provider "google" {}

variables {
  project_id        = "test-project-123"
  trusted_ssh_cidrs = ["203.0.113.0/24"]
  domains           = ["www.example.com"]
}

run "ssh_open_to_world_ipv4" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_open_to_world_ipv6" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["::/0"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_empty_list" {
  command = plan
  variables {
    trusted_ssh_cidrs = []
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_prefix_too_short" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["10.0.0.0/7"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_malformed" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["not-a-cidr"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "certificate_required" {
  command = plan
  variables {
    domains = []
  }
  expect_failures = [terraform_data.validations]
}

run "certificate_not_both" {
  command = plan
  variables {
    existing_ssl_certificate_id = "projects/p/global/sslCertificates/c"
  }
  expect_failures = [terraform_data.validations]
}

run "subnets_must_not_overlap" {
  command = plan
  variables {
    public_subnet_cidr  = "10.10.0.0/16"
    private_subnet_cidr = "10.10.1.0/24"
  }
  expect_failures = [terraform_data.validations]
}

run "zone_must_match_region" {
  command = plan
  variables {
    zone = "us-central1-a"
  }
  expect_failures = [terraform_data.validations]
}

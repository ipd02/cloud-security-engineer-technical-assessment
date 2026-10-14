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

run "ssh_all_256_slash8s_summing_to_the_internet" {
  command = plan
  variables {
    trusted_ssh_cidrs = [for i in range(256) : "${i}.0.0.0/8"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_two_slash9s_exceed_total_cap" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["0.0.0.0/9", "128.0.0.0/9", "64.0.0.0/9"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_half_internet_slash1" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["128.0.0.0/1"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_slash7" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["10.0.0.0/7"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_ipv6_prefix" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["2001:db8::/32"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_ipv4_mapped_ipv6" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["::ffff:0:0/96"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_mixed_v4_and_v6" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["203.0.113.0/24", "2001:db8::/32"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_host_bits_set" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["203.0.113.5/24"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_leading_zero_prefix" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["10.0.0.0/08"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_leading_whitespace" {
  command = plan
  variables {
    trusted_ssh_cidrs = [" 203.0.113.0/24"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_trailing_whitespace" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["0.0.0.0/0 "]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_world_alt_spelling" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["0.0.0.0/00"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_null_element" {
  command = plan
  variables {
    trusted_ssh_cidrs = [null]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_empty_string" {
  command = plan
  variables {
    trusted_ssh_cidrs = [""]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ssh_no_prefix" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["203.0.113.5"]
  }
  expect_failures = [var.trusted_ssh_cidrs]
}

# Valid input must still pass: several /16s are fine (anything wider triggers the check warning, which fails a test run).
run "ssh_valid_ranges_are_accepted" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["172.16.0.0/16", "192.168.0.0/16"]
  }
}

run "ssh_single_host_and_small_ranges_are_accepted" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["203.0.113.0/24", "198.51.100.7/32", "192.0.2.0/25"]
  }
}

run "login_members_reject_public_principals" {
  command = plan
  variables {
    ssh_login_members = ["allUsers"]
  }
  expect_failures = [var.ssh_login_members]
}

run "login_members_reject_domains" {
  command = plan
  variables {
    ssh_login_members = ["domain:example.com"]
  }
  expect_failures = [var.ssh_login_members]
}

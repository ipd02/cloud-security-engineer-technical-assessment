mock_provider "google" {}

variables {
  project_id        = "test-project-123"
  trusted_ssh_cidrs = ["203.0.113.0/24"]
  domains           = ["www.example.com"]
}

run "iap_ssh_is_opt_in" {
  command = plan

  variables {
    enable_iap_ssh = true
  }

  assert {
    condition     = google_compute_firewall.allow_ssh_iap[0].source_ranges == toset(["35.235.240.0/20"])
    error_message = "IAP rule must use the IAP range only."
  }
}

run "existing_certificate_instead_of_domains" {
  command = plan

  variables {
    domains                     = []
    existing_ssl_certificate_id = "projects/test-project-123/global/sslCertificates/existing"
  }

  assert {
    condition     = length(google_compute_managed_ssl_certificate.this) == 0
    error_message = "No managed certificate when an existing one is supplied."
  }
}

run "cmek_is_passed_to_boot_disk" {
  command = plan

  variables {
    kms_key_self_link = "projects/test-project-123/locations/europe-west1/keyRings/r/cryptoKeys/k"
  }

  assert {
    condition     = google_compute_instance.web.boot_disk[0].kms_key_self_link == "projects/test-project-123/locations/europe-west1/keyRings/r/cryptoKeys/k"
    error_message = "CMEK key must reach the boot disk."
  }
}

run "cloud_armor_has_owasp_and_rate_limit" {
  command = plan

  assert {
    condition     = length([for r in google_compute_security_policy.edge.rule : r if r.action == "throttle"]) == 1
    error_message = "Exactly one rate limit rule expected."
  }
}

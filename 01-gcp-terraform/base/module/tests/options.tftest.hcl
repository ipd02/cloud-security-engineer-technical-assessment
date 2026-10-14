mock_provider "google" {}

variables {
  project_id        = "test-project-123"
  trusted_ssh_cidrs = ["203.0.113.0/24"]
  domains           = ["www.example.com"]
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

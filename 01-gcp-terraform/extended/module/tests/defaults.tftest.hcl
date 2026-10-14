# Runs offline with a mocked google provider. Nothing here talks to GCP.
mock_provider "google" {}

variables {
  project_id        = "test-project-123"
  trusted_ssh_cidrs = ["203.0.113.0/24"]
  domains           = ["www.example.com"]
}

run "load_balancer_is_https_only" {
  command = plan

  assert {
    condition     = google_compute_global_forwarding_rule.https.port_range == "443"
    error_message = "The forwarding rule must listen on 443 only."
  }

  assert {
    condition     = google_compute_ssl_policy.modern.min_tls_version == "TLS_1_2" && google_compute_ssl_policy.modern.profile == "MODERN"
    error_message = "TLS policy must be MODERN with minimum TLS 1.2."
  }

  assert {
    condition     = google_compute_backend_service.web.log_config[0].enable && google_compute_health_check.web.log_config[0].enable
    error_message = "Backend service and health check logging must be on."
  }
}

run "firewall_rules_match_the_brief" {
  command = plan

  assert {
    condition     = toset(google_compute_firewall.allow_lb_http.source_ranges) == toset(["130.211.0.0/22", "35.191.0.0/16"])
    error_message = "HTTP must be allowed only from the Google load balancer ranges."
  }

  assert {
    condition     = [for a in google_compute_firewall.allow_lb_http.allow : a.protocol] == ["tcp"] && flatten([for a in google_compute_firewall.allow_lb_http.allow : a.ports]) == ["80"]
    error_message = "The load balancer rule must allow only tcp/80."
  }

  assert {
    condition     = google_compute_firewall.allow_ssh_trusted.source_ranges == toset(["203.0.113.0/24"]) && flatten([for a in google_compute_firewall.allow_ssh_trusted.allow : a.ports]) == ["22"]
    error_message = "SSH must be allowed only from the trusted range on tcp/22."
  }

  assert {
    condition     = !contains(google_compute_firewall.allow_ssh_trusted.source_ranges, "0.0.0.0/0")
    error_message = "SSH must never be open to the world."
  }

  assert {
    condition     = length(google_compute_firewall.allow_ssh_iap) == 0
    error_message = "IAP SSH must be off by default."
  }

  assert {
    condition     = google_compute_firewall.deny_all_ingress.priority == 65000 && google_compute_firewall.deny_all_egress.priority == 65000
    error_message = "Deny-all rules must have the lowest custom priority."
  }
}

run "instance_is_private_and_hardened" {
  command = plan

  assert {
    condition     = length(google_compute_instance.web.network_interface[0].access_config) == 0
    error_message = "The instance must not have an external IP."
  }

  assert {
    condition     = google_compute_instance.web.shielded_instance_config[0].enable_secure_boot && google_compute_instance.web.shielded_instance_config[0].enable_vtpm && google_compute_instance.web.shielded_instance_config[0].enable_integrity_monitoring
    error_message = "Shielded VM must be fully enabled."
  }

  assert {
    condition     = google_compute_instance.web.metadata["enable-oslogin"] == "TRUE" && google_compute_instance.web.metadata["block-project-ssh-keys"] == "TRUE" && google_compute_instance.web.metadata["serial-port-enable"] == "FALSE"
    error_message = "OS Login on, project SSH keys blocked, serial port off."
  }

  assert {
    condition     = google_compute_instance.web.can_ip_forward == false
    error_message = "IP forwarding must be off."
  }
}

run "iam_is_least_privilege" {
  command = plan

  assert {
    condition     = toset([for m in google_project_iam_member.web : m.role]) == toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
    error_message = "The instance service account may only hold the log and metric writer roles."
  }

  assert {
    condition     = length([for m in google_project_iam_member.web : m.role if contains(["roles/editor", "roles/owner"], m.role)]) == 0
    error_message = "roles/editor and roles/owner must never be granted."
  }
}

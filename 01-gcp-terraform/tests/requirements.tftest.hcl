# One run per bullet of the task brief. The mocked provider is applied (not
# only planned) so resource ids exist and references can be compared.
mock_provider "google" {}

variables {
  project_id        = "test-project-123"
  trusted_ssh_cidrs = ["203.0.113.0/24"]
  domains           = ["www.example.com"]
}

# Bullet 1: a VPC network with a public and a private subnet.
run "vpc_has_public_and_private_subnet" {
  command = apply

  assert {
    condition     = google_compute_subnetwork.public.network == google_compute_network.vpc.id && google_compute_subnetwork.private.network == google_compute_network.vpc.id
    error_message = "Both subnets must belong to the VPC."
  }

  assert {
    condition     = google_compute_network.vpc.auto_create_subnetworks == false
    error_message = "The VPC must be custom mode."
  }

  assert {
    condition     = google_compute_subnetwork.public.ip_cidr_range != google_compute_subnetwork.private.ip_cidr_range
    error_message = "The two subnets need different ranges."
  }
}

# Bullet 2: a Compute Engine instance in the private subnet, no external IP.
run "instance_is_in_the_private_subnet" {
  command = apply

  assert {
    condition     = google_compute_instance.web.network_interface[0].subnetwork == google_compute_subnetwork.private.id
    error_message = "The instance must sit in the private subnet."
  }

  assert {
    condition     = length(google_compute_instance.web.network_interface) == 1 && length(google_compute_instance.web.network_interface[0].access_config) == 0
    error_message = "One network interface and no external IP."
  }

  assert {
    condition     = google_compute_instance.web.service_account[0].email == google_service_account.web.email
    error_message = "The instance must run as the dedicated service account."
  }
}

# Bullet 3: a global load balancer that routes traffic to the instance.
run "global_load_balancer_routes_to_the_instance" {
  command = apply

  assert {
    condition     = google_compute_global_forwarding_rule.https.target == google_compute_target_https_proxy.web.id
    error_message = "The global forwarding rule must target the HTTPS proxy."
  }

  assert {
    condition     = google_compute_target_https_proxy.web.url_map == google_compute_url_map.web.id && google_compute_url_map.web.default_service == google_compute_backend_service.web.id
    error_message = "Proxy, URL map and backend service must be chained."
  }

  assert {
    condition     = [for b in google_compute_backend_service.web.backend : b.group] == [google_compute_instance_group.web.id]
    error_message = "The backend service must have exactly the instance group as backend."
  }

  assert {
    condition     = toset(google_compute_instance_group.web.instances) == toset([google_compute_instance.web.id])
    error_message = "The instance group must contain exactly the web instance."
  }

  assert {
    condition     = google_compute_global_forwarding_rule.https.load_balancing_scheme == "EXTERNAL_MANAGED" && google_compute_global_forwarding_rule.https.ip_address == google_compute_global_address.lb.id
    error_message = "External global load balancer on the reserved global address."
  }

  assert {
    condition     = google_compute_target_https_proxy.web.ssl_policy == google_compute_ssl_policy.modern.id
    error_message = "The proxy must use the TLS policy."
  }

  assert {
    condition     = google_compute_backend_service.web.security_policy == google_compute_security_policy.edge.id
    error_message = "The backend service must use the Cloud Armor policy."
  }
}

# Bullet 4a: only HTTPS (443) from the internet to the load balancer. Firewall
# rules do not apply to a global load balancer, so the forwarding rule is the
# control: one port, 443, and nothing in the VPC admits the internet.
run "internet_reaches_only_port_443_on_the_load_balancer" {
  command = apply

  assert {
    condition     = google_compute_global_forwarding_rule.https.port_range == "443" && google_compute_global_forwarding_rule.https.ip_protocol == "TCP"
    error_message = "The forwarding rule must listen on tcp/443 only."
  }

  assert {
    condition = alltrue([
      for r in [google_compute_firewall.allow_lb_http, google_compute_firewall.allow_ssh_trusted] :
      !contains(r.source_ranges, "0.0.0.0/0") && !contains(r.source_ranges, "::/0")
    ])
    error_message = "No allow rule may take traffic from the whole internet."
  }
}

# Bullet 4b: only SSH (22) from a trusted range (not 0.0.0.0/0) to the instance.
run "ssh_only_from_the_trusted_range_to_the_instance" {
  command = apply

  assert {
    condition     = google_compute_firewall.allow_ssh_trusted.direction == "INGRESS" && google_compute_firewall.allow_ssh_trusted.source_ranges == toset(["203.0.113.0/24"])
    error_message = "SSH is allowed only from var.trusted_ssh_cidrs."
  }

  assert {
    condition     = [for a in google_compute_firewall.allow_ssh_trusted.allow : a.protocol] == ["tcp"] && flatten([for a in google_compute_firewall.allow_ssh_trusted.allow : tolist(a.ports)]) == ["22"]
    error_message = "SSH rule must allow exactly tcp/22."
  }

  assert {
    condition     = google_compute_firewall.allow_ssh_trusted.target_service_accounts == toset([google_service_account.web.email])
    error_message = "SSH rule must target the web instance only."
  }

  assert {
    condition     = length(google_compute_firewall.allow_ssh_iap) == 0
    error_message = "The IAP rule is opt-in."
  }
}

# Bullet 4c: only HTTP (80) from the load balancer to the instance.
run "http_only_from_the_load_balancer_to_the_instance" {
  command = apply

  assert {
    condition     = google_compute_firewall.allow_lb_http.direction == "INGRESS" && google_compute_firewall.allow_lb_http.source_ranges == toset(["130.211.0.0/22", "35.191.0.0/16"])
    error_message = "HTTP is allowed only from the Google load balancer and health check ranges."
  }

  assert {
    condition     = [for a in google_compute_firewall.allow_lb_http.allow : a.protocol] == ["tcp"] && flatten([for a in google_compute_firewall.allow_lb_http.allow : tolist(a.ports)]) == ["80"]
    error_message = "The load balancer rule must allow exactly tcp/80."
  }

  assert {
    condition     = google_compute_firewall.allow_lb_http.target_service_accounts == toset([google_service_account.web.email])
    error_message = "The load balancer rule must target the web instance only."
  }

  assert {
    condition     = google_compute_health_check.web.http_health_check[0].port == 80 && [for b in google_compute_backend_service.web.backend : b.group] == [google_compute_instance_group.web.id] && google_compute_backend_service.web.protocol == "HTTP" && google_compute_backend_service.web.port_name == "http" && one(google_compute_instance_group.web.named_port).port == 80
    error_message = "The load balancer must talk to the instance on port 80."
  }
}

# The deny rules must never shadow an allow rule: a lower number wins, and at
# equal priority deny wins, so every allow must be strictly below the denies.
run "allow_rules_outrank_the_deny_rules" {
  command = apply

  assert {
    condition = alltrue([
      for r in [google_compute_firewall.allow_lb_http, google_compute_firewall.allow_ssh_trusted, google_compute_firewall.allow_egress_web] :
      r.priority < min(google_compute_firewall.deny_all_ingress.priority, google_compute_firewall.deny_all_ingress_ipv6.priority, google_compute_firewall.deny_all_egress.priority)
    ])
    error_message = "Every allow rule must have a lower priority number than every deny rule."
  }

  assert {
    condition     = google_compute_firewall.deny_all_ingress.direction == "INGRESS" && google_compute_firewall.deny_all_egress.direction == "EGRESS" && google_compute_firewall.allow_egress_web.direction == "EGRESS"
    error_message = "Rule directions must match their names."
  }
}

# Bonus: least-privilege IAM, no roles/editor or roles/owner.
run "iam_has_no_basic_roles" {
  command = apply

  assert {
    condition     = toset([for m in google_project_iam_member.web : m.role]) == toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
    error_message = "Only the log and metric writer roles."
  }

  assert {
    condition     = alltrue([for m in google_project_iam_member.web : m.member == "serviceAccount:${google_service_account.web.email}"])
    error_message = "Roles go to the dedicated service account only."
  }

}

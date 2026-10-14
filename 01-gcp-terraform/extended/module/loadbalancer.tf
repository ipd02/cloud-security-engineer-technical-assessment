# Global external Application Load Balancer, HTTPS only. There is no port 80
# frontend and no redirect, so plain HTTP from the internet gets no listener.
# It is a Google-managed service, not a virtual machine deployed inside your
# VPC, so it is not in the public subnet or any other subnet.

resource "google_compute_global_address" "lb" {
  project      = var.project_id
  name         = "${var.name}-lb-ip"
  address_type = "EXTERNAL"
}

resource "google_compute_managed_ssl_certificate" "this" {
  count = length(var.domains) > 0 ? 1 : 0

  project = var.project_id
  name    = "${var.name}-cert-${substr(sha1(join(",", sort(var.domains))), 0, 6)}"

  managed {
    domains = var.domains
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_ssl_policy" "modern" {
  project         = var.project_id
  name            = "${var.name}-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_health_check" "web" {
  project             = var.project_id
  name                = "${var.name}-hc"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 80
    request_path = "/"
  }

  log_config {
    enable = true
  }
}

resource "google_compute_backend_service" "web" {
  project               = var.project_id
  name                  = "${var.name}-backend"
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.web.id]
  security_policy       = google_compute_security_policy.edge.id

  backend {
    group           = google_compute_instance_group.web.id
    balancing_mode  = "UTILIZATION"
    max_utilization = 0.8
    capacity_scaler = 1.0
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "web" {
  project         = var.project_id
  name            = "${var.name}-urlmap"
  default_service = google_compute_backend_service.web.id
}

resource "google_compute_target_https_proxy" "web" {
  project    = var.project_id
  name       = "${var.name}-https-proxy"
  url_map    = google_compute_url_map.web.id
  ssl_policy = google_compute_ssl_policy.modern.id
  ssl_certificates = concat(
    [for c in google_compute_managed_ssl_certificate.this : c.id],
    var.existing_ssl_certificate_id == null ? [] : [var.existing_ssl_certificate_id],
  )
}

resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = "${var.name}-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  port_range            = "443"
  target                = google_compute_target_https_proxy.web.id
  ip_address            = google_compute_global_address.lb.id
  labels                = local.labels
}

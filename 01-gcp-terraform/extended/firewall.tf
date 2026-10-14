# Rules target the instance service account, not network tags. A tag can be
# set by anyone who can edit the instance. A service account needs
# iam.serviceAccounts.actAs.

# Source ranges used by Google Front Ends and health checkers when the
# backends are instance groups. Verified against Google documentation:
# https://docs.cloud.google.com/load-balancing/docs/firewall-rules
#   health checks: 35.191.0.0/16
#   GFE proxies:   35.191.0.0/16 and 130.211.0.0/22
# The older health check range 209.85.152.0/22 and 209.85.204.0/22 applies to
# other load balancer types and is not needed here.
locals {
  google_lb_ranges = ["130.211.0.0/22", "35.191.0.0/16"]

  # https://docs.cloud.google.com/iap/docs/using-tcp-forwarding
  iap_ranges = ["35.235.240.0/20"]
}

resource "google_compute_firewall" "allow_lb_http" {
  project                 = var.project_id
  name                    = "${var.name}-allow-lb-http"
  network                 = google_compute_network.vpc.name
  description             = "tcp/80 from Google load balancer and health check ranges to the web instance only."
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = local.google_lb_ranges
  target_service_accounts = [google_service_account.web.email]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_trusted" {
  project                 = var.project_id
  name                    = "${var.name}-allow-ssh-trusted"
  network                 = google_compute_network.vpc.name
  description             = "tcp/22 from the trusted ranges to the web instance only. Useful when those ranges reach the VPC privately."
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = var.trusted_ssh_cidrs
  target_service_accounts = [google_service_account.web.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_trusted_bastion" {
  count = var.enable_bastion ? 1 : 0

  project                 = var.project_id
  name                    = "${var.name}-allow-ssh-bastion-in"
  network                 = google_compute_network.vpc.name
  description             = "tcp/22 from the trusted ranges to the bastion only."
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = var.trusted_ssh_cidrs
  target_service_accounts = [google_service_account.bastion[0].email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_bastion_to_web" {
  count = var.enable_bastion ? 1 : 0

  project                 = var.project_id
  name                    = "${var.name}-allow-ssh-bastion-to-web"
  network                 = google_compute_network.vpc.name
  description             = "tcp/22 from the bastion to the web instance only."
  direction               = "INGRESS"
  priority                = 1000
  source_service_accounts = [google_service_account.bastion[0].email]
  target_service_accounts = [google_service_account.web.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_egress_bastion_ssh" {
  count = var.enable_bastion ? 1 : 0

  project                 = var.project_id
  name                    = "${var.name}-allow-egress-bastion-ssh"
  network                 = google_compute_network.vpc.name
  description             = "Outbound tcp/22 from the bastion to the private subnet only."
  direction               = "EGRESS"
  priority                = 1000
  destination_ranges      = [var.private_subnet_cidr]
  target_service_accounts = [google_service_account.bastion[0].email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_iap" {
  count = var.enable_iap_ssh ? 1 : 0

  project                 = var.project_id
  name                    = "${var.name}-allow-ssh-iap"
  network                 = google_compute_network.vpc.name
  description             = "tcp/22 from the IAP TCP forwarding range to the web instance only."
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = local.iap_ranges
  target_service_accounts = [google_service_account.web.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all_ingress" {
  project       = var.project_id
  name          = "${var.name}-deny-all-ingress"
  network       = google_compute_network.vpc.name
  description   = "Explicit low-priority deny for every other ingress (IPv4)."
  direction     = "INGRESS"
  priority      = 65000
  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all_ingress_ipv6" {
  project       = var.project_id
  name          = "${var.name}-deny-all-ingress-v6"
  network       = google_compute_network.vpc.name
  description   = "Explicit low-priority deny for every other ingress (IPv6)."
  direction     = "INGRESS"
  priority      = 65000
  source_ranges = ["::/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Egress posture: the instances may open tcp/80 and tcp/443 (package
# repositories through Cloud NAT, Google APIs through private access).
# Everything else is denied. DNS to the metadata server (169.254.169.254) is
# always allowed by GCP and needs no rule.
resource "google_compute_firewall" "allow_egress_web" {
  project                 = var.project_id
  name                    = "${var.name}-allow-egress-web"
  network                 = google_compute_network.vpc.name
  description             = "Outbound tcp/80 and tcp/443 for updates and Google APIs (web instance and bastion)."
  direction               = "EGRESS"
  priority                = 1000
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = concat([google_service_account.web.email], google_service_account.bastion[*].email)

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all_egress" {
  project            = var.project_id
  name               = "${var.name}-deny-all-egress"
  network            = google_compute_network.vpc.name
  description        = "Explicit low-priority deny for every other egress."
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

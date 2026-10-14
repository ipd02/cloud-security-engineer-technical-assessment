# Rules target the instance service account, not network tags.

# https://docs.cloud.google.com/load-balancing/docs/firewall-rules
#   health checks: 35.191.0.0/16
#   GFE proxies:   35.191.0.0/16 and 130.211.0.0/22
locals {
  google_lb_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
}

# "Allow only HTTP (80) from the Load Balancer to the Compute Engine instance."
resource "google_compute_firewall" "allow_lb_http" {
  project                 = var.project_id
  name                    = "${var.name}-allow-lb-http"
  network                 = google_compute_network.vpc.name
  description             = "tcp/80 from the Google load balancer and health check ranges to the instance only."
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = local.google_lb_ranges
  target_service_accounts = [google_service_account.web.email]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }
}

# "Allow only SSH (22) from a trusted IP range (not 0.0.0.0/0) to the Compute
# Engine instance." The instance has no external IP, so the path is two rules:
# trusted range to the bastion, then bastion to the instance.
resource "google_compute_firewall" "allow_ssh_trusted_bastion" {
  project                 = var.project_id
  name                    = "${var.name}-allow-ssh-bastion-in"
  network                 = google_compute_network.vpc.name
  description             = "tcp/22 from the trusted ranges to the bastion only."
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = var.trusted_ssh_cidrs
  target_service_accounts = [google_service_account.bastion.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_ssh_bastion_to_web" {
  project                 = var.project_id
  name                    = "${var.name}-allow-ssh-bastion-to-web"
  network                 = google_compute_network.vpc.name
  description             = "tcp/22 from the bastion to the Compute Engine instance only."
  direction               = "INGRESS"
  priority                = 1000
  source_service_accounts = [google_service_account.bastion.email]
  target_service_accounts = [google_service_account.web.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# "Allow only HTTPS (443) from the internet to the Load Balancer." A VPC
# firewall rule cannot do this: a global load balancer is not in the VPC. The
# control is the single forwarding rule on tcp/443 in loadbalancer.tf.

locals {
  labels = merge(var.labels, {
    managed-by = "terraform"
    workload   = var.name
  })
}

resource "google_compute_network" "vpc" {
  project                 = var.project_id
  name                    = "${var.name}-vpc"
  auto_create_subnetworks = false
  description             = "Custom-mode VPC. No default subnets, no default firewall rules."

  depends_on = [terraform_data.validations]
}

# The public subnet is kept because the brief asks for it. A global external
# Application Load Balancer does not live in any subnet.
# It holds the SSH bastion (bastion.tf), the one host with its own
# internet-reachable address. A proxy-only subnet for a regional load balancer
# would be a separate subnet with its own purpose, not this one.
resource "google_compute_subnetwork" "public" {
  project                  = var.project_id
  name                     = "${var.name}-public"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.public_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "private" {
  project                  = var.project_id
  name                     = "${var.name}-private"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.private_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_router" "this" {
  project = var.project_id
  name    = "${var.name}-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

# Outbound internet for the private instance (package updates) without an
# external IP. NAT covers the private subnet only.
resource "google_compute_router_nat" "this" {
  project                            = var.project_id
  name                               = "${var.name}-nat"
  router                             = google_compute_router.this.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ALL"
  }
}

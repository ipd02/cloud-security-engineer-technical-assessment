resource "google_compute_network" "vpc" {
  project                 = var.project_id
  name                    = "${var.name}-vpc"
  auto_create_subnetworks = false
  description             = "Custom-mode VPC with a public and a private subnet."

  depends_on = [terraform_data.validations]
}

# The brief asks for a public subnet. A global external Application Load
# Balancer is a Google edge service and does not live in any subnet, so
# nothing runs here. See the README.
resource "google_compute_subnetwork" "public" {
  #checkov:skip=CKV_GCP_26:Not in the brief. Added by the extended module, see ../README.md. VPC flow logs.
  #checkov:skip=CKV_GCP_74:Not in the brief. Added by the extended module, see ../README.md. Private Google Access.
  project       = var.project_id
  name          = "${var.name}-public"
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = var.public_subnet_cidr
}

resource "google_compute_subnetwork" "private" {
  #checkov:skip=CKV_GCP_26:Not in the brief. Added by the extended module, see ../README.md. VPC flow logs.
  #checkov:skip=CKV_GCP_74:Not in the brief. Added by the extended module, see ../README.md. Private Google Access.
  project       = var.project_id
  name          = "${var.name}-private"
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = var.private_subnet_cidr
}

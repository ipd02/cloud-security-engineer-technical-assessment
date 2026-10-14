# SSH entry point for the private web instance. The web instance has no
# external IP, so a trusted public range cannot reach it directly. The bastion
# lives in the public subnet, takes SSH only from var.trusted_ssh_cidrs, and is
# the only host that may open SSH to the web instance. Set enable_bastion to
# false if trusted_ssh_cidrs already reaches the VPC privately (VPN,
# Interconnect, peering).

resource "google_service_account" "bastion" {
  count = var.enable_bastion ? 1 : 0

  project      = var.project_id
  account_id   = "${var.name}-bastion"
  display_name = "${var.name} bastion"
  description  = "Runs the SSH bastion. Holds no project roles."
}

resource "google_compute_instance" "bastion" {
  #checkov:skip=CKV_GCP_40:The bastion is the one host with an external IP. SSH reaches it only from trusted_ssh_cidrs and it holds no project roles.
  count = var.enable_bastion ? 1 : 0

  project        = var.project_id
  name           = "${var.name}-bastion"
  zone           = var.zone
  machine_type   = var.bastion_machine_type
  can_ip_forward = false
  labels         = local.labels

  allow_stopping_for_update = true

  boot_disk {
    kms_key_self_link = var.kms_key_self_link

    initialize_params {
      image  = var.boot_image
      size   = 10
      type   = "pd-balanced"
      labels = local.labels
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.public.id

    # Empty access_config gives the bastion an ephemeral external IP.
    access_config {}
  }

  service_account {
    email  = google_service_account.bastion[0].email
    scopes = ["https://www.googleapis.com/auth/logging.write"] # The account holds no roles, so IAM allows nothing anyway.
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
  }

  depends_on = [terraform_data.validations]
}

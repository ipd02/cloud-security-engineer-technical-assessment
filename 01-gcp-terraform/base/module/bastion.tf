# SSH entry point. The brief puts the Compute Engine instance in the private
# subnet, so it has no external IP and a trusted public range cannot reach it
# directly. The bastion sits in the public subnet, takes SSH only from
# trusted_ssh_cidrs, and is the only host allowed to SSH to the instance.

resource "google_service_account" "bastion" {
  project      = var.project_id
  account_id   = "${var.name}-bastion"
  display_name = "${var.name} bastion"
  description  = "Runs the SSH bastion. Holds no project roles."
}

resource "google_compute_instance" "bastion" {
  #checkov:skip=CKV_GCP_40:The bastion is the one host with an external IP. SSH reaches it only from trusted_ssh_cidrs and it holds no project roles.
  #checkov:skip=CKV_GCP_32:Not in the brief. Added by the extended module, see ../README.md. Blocks project-wide SSH keys.
  #checkov:skip=CKV_GCP_38:Not in the brief. Added by the extended module, see ../README.md. Customer-supplied disk keys.
  #checkov:skip=CKV_GCP_39:Not in the brief. Added by the extended module, see ../README.md. Shielded VM.
  project      = var.project_id
  name         = "${var.name}-bastion"
  zone         = var.zone
  machine_type = var.bastion_machine_type

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 10
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.public.id

    # An empty access_config gives the bastion an ephemeral external IP.
    access_config {}
  }

  service_account {
    email  = google_service_account.bastion.email
    scopes = ["https://www.googleapis.com/auth/logging.write"] # The account holds no roles, so IAM allows nothing anyway.
  }

  depends_on = [terraform_data.validations]
}

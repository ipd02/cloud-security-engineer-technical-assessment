resource "google_compute_instance" "web" {
  project        = var.project_id
  name           = "${var.name}-web"
  zone           = var.zone
  machine_type   = var.machine_type
  can_ip_forward = false
  labels         = local.labels

  allow_stopping_for_update = true

  boot_disk {
    kms_key_self_link = var.kms_key_self_link

    initialize_params {
      image  = var.boot_image
      size   = var.boot_disk_size_gb
      type   = "pd-balanced"
      labels = local.labels
    }
  }

  # Private subnet, no access_config block, so no external IP.
  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  service_account {
    email = google_service_account.web.email
    # Scopes match the two roles in iam.tf, so a stolen token cannot call
    # other APIs even if a role is added later by mistake.
    scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
    ]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # The script goes in metadata, not metadata_startup_script: that argument
  # forces a new instance on every edit. It runs at boot, so reset the
  # instance to run an edited script.
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
    startup-script         = file("${path.module}/scripts/startup.sh")
  }

  depends_on = [
    google_project_iam_member.web,
    google_compute_router_nat.this,
  ]
}

# Replacing the instance (a new image, disk or network) drops it from an
# unmanaged group, and the instance id string does not change, so Terraform
# plans an update it then skips. Run apply a second time after such a
# replacement: the refresh sees the empty group and adds the instance back.
# Editing the startup script does not replace the instance, see the metadata
# block above.
resource "google_compute_instance_group" "web" {
  project   = var.project_id
  name      = "${var.name}-web-ig"
  zone      = var.zone
  network   = google_compute_network.vpc.id
  instances = [google_compute_instance.web.self_link]

  named_port {
    name = "http"
    port = 80
  }
}

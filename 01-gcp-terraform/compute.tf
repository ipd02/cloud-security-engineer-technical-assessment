resource "google_compute_instance" "web" {
  project        = var.project_id
  name           = "${var.name}-web"
  zone           = var.zone
  machine_type   = var.machine_type
  can_ip_forward = false
  labels         = local.labels

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
    email  = google_service_account.web.email
    scopes = ["cloud-platform"] # Access is limited by IAM roles, not by scopes.
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

  metadata_startup_script = file("${path.module}/scripts/startup.sh")

  depends_on = [
    google_project_iam_member.web,
    google_compute_router_nat.this,
  ]
}

resource "google_compute_instance_group" "web" {
  project   = var.project_id
  name      = "${var.name}-web-ig"
  zone      = var.zone
  network   = google_compute_network.vpc.id
  instances = [google_compute_instance.web.id]

  named_port {
    name = "http"
    port = 80
  }
}

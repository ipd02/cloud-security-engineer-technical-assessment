resource "google_compute_instance" "web" {
  #checkov:skip=CKV_GCP_32:Not in the brief. Added by the extended module, see ../README.md. Blocks project-wide SSH keys.
  #checkov:skip=CKV_GCP_38:Not in the brief. Added by the extended module, see ../README.md. Customer-supplied disk keys.
  #checkov:skip=CKV_GCP_39:Not in the brief. Added by the extended module, see ../README.md. Shielded VM.
  project      = var.project_id
  name         = "${var.name}-web"
  zone         = var.zone
  machine_type = var.machine_type

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = var.boot_image
    }
  }

  # In the private subnet. No access_config block, so no external IP.
  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  service_account {
    email = google_service_account.web.email
    # Scopes match the two roles in iam.tf.
    scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
    ]
  }

  # Serves a test page on port 80 so the load balancer path can be checked.
  # It runs at boot. The script is in metadata, not metadata_startup_script,
  # so editing it updates the instance in place instead of replacing it.
  metadata = {
    startup-script = file("${path.module}/scripts/startup.sh")
  }
}

# The load balancer needs an instance group. GCP drops a replaced instance
# from an unmanaged group and the instance id does not change, so after a real
# replacement (new image or disk) run apply a second time to re-add it.
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

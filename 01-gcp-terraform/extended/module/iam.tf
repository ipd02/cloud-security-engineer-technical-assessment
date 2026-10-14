# Dedicated service account for the instance. The default compute service
# account holds roles/editor and is never used.
resource "google_service_account" "web" {
  project      = var.project_id
  account_id   = "${var.name}-web"
  display_name = "${var.name} web instance"
  description  = "Runs the web instance. Can only write logs and metrics."
}

locals {
  web_instance_roles = [
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ]
}

# Non-authoritative on purpose: google_project_iam_member adds one member to
# one role and leaves every other binding on the project alone.
resource "google_project_iam_member" "web" {
  for_each = toset(local.web_instance_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.web.email}"
}

# SSH access goes through OS Login. The bindings sit on the two instances, not
# on the project, and use roles/compute.osLogin, which gives no sudo. GCP drops
# an instance's bindings when the instance is replaced, and the instance name
# does not change, so each binding is replaced with its instance.
resource "google_compute_instance_iam_member" "os_login_web" {
  for_each = toset(var.ssh_login_members)

  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.web.name
  role          = "roles/compute.osLogin"
  member        = each.value

  lifecycle {
    replace_triggered_by = [google_compute_instance.web.instance_id]
  }
}

resource "google_compute_instance_iam_member" "os_login_bastion" {
  for_each = var.enable_bastion ? toset(var.ssh_login_members) : toset([])

  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.bastion[0].name
  role          = "roles/compute.osLogin"
  member        = each.value

  lifecycle {
    replace_triggered_by = [google_compute_instance.bastion[0].instance_id]
  }
}

# IAP tunnel use, on the web instance only, only when the IAP rule exists.
resource "google_iap_tunnel_instance_iam_member" "iap_web" {
  for_each = var.enable_iap_ssh ? toset(var.ssh_login_members) : toset([])

  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.web.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value

  lifecycle {
    replace_triggered_by = [google_compute_instance.web.instance_id]
  }
}

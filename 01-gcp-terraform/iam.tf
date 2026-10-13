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

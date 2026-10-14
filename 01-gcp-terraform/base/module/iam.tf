# Bonus: least-privilege IAM. A dedicated service account for the instance
# with only the two roles it needs to write logs and metrics. No
# roles/editor, no roles/owner, and the default compute account is not used.
resource "google_service_account" "web" {
  project      = var.project_id
  account_id   = "${var.name}-web"
  display_name = "${var.name} instance"
  description  = "Runs the Compute Engine instance. Can only write logs and metrics."
}

locals {
  instance_roles = [
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ]
}

# Non-authoritative: adds one member to one role and leaves every other
# binding on the project alone.
resource "google_project_iam_member" "web" {
  for_each = toset(local.instance_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.web.email}"
}

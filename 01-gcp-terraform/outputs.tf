output "load_balancer_ip" {
  description = "Global IPv4 address of the HTTPS load balancer. Point DNS for var.domains here."
  value       = google_compute_global_address.lb.address
}

output "instance_name" {
  description = "Name of the web instance."
  value       = google_compute_instance.web.name
}

output "instance_internal_ip" {
  description = "Internal IP of the web instance. It has no external IP."
  value       = google_compute_instance.web.network_interface[0].network_ip
}

output "instance_service_account" {
  description = "Email of the dedicated instance service account."
  value       = google_service_account.web.email
}

output "vpc_id" {
  description = "Id of the VPC."
  value       = google_compute_network.vpc.id
}

output "public_subnet_id" {
  description = "Id of the public subnet."
  value       = google_compute_subnetwork.public.id
}

output "private_subnet_id" {
  description = "Id of the private subnet."
  value       = google_compute_subnetwork.private.id
}

output "security_policy_id" {
  description = "Id of the Cloud Armor policy."
  value       = google_compute_security_policy.edge.id
}

# One module call per environment, each pointed at its own project. Separate
# projects keep IAM, quotas and blast radius apart. Nothing else is shared.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  region = "europe-west1"
}

module "web_dev" {
  source = "../.."

  project_id        = "example-dev-project"
  name              = "web-dev"
  trusted_ssh_cidrs = ["203.0.113.0/24"] # documentation range, replace with your office or VPN egress
  domains           = ["dev.example.com"]
}

output "load_balancer_ip" {
  description = "Address to point dev.example.com at."
  value       = module.web_dev.load_balancer_ip
}

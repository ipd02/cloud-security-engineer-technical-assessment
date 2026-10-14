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

module "web" {
  source = "../../module"

  project_id = "example-project"
  name       = "web"
  # Documentation range. Replace it with your office or VPN egress range.
  trusted_ssh_cidrs = ["203.0.113.0/24"]
  domains           = ["www.example.com"]
}

output "load_balancer_ip" {
  description = "Address to point www.example.com at."
  value       = module.web.load_balancer_ip
}

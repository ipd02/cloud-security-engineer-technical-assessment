variable "project_id" {
  description = "GCP project that receives all resources. Use one project per environment."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project id (6-30 chars, lowercase letters, digits, hyphens)."
  }
}

variable "name" {
  description = "Name prefix for every resource. Lowercase letters, digits and hyphens, at most 20 characters."
  type        = string
  default     = "secure-web"

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,18}[a-z0-9])?$", var.name))
    error_message = "name must start with a letter, use only lowercase letters, digits and hyphens, and be at most 20 characters."
  }
}

variable "region" {
  description = "Region for the subnets, Cloud Router, Cloud NAT and the instance."
  type        = string
  default     = "europe-west1"
}

variable "zone" {
  description = "Zone for the instance and the instance group. Must be inside var.region."
  type        = string
  default     = "europe-west1-b"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+-[a-z]$", var.zone))
    error_message = "zone must look like europe-west1-b."
  }
}

variable "public_subnet_cidr" {
  description = "CIDR of the public subnet. No instance runs here, see the README."
  type        = string
  default     = "10.10.0.0/24"

  validation {
    condition     = can(cidrhost(var.public_subnet_cidr, 0))
    error_message = "public_subnet_cidr must be a valid IPv4 CIDR."
  }
}

variable "private_subnet_cidr" {
  description = "CIDR of the private subnet that hosts the instance."
  type        = string
  default     = "10.10.1.0/24"

  validation {
    condition     = can(cidrhost(var.private_subnet_cidr, 0))
    error_message = "private_subnet_cidr must be a valid IPv4 CIDR."
  }
}

variable "trusted_ssh_cidrs" {
  description = <<-EOT
    IPv4 source ranges allowed to reach tcp/22 on the bastion (and on the web
    instance, for ranges that reach the VPC privately). Required, no default.
    The web instance has no external IP, so public ranges get in through the
    bastion. See the README.
    Rejected: null, an empty list, anything that is not a canonical IPv4 CIDR (IPv6,
    host bits set, whitespace), 0.0.0.0/0, any prefix shorter than /8, and a list
    that adds up to more than 16,777,216 addresses (one /8) in total, so a long list
    of /8s cannot rebuild the internet.
  EOT
  type        = list(string)
  nullable    = false

  validation {
    condition     = length(var.trusted_ssh_cidrs) > 0
    error_message = "trusted_ssh_cidrs must contain at least one CIDR."
  }

  validation {
    condition = alltrue([
      for c in var.trusted_ssh_cidrs :
      can(regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2}$", c)) && try(cidrsubnet(c, 0, 0) == c, false)
    ])
    error_message = "Every entry in trusted_ssh_cidrs must be a canonical IPv4 CIDR such as 203.0.113.0/24 (no host bits, no spaces, no IPv6)."
  }

  validation {
    condition     = !contains(var.trusted_ssh_cidrs, "0.0.0.0/0")
    error_message = "trusted_ssh_cidrs must not contain 0.0.0.0/0."
  }

  validation {
    condition     = alltrue([for c in var.trusted_ssh_cidrs : try(tonumber(split("/", c)[1]) >= 8, false)])
    error_message = "trusted_ssh_cidrs entries must be at least a /8."
  }

  validation {
    condition     = try(sum([for c in distinct(var.trusted_ssh_cidrs) : pow(2, 32 - tonumber(split("/", c)[1]))]) <= 16777216, false)
    error_message = "trusted_ssh_cidrs may cover at most 16,777,216 addresses in total (one /8)."
  }
}

variable "enable_bastion" {
  description = "Create an SSH bastion in the public subnet. It takes SSH from trusted_ssh_cidrs and is the only host allowed to SSH to the private web instance. Turn off only if trusted_ssh_cidrs reaches the VPC privately (VPN, Interconnect, peering)."
  type        = bool
  default     = true
}

variable "bastion_machine_type" {
  description = "Machine type of the bastion."
  type        = string
  default     = "e2-micro"
}

variable "enable_iap_ssh" {
  description = "Also allow SSH from the Identity-Aware Proxy range 35.235.240.0/20 so admins can use IAP TCP forwarding. Default off."
  type        = bool
  default     = false
}

variable "domains" {
  description = "Domains for a Google-managed certificate. Set this or existing_ssl_certificate_id, not both."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for d in var.domains : can(regex("^([a-z0-9-]+\\.)+[a-z]{2,}$", d))])
    error_message = "Every domain must be a lowercase fully qualified domain name."
  }

  validation {
    condition     = length(var.domains) <= 100
    error_message = "A Google-managed certificate supports at most 100 domains."
  }
}

variable "existing_ssl_certificate_id" {
  description = "Self link or id of an existing SSL certificate. Set this or domains, not both. Terraform never creates private keys."
  type        = string
  default     = null
}

variable "machine_type" {
  description = "Machine type of the web instance."
  type        = string
  default     = "e2-small"
}

variable "boot_image" {
  description = "Boot image family. Must support Shielded VM. Default is Debian 13 (trixie); Debian 12 left regular security support in July 2026."
  type        = string
  default     = "projects/debian-cloud/global/images/family/debian-13"
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB."
  type        = number
  default     = 20

  validation {
    condition     = var.boot_disk_size_gb >= 10 && var.boot_disk_size_gb <= 200
    error_message = "boot_disk_size_gb must be between 10 and 200."
  }
}

variable "kms_key_self_link" {
  description = "Optional Cloud KMS key (CMEK) for the boot disk. Null uses Google-managed encryption."
  type        = string
  default     = null
}

variable "rate_limit_requests_per_minute" {
  description = "Cloud Armor per-client-IP request limit over 60 seconds. Requests above it get HTTP 429."
  type        = number
  default     = 300

  validation {
    condition     = var.rate_limit_requests_per_minute >= 10 && var.rate_limit_requests_per_minute <= 100000
    error_message = "rate_limit_requests_per_minute must be between 10 and 100000."
  }
}

variable "labels" {
  description = "Extra labels applied to every resource that supports labels."
  type        = map(string)
  default     = {}
}

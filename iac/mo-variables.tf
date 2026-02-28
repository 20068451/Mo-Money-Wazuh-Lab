variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "project_tag" {
  type    = string
  default = "Mo_Wazuh_Lab"
}

variable "your_ip_cidr" {
  description = "Your public IP in CIDR (optional). Example: 1.2.3.4/32. Not needed if you use SSM only."
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}

variable "linux_ami_name" {
  description = "Ubuntu 22.04 LTS AMD64"
  type        = string
  default     = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
}

variable "windows_ami_name" {
  description = "Windows Server 2022 Base"
  type        = string
  default     = "Windows_Server-2022-English-Full-Base-*"
}

variable "key_name" {
  description = "EC2 Key Pair name. Needed to decrypt Windows Administrator password."
  type        = string
  default     = "mo-wazuh-lab-key"
}

variable "public_key_path" {
  description = "Path to your SSH public key in WSL (e.g. ~/.ssh/id_rsa.pub). Used to create AWS key pair."
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}


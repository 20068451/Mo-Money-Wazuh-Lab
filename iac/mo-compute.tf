# Key pair (needed to decrypt Windows Administrator password)
resource "aws_key_pair" "this" {
  key_name   = var.key_name
  public_key = file(pathexpand(var.public_key_path))

  tags = { Name = "${var.project_tag}-keypair" }
}

# AMIs
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = [var.linux_ami_name]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = [var.windows_ami_name]
  }
}

# User data scripts
locals {
  wazuh_user_data = <<-EOF
    #!/bin/bash
    set -eux

    apt-get update
    apt-get install -y amazon-ssm-agent chrony docker.io docker-compose-plugin unzip jq
    systemctl enable --now amazon-ssm-agent
    systemctl enable --now chrony
    systemctl enable --now docker

    # Helpful: allow ubuntu user to run docker without sudo
    usermod -aG docker ubuntu || true
  EOF

  linux_endpoint_user_data = <<-EOF
    #!/bin/bash
    set -eux

    apt-get update
    apt-get install -y amazon-ssm-agent chrony auditd unzip jq
    systemctl enable --now amazon-ssm-agent
    systemctl enable --now chrony
    systemctl enable --now auditd
  EOF
}

resource "aws_instance" "wazuh" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "c7i-flex.large"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.wazuh.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm_profile.name
  key_name               = aws_key_pair.this.key_name

  user_data = local.wazuh_user_data

  root_block_device {
    volume_size = 40
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project_tag}-wazuh-server"
    Role = "wazuh"
  }
}

resource "aws_instance" "linux_endpoint" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.endpoints.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm_profile.name
  key_name               = aws_key_pair.this.key_name

  user_data = local.linux_endpoint_user_data

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project_tag}-linux-endpoint"
    Role = "linux-endpoint"
  }
}

resource "aws_instance" "windows_endpoint" {
  ami                    = data.aws_ami.windows.id
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.endpoints.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm_profile.name
  key_name               = aws_key_pair.this.key_name

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project_tag}-windows-endpoint"
    Role = "windows-endpoint"
  }
}


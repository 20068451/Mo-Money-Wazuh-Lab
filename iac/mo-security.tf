# Endpoints SG (Linux + Windows) - no inbound from internet
resource "aws_security_group" "endpoints" {
  name        = "${var.project_tag}-endpoints-sg"
  description = "Endpoints SG - no inbound; outbound allowed"
  vpc_id      = aws_vpc.this.id

  # No ingress rules = no inbound allowed

  egress {
    description = "Allow all outbound (updates + SSM + downloads)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_tag}-endpoints-sg" }
}

# Wazuh server SG
resource "aws_security_group" "wazuh" {
  name        = "${var.project_tag}-wazuh-sg"
  description = "Wazuh SG - allow agent ports from endpoints SG only"
  vpc_id      = aws_vpc.this.id

  # Wazuh agent communication ports (common defaults)
  ingress {
    description     = "Wazuh agents (TCP 1514) from endpoints SG"
    from_port       = 1514
    to_port         = 1514
    protocol        = "tcp"
    security_groups = [aws_security_group.endpoints.id]
  }

  ingress {
    description     = "Wazuh agents (UDP 1514) from endpoints SG"
    from_port       = 1514
    to_port         = 1514
    protocol        = "udp"
    security_groups = [aws_security_group.endpoints.id]
  }

  ingress {
    description     = "Wazuh registration/service (TCP 1515) from endpoints SG"
    from_port       = 1515
    to_port         = 1515
    protocol        = "tcp"
    security_groups = [aws_security_group.endpoints.id]
  }

  # No public dashboard access. We'll access dashboard via SSM port-forward.
  # (Optional) If you want temporary access from your IP, uncomment below and set var.your_ip_cidr.
  # ingress {
  #   description = "TEMP: Wazuh dashboard (443) from your IP only"
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = var.your_ip_cidr != "" ? [var.your_ip_cidr] : []
  # }

  egress {
    description = "Allow all outbound (updates + Docker pulls + SSM)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_tag}-wazuh-sg" }
}


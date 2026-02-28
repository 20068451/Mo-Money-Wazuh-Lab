output "project_tag" {
  value = var.project_tag
}

output "wazuh_instance_id" {
  value = aws_instance.wazuh.id
}

output "linux_endpoint_instance_id" {
  value = aws_instance.linux_endpoint.id
}

output "windows_endpoint_instance_id" {
  value = aws_instance.windows_endpoint.id
}

output "wazuh_public_ip" {
  value = aws_instance.wazuh.public_ip
}

output "linux_public_ip" {
  value = aws_instance.linux_endpoint.public_ip
}

output "windows_public_ip" {
  value = aws_instance.windows_endpoint.public_ip
}

output "wazuh_private_ip" {
  value = aws_instance.wazuh.private_ip
}

output "linux_private_ip" {
  value = aws_instance.linux_endpoint.private_ip
}

output "windows_private_ip" {
  value = aws_instance.windows_endpoint.private_ip
}

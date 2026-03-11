#cloud-config
users:
  - default
  - name: ${ssh_username}
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    shell: /bin/bash
    plain_text_passwd: ${ssh_password}
%{ if ssh_public_key != "" ~}
    ssh_authorized_keys:
      - ${ssh_public_key}
%{ endif ~}
ssh_pwauth: true
package_update: false
package_upgrade: false
runcmd:
  - [ bash, -lc, "mkdir -p /tmp/packer-ready" ]

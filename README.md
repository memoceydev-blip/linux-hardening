# linux-hardening
CIS Level 2 Compatible Disk Layout — VM (200 GB Fully Allocated)
| Mount Point | Size | FilesystemL | VM Volume Name| Mount Options (/etc/fstab) | CIS Requirement / Purpose |
|-------------|------|-------------|---------------|----------------------------|---------------------------|
| /boot/efi | 1 GB | FAT32 | N/A | (Standard)|defaults|UEFI Bootloader partition|
| /boot| 2 GB | ext4 | N/A | (Standard)|defaults,nosuid,nodev|Kernel images|
| / (root)| 35 GB|ext4|ubuntu--vg-root|defaults|Core OS binaries, system files, & packages|
| /tmp | 10 GB|ext4| / tmpfs ubuntu--vg-tmp|defaults,nodev,nosuid,noexec|Temporary files (isolated)|
| /var | 20 GB| ext4|ubuntu--vg-var| defaults,nodev| Variable data |
|/var/tmp|10 GB|ext4|ubuntu--vg-var-tmp|defaults,nodev,nosuid,noexec|Temporary storage (separate partition/mount)|
|/var/log|45 GB|ext4|ubuntu--vg-var-log|defaults,nodev,nosuid,noexec|System & application log storage|
|/var/log/audit|35 GB|ext4|ubuntu--vg-audit|defaults,nodev,nosuid,noexec|Dedicated audit daemon (auditd) logs|
|/home| 42 GB|ext4|ubuntu--vg-home|defaults,nodev,nosuid|User directories|
|/dev/shm| Dynamic|tmpfs|N/A (Kernel)|defaults,nodev,nosuid,noexec|Shared memory (configured via fstab)|
|Total Disk|200 GB|—|—|

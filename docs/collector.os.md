# os collector

The os collector exposes metrics about the operating system

|||
-|-
Metric name prefix  | `os`
Data sources         | Registry, [`GetSystemFirmwareTable`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable) (SMBIOS)
Enabled by default? | Yes

## Flags

None

## Metrics

| Name                                         | Description                                                                                                                                                    | Type  | Labels                                                                                                          |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|-----------------------------------------------------------------------------------------------------------------|
| `windows_os_hostname`                        | Labelled system hostname information as provided by ComputerSystem.DNSHostName and ComputerSystem.Domain                                                       | gauge | `domain`, `fqdn`, `hostname`                                                                                    |
| `windows_os_info`                            | Contains full product name & version in labels. Note that the `major_version` for Windows 11 is "10"; a build number greater than 22000 represents Windows 11. | gauge | `product`, `version`, `major_version`, `minor_version`, `build_number`, `revision`, `installation_type`         |
| `windows_os_smbios_info`                     | System product information from SMBIOS. On VMs, reflects hypervisor-assigned identity; on physical hosts, reflects hardware SMBIOS data.                        | gauge | `uuid`, `vendor`, `name`, `identifying_number`, `version`                                                        |
| `windows_os_install_time_timestamp_seconds`  | Unix timestamp of OS installation time                                                                                                                         | gauge | None                                                                                                            |

The `uuid` label on `windows_os_smbios_info` is normalized to lowercase. If SMBIOS data cannot be read (e.g. in some container environments), the metric is silently omitted.

### Example metric

```
# HELP windows_os_hostname Labelled system hostname information as provided by ComputerSystem.DNSHostName and ComputerSystem.Domain
# TYPE windows_os_hostname gauge
windows_os_hostname{domain="",fqdn="PC",hostname="PC"} 1
# HELP windows_os_info Contains full product name & version in labels. Note that the "major_version" for Windows 11 is \\"10\\"; a build number greater than 22000 represents Windows 11.
# TYPE windows_os_info gauge
windows_os_info{build_number="19045",installation_type="Client",major_version="10",minor_version="0",product="Windows 10 Pro",revision="4842",version="10.0.19045"} 1
# HELP windows_os_smbios_info System product information from SMBIOS.
# TYPE windows_os_smbios_info gauge
windows_os_smbios_info{uuid="12345678-1234-1234-1234-123456789abc",vendor="QEMU",name="Standard PC (Q35 + ICH9, 2009)",identifying_number="Not Specified",version="pc-q35-9.2"} 1
# HELP windows_os_install_time_timestamp_seconds Unix timestamp of OS installation time
# TYPE windows_os_install_time_timestamp_seconds gauge
windows_os_install_time_timestamp_seconds 1.6725312e+09
```

## Useful queries

### Correlate with libvirt_exporter

With [prometheus-libvirt-exporter](https://github.com/inovex/prometheus-libvirt-exporter), the domain UUID is exposed directly on `libvirt_domain_info_meta{uuid="..."}`. This UUID matches the SMBIOS UUID passed to the guest by QEMU/KVM.

Add the `uuid` label to any guest metric:

```promql
windows_memory_physical_free_bytes * on(job, instance) group_left(uuid) windows_os_smbios_info
```

Join a host-side libvirt metric with the guest-identified UUID (full guest→host chain):

```promql
libvirt_domain_info_memory_usage_bytes
  * on(job, instance, domain) group_left(uuid)
libvirt_domain_info_meta
  * on(uuid) group_left()
windows_os_smbios_info
```

This reads bottom-up: the guest's SMBIOS UUID resolves the host-side domain, which selects the host metric. The `job` and `instance` labels scope the join to a single libvirt host, preventing false matches when different hosts reuse domain names.

The UUID is normalized to lowercase on both sides for reliable matching.

## Alerting examples
_This collector does not yet have alerting examples, we would appreciate your help adding them!_

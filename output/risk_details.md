# Risk Details

## Per-Image Vulnerability Counts

| Image | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| nginx:1.25 (debian 12.5) | 13 | 45 | 0 | 0 | 0 | 84 |
| docker.io/bitnami/postgresql:16.3.0-debian-12-r19 (debian 12.6) | 5 | 35 | 0 | 0 | 0 | 50 |
| docker.io/bitnami/mysql:8.4.3-debian-12-r5 (debian 12.8) | 1 | 17 | 0 | 0 | 0 | 20 |
| docker.io/bitnami/redis:7.4.3-debian-12-r0 (debian 12.10) | 1 | 12 | 0 | 0 | 0 | 15 |
| opt/bitnami/postgresql | 0 | 5 | 0 | 0 | 0 | 5 |
| opt/bitnami/redis | 0 | 2 | 0 | 0 | 0 | 2 |
| opt/bitnami/common/.spdx-ini-file.spdx | 0 | 1 | 0 | 0 | 0 | 1 |
| opt/bitnami/common/bin/ini-file | 0 | 1 | 0 | 0 | 0 | 1 |
| opt/bitnami/common/.spdx-wait-for-port.spdx | 0 | 1 | 0 | 0 | 0 | 1 |
| opt/bitnami/common/bin/wait-for-port | 0 | 1 | 0 | 0 | 0 | 1 |


## Top Findings per Image

### docker.io/bitnami/mysql:8.4.3-debian-12-r5 (debian 12.8)
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| CRITICAL | CVE-2023-45853 | 9.8 | zlib1g |
| HIGH | CVE-2025-32990 | 8.2 | libgnutls30 |
| HIGH | CVE-2023-31484 | 8.1 | libperl5.36 |
| HIGH | CVE-2023-31484 | 8.1 | perl |
| HIGH | CVE-2023-31484 | 8.1 | perl-base |


### docker.io/bitnami/postgresql:16.3.0-debian-12-r19 (debian 12.6)
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| CRITICAL | CVE-2025-6965 | 9.8 | libsqlite3-0 |
| CRITICAL | CVE-2023-45853 | 9.8 | zlib1g |
| CRITICAL | CVE-2025-7458 | 9.1 | libsqlite3-0 |
| CRITICAL | CVE-2025-49794 | 9.1 | libxml2 |
| CRITICAL | CVE-2025-49796 | 9.1 | libxml2 |


### docker.io/bitnami/redis:7.4.3-debian-12-r0 (debian 12.10)
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| CRITICAL | CVE-2023-45853 | 9.8 | zlib1g |
| HIGH | CVE-2025-32990 | 8.2 | libgnutls30 |
| HIGH | CVE-2023-31484 | 8.1 | libperl5.36 |
| HIGH | CVE-2023-31484 | 8.1 | perl |
| HIGH | CVE-2023-31484 | 8.1 | perl-base |


### nginx:1.25 (debian 12.5)
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| CRITICAL | CVE-2025-0838 | 9.8 | libabsl20220623 |
| CRITICAL | CVE-2023-6879 | 9.8 | libaom3 |
| CRITICAL | CVE-2024-5171 | 9.8 | libaom3 |
| CRITICAL | CVE-2024-45491 | 9.8 | libexpat1 |
| CRITICAL | CVE-2024-45492 | 9.8 | libexpat1 |


### opt/bitnami/common/.spdx-ini-file.spdx
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| HIGH | CVE-2025-47907 | 7.0 | stdlib |


### opt/bitnami/common/.spdx-wait-for-port.spdx
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| HIGH | CVE-2025-47907 | 7.0 | stdlib |


### opt/bitnami/common/bin/ini-file
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| HIGH | CVE-2025-47907 | 7.0 | stdlib |


### opt/bitnami/common/bin/wait-for-port
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| HIGH | CVE-2025-47907 | 7.0 | stdlib |


### opt/bitnami/postgresql
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| HIGH | CVE-2024-10979 | 8.8 | postgresql |
| HIGH | CVE-2025-8714 | 8.8 | postgresql |
| HIGH | CVE-2025-8715 | 8.8 | postgresql |
| HIGH | CVE-2025-1094 | 8.1 | postgresql |
| HIGH | CVE-2024-7348 | 7.5 | postgresql |


### opt/bitnami/redis
| Severity | CVE | CVSS | Package |
| --- | --- | --- | --- |
| HIGH | CVE-2025-48367 | 7.5 | redis |
| HIGH | CVE-2025-32023 | 7.0 | redis |


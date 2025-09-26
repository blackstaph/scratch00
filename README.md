Here’s a comprehensive **README.md** you can ship alongside your extended `safeguardcredentials.py` plugin. It explains usage in Ansible Core and in **Red Hat Ansible Automation Platform (AAP)**, including integration with a **custom Safeguard Credential Type**.

---

# Safeguard Ansible Lookup Plugin (Extended)

This plugin is a **drop-in replacement** for
[`oneidentity.safeguardcollection.safeguardcredentials`](https://github.com/OneIdentity/safeguard-ansible).
It extends functionality so that **if no ApiKey is passed**, the plugin can discover one dynamically using a **System Name + Account Name** combination.

## Features

* **Drop-in replacement**: all parameters and keys remain unchanged (`spp_*` keys, positional ApiKey, etc.).

* **Two modes of operation**:

  * **Direct**: supply an `ApiKey` as the first positional argument.
  * **Discovery**: pass `''` as the ApiKey, plus `spp_systemname` and `spp_username`. The plugin will:

    1. Authenticate with cert+key.
    2. Call Core `/service/core/v4/A2ARegistrations`.
    3. Select the registration ID by `spp_registration_index`.
    4. Call `/A2ARegistrations/{id}/RetrievableAccounts`.
    5. Match the given system+username → extract the `ApiKey`.
    6. Use the discovered ApiKey with `a2a_get_credential` to retrieve the password or private key.

* **Supports both password and private key retrieval.**

---

## Requirements

* Python `pysafeguard` package installed in your Ansible Execution Environment or control node.
* A valid **Safeguard A2A registration** bound to the client certificate and key.
* Unencrypted private key PEM file.
* A CA bundle if TLS verification is enabled.

---

## Options

| Option                   | Required    | Description                                                                    |
| ------------------------ | ----------- | ------------------------------------------------------------------------------ |
| `a2aconnection`          | yes         | Dict of Safeguard connection parameters (see below).                           |
| `spp_appliance`          | yes         | Safeguard appliance hostname or IP.                                            |
| `spp_certificate_file`   | yes         | Path to the client certificate PEM.                                            |
| `spp_certificate_key`    | yes         | Path to the unencrypted client private key PEM.                                |
| `spp_tls_cert`           | if validate | Path to CA bundle PEM.                                                         |
| `spp_validate_certs`     | no          | Whether to validate HTTPS certificates (default: `true`).                      |
| `spp_credential_type`    | yes         | Either `password` or `privatekey`.                                             |
| `spp_systemname`         | no          | System/Asset name for discovery.                                               |
| `spp_username`           | no          | Account name for discovery.                                                    |
| `spp_registration_index` | no          | Zero-based index to select registration from `/A2ARegistrations` (default: 0). |

---

## Examples

### 1. With explicit ApiKey

```yaml
- name: Retrieve password with known ApiKey
  set_fact:
    my_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                my_apikey,
                a2aconnection={
                  'spp_appliance': host,
                  'spp_certificate_file': cert,
                  'spp_certificate_key': key,
                  'spp_tls_cert': cacert,
                  'spp_credential_type': 'password',
                  'spp_validate_certs': true
                }) }}
```

### 2. With system+username discovery

```yaml
- name: Retrieve password using discovery
  set_fact:
    my_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                '',
                a2aconnection={
                  'spp_appliance': host,
                  'spp_certificate_file': cert,
                  'spp_certificate_key': key,
                  'spp_tls_cert': cacert,
                  'spp_credential_type': 'password',
                  'spp_validate_certs': true
                },
                spp_systemname='CSDevExtDomain',
                spp_username='svc.aap_spe_win',
                spp_registration_index=0) }}
```

---

# Using with Ansible Automation Platform (AAP)

## 1. Create a Custom Credential Type

Go to **Controller / Credentials / Credential Types** → **Add**.

### Name

```
Safeguard Credential
```

### Inputs (YAML)

```yaml
fields:
  - id: spp_appliance
    type: string
    label: Safeguard Appliance
  - id: spp_api_key
    type: string
    label: ApiKey (optional)
    secret: true
  - id: spp_system_name
    type: string
    label: System Name (for discovery)
  - id: spp_account_name
    type: string
    label: Account Name (for discovery)
  - id: spp_credential_type
    type: string
    label: Credential Type
    choices:
      - password
      - privatekey
  - id: spp_catrust_path
    type: string
    label: Path to CA bundle
  - id: spp_public_key_path
    type: string
    label: Path to client cert PEM
  - id: spp_private_key_path
    type: string
    label: Path to client key PEM
    secret: true
```

### Injectors (YAML)

```yaml
env:
  SPP_APPLIANCE: '{{ spp_appliance }}'
  SPP_API_KEY: '{{ spp_api_key }}'
  SPP_SYSTEM_NAME: '{{ spp_system_name }}'
  SPP_ACCOUNT_NAME: '{{ spp_account_name }}'
  SPP_CRED_TYPE: '{{ spp_credential_type }}'
  SPP_CA_PATH: '{{ spp_catrust_path }}'
  SPP_CERT_PATH: '{{ spp_public_key_path }}'
  SPP_KEY_PATH: '{{ spp_private_key_path }}'
```

## 2. Create a Credential

Use the custom type “Safeguard Credential” and fill in the appropriate fields.

## 3. Use in a Playbook

```yaml
- name: Test Safeguard credential retrieval
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Build connection dict
      set_fact:
        a2a_conn:
          spp_appliance: "{{ lookup('env','SPP_APPLIANCE') }}"
          spp_certificate_file: "{{ lookup('env','SPP_CERT_PATH') }}"
          spp_certificate_key: "{{ lookup('env','SPP_KEY_PATH') }}"
          spp_tls_cert: "{{ lookup('env','SPP_CA_PATH') }}"
          spp_credential_type: "{{ lookup('env','SPP_CRED_TYPE') }}"
          spp_validate_certs: true

    - name: Retrieve password
      set_fact:
        spp_password: >-
          {{
            lookup(
              'oneidentity.safeguardcollection.safeguardcredentials',
              (lookup('env','SPP_API_KEY')),
              a2aconnection=a2a_conn,
              spp_systemname=(lookup('env','SPP_SYSTEM_NAME') or omit),
              spp_username=(lookup('env','SPP_ACCOUNT_NAME') or omit),
              spp_registration_index=0
            )
          }}
      no_log: true

    - debug:
        msg: "Safeguard password retrieved."
      no_log: true
```

---

## Error Handling

* `A2ARegistrations returned empty list`: no registrations available for the cert.
* `ApiKey not found for system=... account=...`: cert does not grant access to that account.
* `certificate connect failed`: invalid cert/key pair.
* `A2A retrieval failed`: ApiKey invalid or insufficient permissions.

---

Would you like me to also generate a **zip bundle** with:

* `README.md`
* `safeguardcredentials.py` (extended plugin)
* `playbook.yml` (AAP example)

so you can drop it directly into your collection and test?

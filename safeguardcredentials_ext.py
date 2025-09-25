from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
import os, json

class LookupModule(LookupBase):
    """
    Extends behavior:
      - Accept either:
          * target_api_key=<api_key>   (preferred)
          * system=<AssetName>, account=<AccountName>  (derive ApiKey via Core and use it)
      - First positional term remains the secret type: 'Password' or 'PrivateKey'.
    """

    def run(self, terms, variables=None, **kwargs):
        # 1) secret type from _terms, default to 'Password'
        if not terms:
            raise AnsibleError("usage: lookup('...safeguardcredentials', 'Password'|'PrivateKey', ...)")
        secret_type = terms[0]

        # 2) normalize connection args (supports either a2aconnection dict or flat args)
        a2a = kwargs.get("a2aconnection") or {}
        appliance = kwargs.get("appliance") or kwargs.get("appliance_address") or a2a.get("appliance") or a2a.get("appliance_address")
        if not appliance:
            raise AnsibleError("Missing appliance/appliance_address")

        cert_file = kwargs.get("certificate_file") or a2a.get("certificate_file")
        key_file  = kwargs.get("key_file")        or a2a.get("key_file")
        ca_bundle = kwargs.get("ca_bundle")       or a2a.get("ca_bundle")
        api_version = kwargs.get("api_version")   or a2a.get("api_version") or "v4"
        validate_certs = kwargs.get("validate_certs", True)

        # 3) resolve api_key:
        api_key = kwargs.get("target_api_key")
        if not api_key:
            # allow discovery via system/account
            system  = kwargs.get("system")
            account = kwargs.get("account")
            if not (system and account):
                raise AnsibleError("Provide either target_api_key OR both system and account")
            api_key = self._discover_api_key_via_core(
                appliance, cert_file, key_file, ca_bundle, validate_certs, system, account
            )
            if not api_key:
                raise AnsibleError(f"ApiKey not found for system='{system}', account='{account}'")

        # 4) perform A2A retrieval using Authorization: A2A <api_key>
        secret = self._a2a_get_secret(
            appliance, api_version, cert_file, key_file, ca_bundle, validate_certs,
            secret_type, api_key
        )
        # lookup should return a list
        return [secret]

    # ---------------- helpers ----------------

    def _abs_ok(self, p, name):
        p = os.path.expanduser(os.path.expandvars(p or ""))
        if not (os.path.isfile(p) and os.path.getsize(p) > 0):
            raise AnsibleError(f"{name} not found or empty: {p!r}")
        return os.path.abspath(p)

    def _http_get(self, url, headers, cert_file, key_file, ca_bundle, validate_certs):
        kwargs = {
            "method": "GET",
            "headers": headers,
            "follow_redirects": "all",
            "timeout": 30,
        }
        if cert_file:
            kwargs["client_cert"] = self._abs_ok(cert_file, "certificate_file")
        if key_file:
            kwargs["client_key"]  = self._abs_ok(key_file,  "key_file")
        if validate_certs:
            kwargs["validate_certs"] = True
            if ca_bundle:
                kwargs["ca_path"] = self._abs_ok(ca_bundle, "ca_bundle")
        else:
            kwargs["validate_certs"] = False

        try:
            r = open_url(url, **kwargs)
            return r.read()
        except Exception as e:
            raise AnsibleError(f"GET {url} failed: {e}")

    def _get_json(self, url, headers, cert_file, key_file, ca_bundle, validate_certs, where):
        raw = self._http_get(url, headers, cert_file, key_file, ca_bundle, validate_certs)
        try:
            return json.loads(raw)
        except Exception:
            preview = (raw[:256].decode("utf-8","ignore") if isinstance(raw,(bytes,bytearray)) else str(raw))[:256]
            raise AnsibleError(f"{where}: Non-JSON from {url}: {preview!r}")

    def _discover_api_key_via_core(self, appliance, cert_file, key_file, ca_bundle, validate_certs, system, account):
        """
        Implements Core discovery:
          1) GET /service/core/v4/A2ARegistrations
          2) id = content[0].Id
          3) GET /service/core/v4/A2ARegistrations/{id}/RetrievableAccounts
          4) match (system, account) → ApiKey
        """
        base = f"https://{appliance}/service/core/v4"
        h = {"Accept":"application/json","Content-Type":"application/json"}

        regs = self._get_json(f"{base}/A2ARegistrations", h,
                              cert_file, key_file, ca_bundle, validate_certs,
                              "A2ARegistrations")
        if not isinstance(regs, list) or not regs:
            raise AnsibleError("A2ARegistrations returned empty list")

        reg = regs[0]
        reg_id = reg.get("Id") or reg.get("ID")
        if reg_id is None:
            raise AnsibleError(f"Registration missing Id: {reg}")

        page, limit = 0, 200
        while True:
            ras = self._get_json(f"{base}/A2ARegistrations/{reg_id}/RetrievableAccounts?page={page}&limit={limit}",
                                 h, cert_file, key_file, ca_bundle, validate_certs,
                                 "RetrievableAccounts")
            if not isinstance(ras, list) or not ras:
                break
            for ra in ras:
                asset_nm  = ra.get("AssetName")   or (ra.get("Asset")   or {}).get("Name")
                account_nm= ra.get("AccountName") or (ra.get("Account") or {}).get("Name")
                if asset_nm == system and account_nm == account:
                    api_key = ra.get("ApiKey")
                    if not api_key:
                        raise AnsibleError(f"Match found but ApiKey missing: {ra}")
                    return api_key
            page += 1
        return None

    def _a2a_get_secret(self, appliance, api_version, cert_file, key_file, ca_bundle, validate_certs, secret_type, api_key):
        """
        A2A retrieval with vendor-required header:
            Authorization: A2A <api_key>
        """
        url = f"https://{appliance}/service/a2a/{api_version}/credentials?type={secret_type}"
        headers = {"Accept": "application/json", "Authorization": f"A2A {api_key}"}
        raw = self._http_get(url, headers, cert_file, key_file, ca_bundle, validate_certs)

        # For Password, response is typically the secret as bytes; return text
        try:
            return raw.decode("utf-8", "ignore")
        except Exception:
            return str(raw)

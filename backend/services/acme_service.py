"""
ACME v2 (RFC 8555) client service for automated certificate management.
Supports Let's Encrypt, ZeroSSL, Google Trust Services, and any ACME-compatible CA.
"""
import aiohttp
import json
import logging
import hashlib
import base64
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509
import josepy as jose

from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)  # pad to a multiple of 4 (0 pad when already aligned)
    return base64.urlsafe_b64decode(s)


class ACMEService:
    """Async ACME v2 client with multi-provider support."""

    def __init__(self):
        self._directory_cache: Dict[str, dict] = {}
        # Anti-replay nonces are scoped PER CA (directory_url). A Replay-Nonce issued by one ACME
        # server must never be sent in a JWS to another, or the second server rejects it (e.g. ZeroSSL
        # "malformed: The Replay Nonce could not be base64url-decoded"). This client is a process-wide
        # singleton shared across CAs, so a single shared nonce was leaking across them.
        self._nonce_by_dir: Dict[str, str] = {}

    async def _get_settings(self) -> dict:
        conn = await get_database_connection()
        try:
            rows = await conn.fetch(
                "SELECT key, value FROM system_settings WHERE category = 'acme'"
            )
            settings = {}
            for row in rows:
                key = row['key'].split('.', 1)[1] if '.' in row['key'] else row['key']
                val = row['value']
                if isinstance(val, str):
                    try:
                        val = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        pass
                settings[key] = val
            return settings
        finally:
            await close_database_connection(conn)

    async def get_directory(self, directory_url: str) -> dict:
        if directory_url in self._directory_cache:
            cached = self._directory_cache[directory_url]
            if cached.get('_fetched_at', 0) > time.time() - 3600:
                return cached

        # SECURITY (GHSA-3vh4-gvxx-wm2p): directory_url can come from a stored
        # account row; validate it (https + public IP, no redirects) before the
        # server-side fetch so it cannot be pointed at internal/metadata targets.
        from utils.ssrf_guard import assert_public_url, safe_connector
        await assert_public_url(directory_url)

        async with aiohttp.ClientSession(connector=safe_connector()) as session:
            async with session.get(directory_url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=False) as resp:
                if resp.status != 200:
                    raise Exception(f"Failed to fetch ACME directory: HTTP {resp.status}")
                data = await resp.json()
                if 'Replay-Nonce' in resp.headers:
                    self._nonce_by_dir[directory_url] = resp.headers['Replay-Nonce']
                data['_fetched_at'] = time.time()
                self._directory_cache[directory_url] = data
                return data

    async def _get_nonce(self, directory_url: str) -> str:
        # Use a cached nonce for THIS CA only; otherwise fetch a fresh one from THIS CA's newNonce.
        cached = self._nonce_by_dir.pop(directory_url, None)
        if cached:
            return cached
        directory = await self.get_directory(directory_url)
        # get_directory may have just captured a nonce for this CA from the directory response.
        cached = self._nonce_by_dir.pop(directory_url, None)
        if cached:
            return cached
        async with aiohttp.ClientSession() as session:
            async with session.head(directory['newNonce']) as resp:
                return resp.headers['Replay-Nonce']

    def _generate_account_key(self) -> Tuple[str, dict]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        pub = private_key.public_key()
        pub_numbers = pub.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": _b64url(pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, 'big')),
            "e": _b64url(pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, 'big')),
        }
        return pem, jwk

    def _load_private_key(self, pem_str: str):
        return serialization.load_pem_private_key(
            pem_str.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

    def _get_jwk(self, private_key) -> dict:
        pub = private_key.public_key()
        pub_numbers = pub.public_numbers()
        return {
            "kty": "RSA",
            "n": _b64url(pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, 'big')),
            "e": _b64url(pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, 'big')),
        }

    def _jwk_thumbprint(self, jwk: dict) -> str:
        ordered = json.dumps({"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]}, separators=(',', ':'))
        digest = hashlib.sha256(ordered.encode('utf-8')).digest()
        return _b64url(digest)

    @staticmethod
    def _dns_txt_value(key_authorization: str) -> str:
        """RFC 8555 §8.4: the DNS-01 TXT value is base64url(SHA256(key_authorization)) over the
        RAW 32-byte digest (NOT the hexdigest)."""
        return _b64url(hashlib.sha256(key_authorization.encode('utf-8')).digest())

    @staticmethod
    def _challenge_dns_name(identifier: str) -> str:
        """The `_acme-challenge.<base>` record name for an ACME identifier. A leading wildcard
        `*.` is stripped, so both `*.example.com` and bare `example.com` map to the SAME name
        `_acme-challenge.example.com` (which is why apex+wildcard need two coexisting TXT values)."""
        base = identifier[2:] if identifier.startswith('*.') else identifier
        return f"_acme-challenge.{base}"

    def _sign_jws(self, private_key, protected: dict, payload: Any) -> dict:
        protected_b64 = _b64url(json.dumps(protected).encode('utf-8'))
        if payload == "":
            payload_b64 = ""
        else:
            payload_b64 = _b64url(json.dumps(payload).encode('utf-8'))

        sign_input = f"{protected_b64}.{payload_b64}".encode('ascii')
        signature = private_key.sign(sign_input, padding.PKCS1v15(), hashes.SHA256())

        return {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _b64url(signature),
        }

    async def _signed_request(
        self,
        url: str,
        directory_url: str,
        private_key,
        payload: Any,
        account_url: Optional[str] = None,
        jwk: Optional[dict] = None,
    ) -> Tuple[int, dict, dict]:
        nonce = await self._get_nonce(directory_url)

        protected = {"alg": "RS256", "nonce": nonce, "url": url}
        if account_url:
            protected["kid"] = account_url
        elif jwk:
            protected["jwk"] = jwk
        else:
            protected["jwk"] = self._get_jwk(private_key)

        body = self._sign_jws(private_key, protected, payload)

        # SECURITY (GHSA-3vh4-gvxx-wm2p): `url` is taken from the CA directory /
        # order responses. The directory is already fetched from a validated
        # public CA, but guard the follow-up POST target too (defence in depth)
        # so a tampered/malicious directory cannot steer the request internally.
        from utils.ssrf_guard import assert_public_url, safe_connector
        await assert_public_url(url)

        async with aiohttp.ClientSession(connector=safe_connector()) as session:
            for attempt in range(3):
                async with session.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/jose+json"},
                    timeout=aiohttp.ClientTimeout(total=30),
                    allow_redirects=False,
                ) as resp:
                    if 'Replay-Nonce' in resp.headers:
                        self._nonce_by_dir[directory_url] = resp.headers['Replay-Nonce']

                    if resp.status == 400 and attempt < 2:
                        err = await resp.json()
                        etype = (err.get('type') or '')
                        edetail = (err.get('detail') or '').lower()
                        # Retry on badNonce, and on any nonce-related malformed rejection (e.g.
                        # "The Replay Nonce could not be base64url-decoded") — refetch a FRESH nonce
                        # from the target CA and resign. With per-CA scoping the cross-CA cause is gone;
                        # this is defense-in-depth so a stale/rejected nonce always self-heals.
                        if etype.endswith('badNonce') or 'nonce' in edetail:
                            nonce = resp.headers.get('Replay-Nonce') or await self._get_nonce(directory_url)
                            protected['nonce'] = nonce
                            body = self._sign_jws(private_key, protected, payload)
                            continue

                    resp_data = {}
                    content_type = resp.headers.get('Content-Type', '')
                    if 'json' in content_type:
                        resp_data = await resp.json()
                    elif resp.status < 300:
                        text = await resp.text()
                        if text:
                            try:
                                resp_data = json.loads(text)
                            except json.JSONDecodeError:
                                resp_data = {"raw": text}

                    headers = dict(resp.headers)
                    return resp.status, resp_data, headers

        raise Exception(f"ACME request to {url} failed after retries")

    async def register_account(
        self,
        email: str,
        directory_url: str,
        tos_agreed: bool = True,
        eab_kid: Optional[str] = None,
        eab_hmac_key: Optional[str] = None,
        challenge_type: str = 'http-01',
        dns_provider: Optional[str] = None,
    ) -> dict:
        directory = await self.get_directory(directory_url)
        pem, jwk = self._generate_account_key()
        private_key = self._load_private_key(pem)

        payload: Dict[str, Any] = {
            "termsOfServiceAgreed": tos_agreed,
            "contact": [f"mailto:{email}"],
        }

        if eab_kid and eab_hmac_key:
            eab_key_bytes = _b64url_decode(eab_hmac_key)
            eab_protected = {
                "alg": "HS256",
                "kid": eab_kid,
                "url": directory['newAccount'],
            }
            eab_protected_b64 = _b64url(json.dumps(eab_protected).encode('utf-8'))
            eab_payload_b64 = _b64url(json.dumps(jwk).encode('utf-8'))

            import hmac as hmac_mod
            eab_sign_input = f"{eab_protected_b64}.{eab_payload_b64}".encode('ascii')
            eab_signature = hmac_mod.new(eab_key_bytes, eab_sign_input, hashlib.sha256).digest()

            payload["externalAccountBinding"] = {
                "protected": eab_protected_b64,
                "payload": eab_payload_b64,
                "signature": _b64url(eab_signature),
            }

        status, data, headers = await self._signed_request(
            directory['newAccount'], directory_url, private_key, payload, jwk=jwk
        )

        if status not in (200, 201):
            raise Exception(f"Account registration failed: {data}")

        account_url = headers.get('Location', '')

        conn = await get_database_connection()
        try:
            row = await conn.fetchrow("""
                INSERT INTO letsencrypt_accounts (email, directory_url, account_url, jwk_private_key, status, tos_agreed, eab_kid, challenge_type, dns_provider)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (email, directory_url) DO UPDATE SET
                    account_url = $3, jwk_private_key = $4, status = $5, tos_agreed = $6,
                    challenge_type = $8, dns_provider = $9, updated_at = NOW()
                RETURNING id, email, directory_url, account_url, status, tos_agreed, created_at, challenge_type, dns_provider
            """, email, directory_url, account_url, pem,
                data.get('status') or 'valid', tos_agreed, eab_kid, challenge_type, dns_provider)
            return dict(row)
        finally:
            await close_database_connection(conn)

    async def deactivate_account(self, account_id: int) -> dict:
        """Deactivate an ACME account at the CA and mark it locally."""
        conn = await get_database_connection()
        try:
            account = await conn.fetchrow(
                "SELECT id, email, directory_url, account_url, jwk_private_key, status FROM letsencrypt_accounts WHERE id = $1",
                account_id
            )
            if not account:
                raise Exception("Account not found")
            if account['status'] == 'deactivated':
                raise Exception("Account is already deactivated")

            private_key = self._load_private_key(account['jwk_private_key'])
            payload = {"status": "deactivated"}

            status, data, _headers = await self._signed_request(
                account['account_url'],
                account['directory_url'],
                private_key,
                payload,
                account_url=account['account_url'],
            )

            if status not in (200, 201):
                logger.warning(f"ACME account deactivation returned {status}: {data}")
                raise Exception(f"CA rejected deactivation (HTTP {status}): {data.get('detail') or 'Unknown error'}")

            await conn.execute(
                "UPDATE letsencrypt_accounts SET status = 'deactivated', updated_at = NOW() WHERE id = $1",
                account_id
            )
            return {"id": account_id, "email": account['email'], "status": "deactivated"}
        finally:
            await close_database_connection(conn)

    async def create_order(
        self,
        account_id: int,
        domains: List[str],
        cluster_ids: Optional[List[int]] = None,
        challenge_type: str = 'http-01',
        created_by: Optional[int] = None,
    ) -> dict:
        logger.info(f"ACME: Creating order for domains={domains}, account_id={account_id}, challenge_type={challenge_type}")
        conn = await get_database_connection()
        try:
            account = await conn.fetchrow(
                "SELECT * FROM letsencrypt_accounts WHERE id = $1", account_id
            )
            if not account:
                raise Exception(f"Account {account_id} not found")

            private_key = self._load_private_key(account['jwk_private_key'])
            directory = await self.get_directory(account['directory_url'])

            identifiers = [{"type": "dns", "value": d} for d in domains]
            payload = {"identifiers": identifiers}

            status, data, headers = await self._signed_request(
                directory['newOrder'],
                account['directory_url'],
                private_key,
                payload,
                account_url=account['account_url'],
            )

            if status not in (200, 201):
                logger.error(f"ACME: Order creation failed: HTTP {status}, response={data}")
                raise Exception(f"Order creation failed: {data}")

            order_url = headers.get('Location', '')
            logger.info(f"ACME: Order created, order_url={order_url}, status={data.get('status')}, authorizations={len(data.get('authorizations', []))}")
            expires_at = None
            if data.get('expires'):
                try:
                    expires_at = datetime.fromisoformat(data['expires'].replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    pass

            order_row = await conn.fetchrow("""
                INSERT INTO letsencrypt_orders
                    (account_id, order_url, status, domains, finalize_url, expires_at, cluster_ids, challenge_type, created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id
            """, account_id, order_url, data.get('status') or 'pending',
                json.dumps(domains), data.get('finalize') or '', expires_at,
                json.dumps(cluster_ids or []), challenge_type, created_by)

            order_id = order_row['id']

            # Commit 5e: track authorization fetch outcomes per-domain.
            # Previously a 'continue' on auth fetch failure silently dropped HTTP-01
            # challenges; the order proceeded but had no challenges to respond to,
            # leaving it stuck in 'pending' forever.
            auth_fetch_failures = []  # [{auth_url, http_status, error}]
            domains_with_http01 = set()
            
            for auth_url in data.get('authorizations', []):
                try:
                    auth_status, auth_data, _ = await self._signed_request(
                        auth_url, account['directory_url'], private_key, "",
                        account_url=account['account_url'],
                    )
                except Exception as auth_err:
                    logger.warning(f"ACME: authorization fetch raised: {auth_url} - {auth_err}")
                    auth_fetch_failures.append({
                        "auth_url": auth_url, "http_status": None, "error": str(auth_err)
                    })
                    continue
                
                if auth_status != 200:
                    logger.warning(
                        f"ACME: Failed to fetch authorization {auth_url}: HTTP {auth_status}, body={str(auth_data)[:200]}"
                    )
                    auth_fetch_failures.append({
                        "auth_url": auth_url, "http_status": auth_status,
                        "error": str(auth_data)[:500] if auth_data else ""
                    })
                    continue

                domain = (auth_data.get('identifier') or {}).get('value', '')
                http01_for_domain = False
                for challenge in (auth_data.get('challenges') or []):
                    # Store only the challenge of the CHOSEN method (default 'http-01' keeps the
                    # existing behaviour byte-identical; 'dns-01' selects the TXT challenge instead).
                    if challenge.get('type') == challenge_type:
                        token = challenge['token']
                        jwk = self._get_jwk(private_key)
                        thumbprint = self._jwk_thumbprint(jwk)
                        key_auth = f"{token}.{thumbprint}"
                        dns_txt = self._dns_txt_value(key_auth) if challenge_type == 'dns-01' else None

                        await conn.execute("""
                            INSERT INTO acme_challenges
                                (order_id, domain, token, key_authorization, challenge_url, status,
                                 challenge_type, dns_txt_value)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        """, order_id, domain, token, key_auth,
                            challenge.get('url') or '', challenge.get('status') or 'pending',
                            challenge_type, dns_txt)
                        logger.info(f"ACME: {challenge_type} challenge stored for domain={domain}, token={token[:20]}..., challenge_url={(challenge.get('url') or '')[:60]}")
                        http01_for_domain = True
                if http01_for_domain and domain:
                    domains_with_http01.add(domain)
            
            # If NO http-01 challenges were registered at all, the order cannot
            # proceed — fail-fast and persist diagnostic detail.
            if not domains_with_http01:
                error_payload = json.dumps({
                    "stage": "create_order_authorizations",
                    "auth_fetch_failures": auth_fetch_failures,
                    "domains": domains,
                    "timestamp": datetime.utcnow().isoformat(),
                })
                await conn.execute(
                    "UPDATE letsencrypt_orders SET status = 'invalid', error_detail = $1, updated_at = NOW() WHERE id = $2",
                    error_payload, order_id
                )
                raise Exception(
                    f"ACME order {order_id} created but no {challenge_type} challenges available "
                    f"(auth fetch failures: {len(auth_fetch_failures)}). See order.error_detail for diagnostics."
                )
            elif auth_fetch_failures:
                # Partial failure: some domains have challenges, others don't. Record warning.
                error_payload = json.dumps({
                    "stage": "create_order_authorizations_partial",
                    "auth_fetch_failures": auth_fetch_failures,
                    "domains_with_challenges": sorted(domains_with_http01),
                    "timestamp": datetime.utcnow().isoformat(),
                })
                await conn.execute(
                    "UPDATE letsencrypt_orders SET error_detail = $1, updated_at = NOW() WHERE id = $2",
                    error_payload, order_id
                )
                logger.warning(
                    f"ACME order {order_id}: partial authorization fetch failure — "
                    f"{len(auth_fetch_failures)} failed, {len(domains_with_http01)} succeeded"
                )

            return {
                "order_id": order_id,
                "order_url": order_url,
                "status": data.get('status') or 'pending',
                "domains": domains,
                "authorizations": data.get('authorizations') or [],
                "finalize": data.get('finalize') or '',
            }
        finally:
            await close_database_connection(conn)

    async def respond_to_challenges(self, order_id: int) -> List[dict]:
        conn = await get_database_connection()
        try:
            # Issue #12 / Commit 5a: include 'failed' challenges so they can be retried,
            # but rate-limit per challenge: max 5 attempts in last 5 minutes.
            # DNS-01 skip-gate (the single safe choke point): never POST a challenge response for a
            # dns-01 row whose TXT record has not been published yet — that would make the CA validate
            # against a missing record and burn the order. http-01 rows (challenge_type 'http-01'/NULL)
            # are never excluded, so the existing flow is byte-identical.
            challenges = await conn.fetch(
                """SELECT * FROM acme_challenges
                   WHERE order_id = $1
                     AND (status IN ('pending', 'failed') OR status IS NULL)
                     AND NOT (COALESCE(challenge_type, 'http-01') = 'dns-01' AND COALESCE(dns_record_published, FALSE) = FALSE)""",
                order_id
            )
            order = await conn.fetchrow(
                "SELECT o.*, a.jwk_private_key, a.account_url, a.directory_url FROM letsencrypt_orders o JOIN letsencrypt_accounts a ON o.account_id = a.id WHERE o.id = $1",
                order_id
            )
            if not order:
                raise Exception(f"Order {order_id} not found")

            private_key = self._load_private_key(order['jwk_private_key'])
            results = []
            logger.info(f"ACME: Responding to {len(challenges)} challenge(s) for order_id={order_id}")

            for ch in challenges:
                if not ch['challenge_url']:
                    logger.warning(f"ACME: Skipping challenge id={ch['id']} domain={ch['domain']} - no challenge_url")
                    continue
                
                # Rate-limit retry: skip if attempted >=5 times in last 5 minutes
                attempts = ch.get('attempts') or 0
                last_attempt = ch.get('last_attempt_at')
                if attempts >= 5 and last_attempt:
                    age_seconds = (datetime.utcnow().replace(tzinfo=None) -
                                   (last_attempt.replace(tzinfo=None) if last_attempt.tzinfo else last_attempt)).total_seconds()
                    if age_seconds < 300:
                        logger.warning(
                            f"ACME: Rate-limit: skipping challenge id={ch['id']} domain={ch['domain']} "
                            f"(attempts={attempts}, age={int(age_seconds)}s < 300s)"
                        )
                        results.append({"domain": ch['domain'], "token": ch['token'],
                                        "status": ch['status'], "skipped": "rate-limit"})
                        continue
                
                status, data, _ = await self._signed_request(
                    ch['challenge_url'],
                    order['directory_url'],
                    private_key,
                    {},
                    account_url=order['account_url'],
                )
                new_status = (data.get('status') or 'processing') if status == 200 else 'failed'
                logger.info(f"ACME: Challenge response for domain={ch['domain']}, token={ch['token'][:20]}..., CA_HTTP={status}, CA_status_raw={data.get('status')!r}, stored_status={new_status}")
                await conn.execute(
                    """UPDATE acme_challenges
                       SET status = $1,
                           attempts = COALESCE(attempts, 0) + 1,
                           last_attempt_at = NOW()
                       WHERE id = $2""",
                    new_status, ch['id']
                )
                results.append({"domain": ch['domain'], "token": ch['token'], "status": new_status})

            return results
        finally:
            await close_database_connection(conn)

    async def finalize_order(self, order_id: int) -> dict:
        conn = await get_database_connection()
        try:
            order = await conn.fetchrow("""
                SELECT o.*, a.jwk_private_key, a.account_url, a.directory_url
                FROM letsencrypt_orders o
                JOIN letsencrypt_accounts a ON o.account_id = a.id
                WHERE o.id = $1
            """, order_id)
            if not order:
                raise Exception(f"Order {order_id} not found")

            domains = json.loads(order['domains']) if isinstance(order['domains'], str) else order['domains']
            logger.info(f"ACME: Finalizing order_id={order_id}, domains={domains}, finalize_url={(order['finalize_url'] or 'N/A')[:60]}")
            private_key = self._load_private_key(order['jwk_private_key'])

            cert_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            cert_key_pem = cert_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode('utf-8')

            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
            ]))
            san_names = [x509.DNSName(d) for d in domains]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_names), critical=False
            )
            csr = builder.sign(cert_key, hashes.SHA256(), default_backend())
            csr_der = csr.public_bytes(serialization.Encoding.DER)

            payload = {"csr": _b64url(csr_der)}
            status, data, _ = await self._signed_request(
                order['finalize_url'],
                order['directory_url'],
                private_key,
                payload,
                account_url=order['account_url'],
            )

            if status not in (200, 201):
                # Commit 5h: structured JSON-as-TEXT error_detail for consistency
                # with check_order_status (5c) and download_certificate (5i).
                error_msg = data.get('detail') if isinstance(data, dict) else str(data)
                error_payload = json.dumps({
                    "stage": "finalize_order",
                    "http_status": status,
                    "ca_response": data if isinstance(data, dict) else str(data)[:1000],
                    "timestamp": datetime.utcnow().isoformat(),
                })
                logger.error(f"ACME: Finalize failed for order_id={order_id}: HTTP {status}, error={error_msg}")
                await conn.execute(
                    "UPDATE letsencrypt_orders SET status = 'invalid', error_detail = $1, updated_at = NOW() WHERE id = $2",
                    error_payload, order_id
                )
                raise Exception(f"Finalize failed: {error_msg}")

            order_status = data.get('status') or 'processing'
            certificate_url = data.get('certificate') or ''
            logger.info(f"ACME: Finalize success for order_id={order_id}, status={order_status}, certificate_url={certificate_url[:60] if certificate_url else 'N/A'}")

            await conn.execute(
                "UPDATE letsencrypt_orders SET status = $1, certificate_url = $2, cert_private_key = $3, updated_at = NOW() WHERE id = $4",
                order_status, certificate_url, cert_key_pem, order_id
            )

            return {
                "order_id": order_id,
                "status": order_status,
                "certificate_url": certificate_url,
                "private_key_pem": cert_key_pem,
            }
        finally:
            await close_database_connection(conn)

    async def download_certificate(self, order_id: int) -> dict:
        conn = await get_database_connection()
        try:
            order = await conn.fetchrow("""
                SELECT o.*, a.jwk_private_key, a.account_url, a.directory_url
                FROM letsencrypt_orders o
                JOIN letsencrypt_accounts a ON o.account_id = a.id
                WHERE o.id = $1
            """, order_id)
            if not order or not order['certificate_url']:
                raise Exception("Certificate not ready for download")

            private_key = self._load_private_key(order['jwk_private_key'])

            status, data, headers = await self._signed_request(
                order['certificate_url'],
                order['directory_url'],
                private_key,
                "",
                account_url=order['account_url'],
            )

            if status != 200:
                # Commit 5i: persist structured error_detail to TEXT column.
                # Previously download failures only raised an exception, leaving the
                # order in 'valid' state with no DB diagnostic — operators were
                # blind to root cause.
                try:
                    error_payload = json.dumps({
                        "stage": "download_certificate",
                        "http_status": status,
                        "ca_response": data if isinstance(data, dict) else str(data)[:1000],
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    await conn.execute(
                        "UPDATE letsencrypt_orders SET error_detail = $1, updated_at = NOW() WHERE id = $2",
                        error_payload, order_id
                    )
                except Exception as persist_err:
                    logger.warning(f"ACME: failed to persist download error for order {order_id}: {persist_err}")
                raise Exception(f"Certificate download failed: HTTP {status}")

            # Commit 5d: harden response parsing. ACME RFC 8555 §7.4.2 specifies
            # `application/pem-certificate-chain` as the Content-Type. Some test
            # CAs (Pebble) return raw PEM, others return JSON-wrapped data. We
            # accept either format and extract the PEM body robustly.
            cert_pem = ''
            if isinstance(data, dict):
                cert_pem = data.get('raw', '') or data.get('certificate', '') or ''
            elif isinstance(data, (str, bytes)):
                cert_pem = data.decode('utf-8') if isinstance(data, bytes) else data
            elif data is not None:
                cert_pem = str(data)
            
            if not cert_pem or '-----BEGIN CERTIFICATE-----' not in cert_pem:
                raise Exception(
                    f"Certificate download succeeded (HTTP 200) but response body "
                    f"does not contain a PEM certificate. Content-Type={headers.get('Content-Type', 'unknown') if headers else 'unknown'}, "
                    f"body_len={len(cert_pem) if cert_pem else 0}"
                )

            parts = cert_pem.strip().split('-----END CERTIFICATE-----')
            certificate = (parts[0] + '-----END CERTIFICATE-----').strip() if parts else cert_pem
            chain = '-----END CERTIFICATE-----'.join(parts[1:]).strip() if len(parts) > 1 else ''
            if chain and not chain.startswith('-----'):
                chain = chain.lstrip('\n')

            await conn.execute(
                "UPDATE letsencrypt_orders SET status = 'valid', updated_at = NOW() WHERE id = $1",
                order_id
            )

            return {
                "certificate_pem": certificate,
                "chain_pem": chain,
                "full_chain_pem": cert_pem,
            }
        finally:
            await close_database_connection(conn)

    async def check_order_status(self, order_id: int) -> dict:
        conn = await get_database_connection()
        try:
            order = await conn.fetchrow("""
                SELECT o.*, a.jwk_private_key, a.account_url, a.directory_url
                FROM letsencrypt_orders o
                JOIN letsencrypt_accounts a ON o.account_id = a.id
                WHERE o.id = $1
            """, order_id)
            if not order:
                raise Exception(f"Order {order_id} not found")
            if not order['order_url']:
                return {"order_id": order_id, "status": order['status']}

            private_key = self._load_private_key(order['jwk_private_key'])
            status, data, _ = await self._signed_request(
                order['order_url'],
                order['directory_url'],
                private_key,
                "",
                account_url=order['account_url'],
            )

            if status == 200:
                new_status = data.get('status') or order['status']
                certificate_url = data.get('certificate') or order['certificate_url']
                await conn.execute(
                    "UPDATE letsencrypt_orders SET status = $1, certificate_url = $2, updated_at = NOW() WHERE id = $3",
                    new_status, certificate_url, order_id
                )
                return {"order_id": order_id, "status": new_status, "certificate_url": certificate_url}

            # Commit 5c: persist CA error to error_detail (TEXT) as structured JSON.
            # Previously a non-200 was silently swallowed (no log, no DB record),
            # leaving operators without diagnostic info for stuck orders.
            try:
                error_payload = json.dumps({
                    "stage": "check_order_status",
                    "http_status": status,
                    "ca_response": data if isinstance(data, dict) else str(data)[:1000],
                    "timestamp": datetime.utcnow().isoformat(),
                })
                await conn.execute(
                    "UPDATE letsencrypt_orders SET error_detail = $1, updated_at = NOW() WHERE id = $2",
                    error_payload, order_id
                )
            except Exception as persist_err:
                logger.warning(f"ACME: failed to persist error_detail for order {order_id}: {persist_err}")
            logger.warning(
                f"ACME: check_order_status non-200 for order {order_id}: HTTP {status}, response={data}"
            )

            return {"order_id": order_id, "status": order['status']}
        finally:
            await close_database_connection(conn)

    async def revoke_certificate(self, certificate_pem: str, account_id: int, reason: int = 0) -> bool:
        conn = await get_database_connection()
        try:
            account = await conn.fetchrow(
                "SELECT * FROM letsencrypt_accounts WHERE id = $1", account_id
            )
            if not account:
                raise Exception("Account not found")

            private_key = self._load_private_key(account['jwk_private_key'])
            directory = await self.get_directory(account['directory_url'])

            cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'), default_backend())
            cert_der = cert.public_bytes(serialization.Encoding.DER)

            payload = {"certificate": _b64url(cert_der), "reason": reason}
            status, data, _ = await self._signed_request(
                directory['revokeCert'],
                account['directory_url'],
                private_key,
                payload,
                account_url=account['account_url'],
            )
            return status == 200
        finally:
            await close_database_connection(conn)


acme_service = ACMEService()

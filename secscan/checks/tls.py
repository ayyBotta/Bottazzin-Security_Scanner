"""Controlli su HTTPS, certificato e versioni TLS."""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from urllib.parse import urljoin

import certifi
import requests

from ..models import Check, ScanContext, Severity, Skip
from .base import BaseChecker


class HttpsChecker(BaseChecker):
    """HTTPS raggiungibile e redirect da HTTP a HTTPS."""

    category = "HTTPS/TLS"

    def run(self, ctx: ScanContext) -> list[Check]:
        return [self._https_available(ctx), self._http_redirect(ctx)]

    def _https_available(self, ctx: ScanContext) -> Check:
        c = self.check("HTTPS disponibile", 10, Severity.CRITICA,
                       "Senza HTTPS tutto il traffico (password, cookie di sessione, dati personali) viaggia in chiaro: chiunque sulla stessa rete (Wi-Fi pubblico, ISP, router compromesso) puo' leggerlo o modificarlo con un attacco man-in-the-middle.")
        if ctx.https_response is not None:
            c.points, c.message = 10, f"HTTP {ctx.https_response.status_code}"
        else:
            c.message = f"HTTPS non raggiungibile ({ctx.https_error})"
            ctx.add_cap(20, "HTTPS non disponibile")
        return c

    def _http_redirect(self, ctx: ScanContext) -> Check:
        c = self.check("Redirect HTTP -> HTTPS", 5, Severity.ALTA,
                       "Se la versione HTTP resta servita senza redirect, chi digita il dominio senza https:// o segue vecchi link naviga in chiaro e puo' essere intercettato o dirottato verso pagine false (SSL stripping).")
        r = ctx.http_response
        if r is None:
            c.points, c.message = 5, "Porta 80 non risponde (accettabile)"
            return c
        c.source_url = (r.history[0] if r.history else r).url
        first_target = urljoin(r.history[0].url, r.history[0].headers.get("Location", "")) if r.history else ""
        if first_target.startswith("https://"):
            c.points, c.message = 5, f"Il primo salto va subito su HTTPS: {first_target}"
        elif r.url.startswith("https://"):
            # arriva su HTTPS, ma dopo uno o piu' salti in chiaro che un attaccante puo' alterare
            c.points = 3
            c.message = f"Arriva su HTTPS solo dopo un salto in chiaro: {c.source_url} -> {first_target} -> ... -> {r.url}"
        else:
            c.message = "HTTP servito in chiaro senza redirect a HTTPS"
        return c


class TlsChecker(BaseChecker):
    """Validita' e scadenza del certificato, versione TLS, protocolli deprecati."""

    category = "HTTPS/TLS"

    def run(self, ctx: ScanContext) -> list[Check]:
        return [*self._certificate(ctx), *self._legacy_protocols(ctx)]

    def _certificate(self, ctx: ScanContext) -> list[Check]:
        cert_c = self.check("Certificato valido", 6, Severity.CRITICA,
                            "Un certificato non valido impedisce di verificare l'identita' del server: il browser mostra un avviso e chi lo ignora non puo' distinguere il sito vero da un impostore che intercetta la connessione.")
        exp_c = self.check("Scadenza certificato", 3, Severity.MEDIA,
                           "Un certificato prossimo alla scadenza, se non rinnovato, rende il sito non piu' raggiungibile in modo sicuro e abitua gli utenti a ignorare gli avvisi del browser.")
        ver_c = self.check("Versione TLS negoziata", 4, Severity.MEDIA,
                           "Le versioni di TLS precedenti alla 1.2 hanno debolezze crittografiche note; TLS 1.3 elimina gli algoritmi deboli e riduce la superficie d'attacco.")

        incomplete_chain = False
        cert_c.source_url = exp_c.source_url = ver_c.source_url = f"https://{ctx.domain}/"
        try:
            try:
                cert, version = self._handshake(ctx.domain)
            except ssl.SSLCertVerificationError as e:
                # catena incompleta: i browser scaricano da soli l'intermedio mancante (AIA), facciamo lo stesso
                if e.verify_code != self.UNABLE_TO_GET_ISSUER:
                    raise
                completed = self._handshake_with_aia(ctx.domain)
                if completed is None:
                    raise
                cert, version = completed
                incomplete_chain = True
        except ssl.SSLCertVerificationError as e:
            ctx.cert_valid = False
            if ctx.redirect_target:
                # dominio di solo redirect: non raccoglie dati, quindi il certificato non penalizza.
                # Lo segnaliamo comunque: chi apre https://<dominio> vede l'avviso del browser.
                cert_c.skip(f"NON valido ({e.verify_message}), ma rimanda a {ctx.redirect_target}",
                            Skip.REDIRECT_CERT)
                for c in (exp_c, ver_c):
                    c.skip("Non verificabile: il certificato non e' valido", Skip.REDIRECT_CERT)
            else:
                for c in (exp_c, ver_c):
                    c.skip("Certificato non valido", Skip.CERT_INVALID)
                cert_c.message = f"Certificato NON valido: {e.verify_message}"
                ctx.add_cap(35, "Certificato non valido")
            return [cert_c, exp_c, ver_c]
        except (OSError, ssl.SSLError) as e:
            for c in (cert_c, exp_c, ver_c):
                c.skip(f"Connessione TLS fallita ({e.__class__.__name__})", Skip.TLS_FAILED)
            return [cert_c, exp_c, ver_c]

        ctx.cert_valid = True
        ctx.cert = cert
        cert_c.points, cert_c.message = 6, f"Emesso da {self._issuer(cert)}"
        if incomplete_chain:
            cert_c.points = 5
            cert_c.message += (" - valido, ma il server non invia il certificato intermedio: i browser lo "
                               "recuperano da soli, alcune app e client (curl, vecchi Android) danno errore")

        days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
        exp_c.points = 3 if days >= 30 else 1 if days >= 7 else 0
        exp_c.message = f"Scade tra {days} giorni"

        ver_c.points = {"TLSv1.3": 4, "TLSv1.2": 3}.get(version, 0)
        ver_c.message = version or "sconosciuta"
        return [cert_c, exp_c, ver_c]

    @staticmethod
    def _verify_context(extra_pem: str = "") -> ssl.SSLContext:
        """Contesto con verifica completa: radici di sistema + bundle certifi. Su Windows l'archivio
        locale contiene solo le radici gia' usate (le altre le scarica su richiesta), quindi da solo
        darebbe falsi "certificato non valido"."""
        context = ssl.create_default_context()
        context.load_verify_locations(certifi.where())
        if extra_pem:
            context.load_verify_locations(cadata=extra_pem)
            # gli intermedi aggiunti NON diventano radici fidate: la catena deve arrivare a una vera radice
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
        return context

    def _connect(self, domain: str, context: ssl.SSLContext, binary: bool = False):
        with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert(binary_form=binary), ssock.version()

    def _handshake(self, domain: str, attempts: int = 2) -> tuple[dict, str | None]:
        """Handshake TLS con verifica; riprova sugli errori di rete (non su quelli di certificato)."""
        context = self._verify_context()
        for attempt in range(attempts):
            try:
                return self._connect(domain, context)
            except ssl.SSLCertVerificationError:
                raise
            except (OSError, ssl.SSLError):
                if attempt == attempts - 1:
                    raise
        raise AssertionError("irraggiungibile")

    UNABLE_TO_GET_ISSUER = 20  # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    ISSUER_NOT_FOUND = {2, 20}  # ...UNABLE_TO_GET_ISSUER_CERT, ...UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    AIA_CA_ISSUERS_OID = bytes.fromhex("06082b06010505073002")  # 1.3.6.1.5.5.7.48.2 (caIssuers)
    AIA_MAX_DEPTH = 3

    def _handshake_with_aia(self, domain: str) -> tuple[dict, str | None] | None:
        """Completa la catena scaricando gli intermedi indicati dai certificati (Authority Information
        Access), come fanno i browser, e rifa' la verifica COMPLETA fino a una radice fidata.
        None se non si riesce."""
        try:
            insecure = ssl.create_default_context()
            insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE
            der, _ = self._connect(domain, insecure, binary=True)
            pems: list[str] = []
            for _ in range(self.AIA_MAX_DEPTH):
                url = self._ca_issuers_url(der)
                if not url:
                    return None
                data = self.fetcher.get(url).content
                if b"-----BEGIN CERTIFICATE-----" in data:
                    pem = data.decode("ascii", "ignore")
                    der = ssl.PEM_cert_to_DER_cert(pem)
                elif data[:1] == bytes([0x30]):  # DER (i PKCS#7 .p7c non sono gestiti)
                    pem, der = ssl.DER_cert_to_PEM_cert(data), data
                else:
                    return None
                pems.append(pem)
                try:
                    return self._connect(domain, self._verify_context("\n".join(pems)))
                except ssl.SSLCertVerificationError as e:
                    if e.verify_code not in self.ISSUER_NOT_FOUND:
                        return None  # problema diverso (scaduto, nome sbagliato...): resta non valido
        except (OSError, ssl.SSLError, ValueError, requests.RequestException):
            return None
        return None

    @classmethod
    def _ca_issuers_url(cls, der: bytes) -> str | None:
        """URL "CA Issuers" dall'estensione AIA del certificato (DER), senza librerie esterne."""
        i = der.find(cls.AIA_CA_ISSUERS_OID)
        if i < 0:
            return None
        j = i + len(cls.AIA_CA_ISSUERS_OID)
        if der[j:j + 1] != bytes([0x86]):  # GeneralName uniformResourceIdentifier
            return None
        length, start = der[j + 1], j + 2
        if length == 0x81:
            length, start = der[j + 2], j + 3
        url = der[start:start + length].decode("ascii", "ignore")
        return url if url.startswith("http") else None

    @staticmethod
    def _issuer(cert: dict) -> str:
        for rdn in cert.get("issuer", ()):
            for key, value in rdn:
                if key in ("organizationName", "commonName"):
                    return value
        return "sconosciuto"

    LEGACY_WHY = ("Accettare TLS 1.0/1.1 permette attacchi di downgrade e l'uso di cifrari deboli "
                  "(es. BEAST, POODLE); questi protocolli sono deprecati dall'RFC 8996.")

    def _legacy_protocols(self, ctx: ScanContext) -> list[Check]:
        """TLS 1.0/1.1 sull'host finale del dominio (pesa di piu') e, se diverso, sull'host iniziale che
        fa solo da redirect (es. google.com -> www.google.com): li' il rischio e' minore."""
        initial = ctx.domain
        final = ctx.own_final_host or initial
        main = self._legacy_check("TLS 1.0/1.1 disabilitati", 2, Severity.MEDIA, self.LEGACY_WHY, final)
        if final == initial:
            return [main]
        minor = self._legacy_check(
            "TLS 1.0/1.1 sull'host di redirect", 1, Severity.INFO,
            "L'host iniziale fa solo da redirect verso " + final + ": un protocollo debole li' espone solo il "
            "primo salto (un attaccante in rete potrebbe forzare il downgrade e alterare il redirect). "
            "Rischio minore rispetto all'host finale, per questo pesa poco.", initial)
        return [main, minor]

    def _legacy_check(self, name: str, points: int, severity: Severity, why: str, host: str) -> Check:
        c = self.check(name, points, severity, why)
        c.source_url = f"https://{host}/"
        accepted = self._probe_legacy(host)
        if accepted is None:
            c.skip(f"{host}: l'OpenSSL di questo computer non supporta TLS 1.0/1.1", Skip.LOCAL_LIMIT)
        elif accepted:
            c.message = f"{host}: accettati protocolli deprecati {', '.join(accepted)}"
        else:
            c.points, c.message = points, f"{host}: solo TLS >= 1.2"
        return c

    def _probe_legacy(self, host: str) -> list[str] | None:
        """Versioni deprecate accettate dal server (lista vuota = rifiutate), None se non testabile.
        Il client abbassa il security level (DEFAULT:@SECLEVEL=0) e fissa min/max version: senza, OpenSSL 3
        non proverebbe nemmeno TLS 1.0/1.1 e si avrebbero falsi negativi."""
        accepted: list[str] = []
        tested = False
        for name, ver in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            context = self._legacy_context(ver)
            if context is None:
                continue  # l'OpenSSL locale non supporta questa versione
            try:
                with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        accepted.append(name)
                tested = True
            except ssl.SSLError as e:
                # "no protocols available" = limite del client, non del server
                if "NO_PROTOCOLS_AVAILABLE" not in str(e).upper():
                    tested = True
            except OSError:
                tested = True
        return accepted if tested else None

    @staticmethod
    def _legacy_context(version: ssl.TLSVersion) -> ssl.SSLContext | None:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = version
                context.maximum_version = version
            return context
        except (ValueError, ssl.SSLError):
            return None

import asyncio
import html
import logging
import ssl
import stat
import os
import socket
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from aiohttp import web

logger = logging.getLogger("sinkhole_server")

# Global paths
TEMPLATE_DIR = Path("modules/dns_security/templates")
BLOCK_PAGE_PATH = TEMPLATE_DIR / "block_page.html"

# Ensure temp certs for HTTPS
CERT_PATH = Path("modules/dns_security/certs")

class SinkholeServer:
    """
    Enterprise Sinkhole Web Server.
    Intercepts any HTTP (80) or HTTPS (443) request.
    Responds with a 403 Forbidden Block Page.
    Logs the hijacked connection.
    """

    def __init__(self, host: str = "0.0.0.0", http_port: int = 80, https_port: int = 443):
        self.host = host
        self.http_port = http_port
        self.https_port = https_port
        self.runner_http = None
        self.runner_https = None
        
        self.app = web.Application()
        # Catch-all route
        self.app.router.add_route('*', '/{path_info:.*}', self.handle_sinkhole)

        # Separate app runner instances — one per protocol — so stop() can
        # clean each up independently without a double-cleanup RuntimeError.
        self.runner_http: web.AppRunner | None = None
        self.runner_https: web.AppRunner | None = None

    async def handle_sinkhole(self, request: web.Request) -> web.Response:
        """Handles any request sent to the Sinkhole IP."""
        client_ip = request.remote
        target_host = request.headers.get("Host", "Unknown")
        user_agent = request.headers.get("User-Agent", "Unknown")
        path = request.path

        # Log the incident to the SOC
        logger.warning(
            f"🚨 SINKHOLE HIT: {client_ip} attempted to access blocked domain -> {target_host}{path} "
            f"[UA: {user_agent}]"
        )

        # Build Dynamic Page
        try:
            if BLOCK_PAGE_PATH.exists():
                with open(BLOCK_PAGE_PATH, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                
                # Simple templating
                # XSS protection: escape all user-controlled values
                html_content = html_content.replace("{{CLIENT_IP}}", html.escape(client_ip or ""))
                html_content = html_content.replace("{{TARGET_DOMAIN}}", html.escape(target_host or ""))
                html_content = html_content.replace("{{TIMESTAMP}}", html.escape(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')))
            else:
                # SEC-2 FIX: escape ALL user-controlled values in fallback HTML
                # to prevent reflected XSS via Host header or X-Forwarded-For.
                safe_host = html.escape(target_host or "Unknown")
                safe_ip   = html.escape(client_ip   or "Unknown")
                safe_ts   = html.escape(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
                html_content = f"""
                <html>
                    <body style="background:#0f172a; color:#fff; font-family:sans-serif; text-align:center; padding-top:100px;">
                        <h1 style="color:#ef4444;">&#x1F6E1;&#xFE0F; bunyanx Security Alert</h1>
                        <h2>Access to {safe_host} has been blocked.</h2>
                        <p>This domain was intercepted by the Enterprise DNS Sinkhole.</p>
                        <p>Your IP: {safe_ip}</p>
                        <p>Time: {safe_ts}</p>
                    </body>
                </html>
                """
        except Exception as e:
            logger.error(f"Error reading block page template: {e}")
            html_content = "bunyanx: Access Denied via Sinkhole."

        # Return 403 Forbidden with the HTML
        return web.Response(
            status=403, 
            text=html_content, 
            content_type="text/html",
            headers={
                "Server": "bunyanx-Sinkhole-Engine",
                "X-Frame-Options": "DENY"
            }
        )

    def _generate_dummy_cert(self):
        """Generates a dummy self-signed certificate if none exists."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from datetime import timedelta

        CERT_PATH.mkdir(parents=True, exist_ok=True)
        cert_file = CERT_PATH / "sinkhole.crt"
        key_file = CERT_PATH / "sinkhole.key"

        if cert_file.exists() and key_file.exists():
            return cert_file, key_file

        logger.info("Generating new dummy self-signed cert for Sinkhole HTTPS...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "bunyanx-sinkhole.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "bunyanx Defense"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("bunyanx-sinkhole.local")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # SEC-8: Log security warning — key is stored unencrypted on disk.
        # This is acceptable for the sinkhole (ephemeral self-signed cert) but
        # must never be used for real PKI material.
        logger.warning(
            "⚠️  Sinkhole private key written WITHOUT passphrase encryption. "
            "Ensure file-system ACLs restrict access (chmod 600 enforced below). "
            "Do NOT use this cert/key for any purpose other than the DNS sinkhole."
        )
        # Restrict file permissions: owner read/write only
        try:
            os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # Windows may not support chmod
        
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(cert_file, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        return cert_file, key_file

    async def start(self):
        """Start the HTTP and HTTPS listeners."""
        # BUG-4 FIX: Create a dedicated runner for HTTP; HTTPS gets its own below.
        runner = web.AppRunner(self.app, access_log=None)  # We handle logging manually
        await runner.setup()
        
        # 1. Start HTTP (Port 80)
        try:
            site_http = web.TCPSite(runner, self.host, self.http_port)
            await site_http.start()
            self.runner_http = runner
            logger.info(f"🌐 Sinkhole Server listening on HTTP {self.host}:{self.http_port}")
        except Exception as e:
            logger.error(f"Failed to bind Sinkhole HTTP Port {self.http_port}: {e}")

        # 2. Start HTTPS (Port 443)
        try:
            cert_file, key_file = self._generate_dummy_cert()
            
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(str(cert_file), str(key_file))
            # SEC-3 FIX: Exclude NULL/eNULL ciphers while still allowing
            # weak legacy ciphers so older malware still negotiates TLS.
            # ALL:@SECLEVEL=0 alone permits NULL ciphers — explicitly exclude them.
            logger.warning(
                "⚠️ Sinkhole HTTPS using relaxed cipher suite (excludes NULL ciphers). "
                "This is intentional for malware interception but should NOT be used for sensitive traffic."
            )
            ssl_context.set_ciphers('ALL:!NULL:!eNULL:@SECLEVEL=0')

            # BUG-4 FIX: Use a SEPARATE AppRunner for HTTPS so stop() can
            # clean up each runner independently without double-cleanup.
            runner_https = web.AppRunner(self.app, access_log=None)
            await runner_https.setup()
            site_https = web.TCPSite(runner_https, self.host, self.https_port, ssl_context=ssl_context)
            await site_https.start()
            self.runner_https = runner_https
            logger.info(f"🔒 Sinkhole Server listening on HTTPS {self.host}:{self.https_port}")
        except PermissionError:
            logger.error(f"Permission denied to bind HTTPS Port {self.https_port} (Need root/admin?)")
        except Exception as e:
            logger.error(f"Failed to start Sinkhole HTTPS server on port {self.https_port}: {e}")

    async def stop(self):
        """Stop cleanly."""
        if self.runner_http: await self.runner_http.cleanup()
        if self.runner_https: await self.runner_https.cleanup()
        logger.info("🛑 Sinkhole Server stopped.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = SinkholeServer(http_port=8080, https_port=8443)  # Use unprivileged ports for initial testing
    # BUG-3 FIX: asyncio.get_event_loop() is deprecated in Python 3.10+.
    # Use asyncio.run() which properly manages the event loop lifecycle.
    async def _main():
        await server.start()
        try:
            await asyncio.Event().wait()  # Run forever until interrupted
        except asyncio.CancelledError:
            pass
        finally:
            await server.stop()

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass

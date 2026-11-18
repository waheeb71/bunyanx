"""
Enterprise bunyanx - WireGuard VPN Manager
==============================================

Manages WireGuard VPN interfaces, keys, and peers for Site-to-Site
and Remote Access VPN capabilities.

Provides a Python wrapper around the `wg` and `ip` command-line tools.

Security hardening (v2):
  - Private key and preshared key temp files use tempfile.mkstemp()
    with 0o600 permissions and are guaranteed deletion via try/finally.
  - No predictable /tmp filenames — eliminates symlink/race attacks.
"""

import os
import stat
import tempfile
import subprocess
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class PeerConfig:
    public_key: str
    allowed_ips: List[str]
    endpoint: Optional[str] = None
    preshared_key: Optional[str] = None
    persistent_keepalive: Optional[int] = 25


class WireGuardManager:
    """Manages WireGuard interfaces and configuration."""

    def __init__(self, interface: str = "wg0", logger: Optional[logging.Logger] = None):
        self.interface = interface
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.private_key: Optional[str] = None
        self.public_key: Optional[str] = None
        self.listen_port: int = 51820
        self.peers: Dict[str, PeerConfig] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _run_cmd(self, cmd: List[str], check: bool = True, log_error: bool = True) -> str:
        """Run a shell command and return its stdout."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check,
            )
            return result.stdout.strip()
        except FileNotFoundError as e:
            if log_error:
                self.logger.error(
                    "Command binary not found: %s | error: %s",
                    cmd[0],
                    e,
                )
            if check:
                raise
            return ""
        except subprocess.CalledProcessError as e:
            if log_error:
                self.logger.error(
                    "Command failed: %s | stderr: %s",
                    " ".join(cmd),
                    e.stderr.strip(),
                )
            if check:
                raise
            return ""

    @staticmethod
    def _make_secure_tmpfile(content: str) -> str:
        """
        Write *content* to a randomly-named temp file with 0o600 permissions.

        Returns the absolute path. The CALLER must delete the file inside
        a try/finally block using _safe_unlink().

        Security guarantees:
          - mkstemp() creates the file exclusively — no race condition.
          - chmod(0o600) applied before any data is written.
          - Prefix 'wg_secret_' gives no hint about the key type.
        """
        fd, tmp_path = tempfile.mkstemp(prefix="wg_secret_", suffix=".key")
        try:
            # Restrict permissions BEFORE writing secret material
            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)   # 0o600
            with os.fdopen(fd, "w") as fh:
                fh.write(content)
        except Exception:
            # Ensure fd is closed and file cleaned up on write failure
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return tmp_path

    @staticmethod
    def _safe_unlink(path: str) -> None:
        """Delete a file, suppressing all OS errors (best-effort cleanup)."""
        try:
            os.unlink(path)
        except OSError:
            pass

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_keys(self, allow_fallback: bool = True) -> Tuple[str, str]:
        """Generate a new Curve25519 keypair for WireGuard.

        Returns:
            (private_key, public_key) as stripped strings.
        """
        try:
            priv_key = self._run_cmd(["wg", "genkey"])

            # Derive public key from private key via stdin pipe
            process = subprocess.Popen(
                ["wg", "pubkey"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            pub_key, err = process.communicate(input=priv_key)

            if process.returncode != 0:
                raise RuntimeError(f"Failed to derive public key: {err.strip()}")

            self.private_key = priv_key.strip()
            self.public_key = pub_key.strip()

            self.logger.info("Generated new WireGuard keypair.")
            return self.private_key, self.public_key

        except FileNotFoundError:
            if not allow_fallback:
                raise
            self.logger.warning(
                "WireGuard CLI binary ('wg') not found. Falling back to native cryptography Curve25519 keypair generation."
            )
            try:
                from cryptography.hazmat.primitives.asymmetric import x25519
                from cryptography.hazmat.primitives import serialization
                import base64

                priv_obj = x25519.X25519PrivateKey.generate()
                priv_bytes = priv_obj.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                pub_bytes = priv_obj.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                self.private_key = base64.b64encode(priv_bytes).decode("ascii")
                self.public_key = base64.b64encode(pub_bytes).decode("ascii")
                self.logger.info("Generated new WireGuard keypair via native cryptography fallback.")
                return self.private_key, self.public_key
            except Exception as exc:
                self.logger.error("Native cryptography key generation failed: %s", exc)
                raise

    def setup_interface(self, ip_address: str, port: int = 51820) -> bool:
        """Create and configure the WireGuard interface.

        Security: the private key is written to a randomly-named temp file
        with 0o600 permissions and is GUARANTEED to be deleted even if the
        `wg set` command fails (via try/finally).

        Args:
            ip_address: Server IP with prefix length, e.g. '10.10.0.1/24'.
            port:       UDP listen port (default 51820).

        Returns:
            True on success, False on any error.
        """
        self.listen_port = port
        if not self.private_key:
            self.generate_keys()

        tmp_key_path: Optional[str] = None
        try:
            # Create interface if it doesn't already exist
            if not self._interface_exists():
                self._run_cmd(
                    ["ip", "link", "add", "dev", self.interface, "type", "wireguard"]
                )

            # Assign IP address to the interface (use replace to handle existing IP assignment safely)
            try:
                self._run_cmd(["ip", "address", "replace", "dev", self.interface, ip_address])
            except Exception:
                self._run_cmd(["ip", "address", "add", "dev", self.interface, ip_address], check=False)

            # ── SECURE TEMP FILE — guaranteed deletion in finally block ──────
            tmp_key_path = self._make_secure_tmpfile(self.private_key)

            self._run_cmd([
                "wg", "set", self.interface,
                "listen-port", str(self.listen_port),
                "private-key", tmp_key_path,
            ])
            # ─────────────────────────────────────────────────────────────────

            # Bring interface up
            self._run_cmd(["ip", "link", "set", "up", "dev", self.interface])

            self.logger.info(
                "WireGuard interface %s configured and up (IP: %s, Port: %d)",
                self.interface, ip_address, port,
            )
            return True

        except Exception as exc:
            self.logger.error(
                "Failed to setup WireGuard interface %s: %s", self.interface, exc
            )
            return False

        finally:
            # ALWAYS delete the private key file — regardless of success/failure
            if tmp_key_path:
                self._safe_unlink(tmp_key_path)

    def add_peer(self, peer: PeerConfig) -> bool:
        """Add a peer to the WireGuard interface.

        Security: if a preshared key is provided it is written to a randomly-
        named temp file with 0o600 permissions and is GUARANTEED to be deleted
        via try/finally even if `wg set` fails.

        Args:
            peer: PeerConfig describing the remote peer.

        Returns:
            True on success, False on any error.
        """
        if not self._interface_exists():
            self.logger.error(
                "Cannot add peer: Interface %s does not exist.", self.interface
            )
            return False

        cmd = [
            "wg", "set", self.interface,
            "peer", peer.public_key,
            "allowed-ips", ",".join(peer.allowed_ips),
        ]

        if peer.endpoint:
            cmd.extend(["endpoint", peer.endpoint])
        if peer.persistent_keepalive:
            cmd.extend(["persistent-keepalive", str(peer.persistent_keepalive)])

        psk_tmp_path: Optional[str] = None
        try:
            if peer.preshared_key:
                # ── SECURE TEMP FILE — guaranteed deletion in finally block ──
                psk_tmp_path = self._make_secure_tmpfile(peer.preshared_key)
                cmd.extend(["preshared-key", psk_tmp_path])

            self._run_cmd(cmd)
            self.peers[peer.public_key] = peer
            self.logger.info(
                "Added peer %s... to %s", peer.public_key[:8], self.interface
            )
            return True

        except Exception as exc:
            self.logger.error(
                "Failed to add peer %s...: %s", peer.public_key[:8], exc
            )
            return False

        finally:
            # ALWAYS delete the preshared key file — regardless of outcome
            if psk_tmp_path:
                self._safe_unlink(psk_tmp_path)

    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer from the WireGuard interface."""
        try:
            self._run_cmd(["wg", "set", self.interface, "peer", public_key, "remove"])
            self.peers.pop(public_key, None)
            self.logger.info(
                "Removed peer %s... from %s", public_key[:8], self.interface
            )
            return True
        except Exception as exc:
            self.logger.error(
                "Failed to remove peer %s...: %s", public_key[:8], exc
            )
            return False

    def teardown(self) -> bool:
        """Bring down and delete the WireGuard interface."""
        if self._interface_exists():
            try:
                self._run_cmd(["ip", "link", "del", "dev", self.interface])
                self.logger.info("Deleted WireGuard interface %s.", self.interface)
                return True
            except Exception as exc:
                self.logger.error(
                    "Failed to delete interface %s: %s", self.interface, exc
                )
                return False
        return True

    def _interface_exists(self) -> bool:
        """Return True if the network interface currently exists."""
        try:
            self._run_cmd(
                ["ip", "link", "show", "dev", self.interface], log_error=False
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def get_status(self) -> str:
        """Return the output of `wg show <interface>` or 'Interface down'."""
        if not self._interface_exists():
            return "Interface down"
        return self._run_cmd(["wg", "show", self.interface], check=False)

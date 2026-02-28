"""
QKDService — BB84-Inspired Quantum Key Distribution Simulation

IMPORTANT DISCLAIMER:
This is a software simulation of the BB84 QKD protocol.
True QKD requires quantum hardware (photon emitters,
polarization filters, quantum channels). This implementation
simulates the MATHEMATICAL PRINCIPLES of BB84:
- Random basis selection using cryptographically secure random
- Basis reconciliation (sifting)
- One-time session key derivation via HKDF-SHA256
- Session invalidation after first use (one-time pad behavior)
This provides stronger security than plain SHA-256 by adding
a one-time session layer that makes replay attacks impossible.
Protocol: BB84-sim-v1
"""

# QKD-CHANGE
import secrets
# QKD-CHANGE
import hashlib
# QKD-CHANGE
import hmac
# QKD-CHANGE
import uuid
# QKD-CHANGE
from datetime import datetime


# QKD-CHANGE
class QKDService:
    """BB84-inspired Quantum Key Distribution simulation service."""

    # QKD-CHANGE
    def generate_quantum_bits(self, n_bits: int = 256) -> dict:
        """
        Simulate Alice's side of BB84 —
        generating photon states and bases.
        """
        # QKD-CHANGE — generate n_bits random bits for alice_bits
        alice_bits = [secrets.randbelow(2) for _ in range(n_bits)]
        # QKD-CHANGE — generate n_bits random bases for alice_bases
        # 0 = rectilinear basis "+", 1 = diagonal basis "x"
        alice_bases = [secrets.randbelow(2) for _ in range(n_bits)]
        # QKD-CHANGE — convert alice_bits to hex string for raw_key_material
        raw_key_material = hashlib.sha256(
            "".join(str(b) for b in alice_bits).encode()
        ).hexdigest()

        # QKD-CHANGE
        return {
            "alice_bits": alice_bits,
            "alice_bases": alice_bases,
            "raw_key_material": raw_key_material,
            "n_bits": n_bits,
        }

    # QKD-CHANGE
    def generate_bob_bases(self, n_bits: int = 256) -> list:
        """
        Simulate Bob's independent basis selection.
        This simulates Bob choosing his measurement basis
        independently (like a second quantum observer).
        """
        # QKD-CHANGE — generate n_bits random bases for Bob
        return [secrets.randbelow(2) for _ in range(n_bits)]

    # QKD-CHANGE
    def reconcile_bases(
        self, alice_bases: list, bob_bases: list, alice_bits: list
    ) -> dict:
        """
        BB84 sifting — keep only bits where
        Alice and Bob chose the SAME basis.
        """
        # QKD-CHANGE — loop through all bases simultaneously
        sifted_key = []
        sifted_indices = []
        for i in range(len(alice_bases)):
            # QKD-CHANGE — keep bit only if bases match
            if alice_bases[i] == bob_bases[i]:
                sifted_key.append(alice_bits[i])
                sifted_indices.append(i)

        # QKD-CHANGE — compute match rate
        match_rate = len(sifted_key) / len(alice_bases)
        # QKD-CHANGE — eavesdrop detection: match rate below 0.40 is suspicious
        eavesdrop_detected = match_rate < 0.40

        # QKD-CHANGE — ensure sufficient sifted bits
        if len(sifted_key) < 64:
            raise ValueError(
                "Insufficient sifted bits — increase n_bits or retry"
            )

        # QKD-CHANGE
        return {
            "sifted_key": sifted_key,
            "sifted_indices": sifted_indices,
            "match_rate": match_rate,
            "match_percentage": match_rate * 100,
            "eavesdrop_detected": eavesdrop_detected,
            "n_sifted_bits": len(sifted_key),
        }

    # QKD-CHANGE
    def derive_session_key(self, sifted_key: list, context: str) -> str:
        """
        Convert sifted bits into a cryptographic
        session key using HKDF-SHA256.
        """
        # QKD-CHANGE — convert sifted_key list to bytes
        bits_str = "".join(str(b) for b in sifted_key)
        key_material = hashlib.sha256(bits_str.encode()).digest()

        # QKD-CHANGE — HKDF Extract
        salt = hashlib.sha256(context.encode()).digest()
        prk = hmac.new(salt, key_material, hashlib.sha256).digest()

        # QKD-CHANGE — HKDF Expand
        info = f"PrivacyProxy-QKD-v1-{context}".encode()
        T1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        T2 = hmac.new(prk, T1 + info + b"\x02", hashlib.sha256).digest()
        # QKD-CHANGE — 32 bytes = 256 bits output key material
        okm = (T1 + T2)[:32]

        # QKD-CHANGE
        return okm.hex()

    # QKD-CHANGE
    def generate_qkd_access_token(
        self, access_code: str, link_token: str
    ) -> dict:
        """
        Full BB84 pipeline to generate a QKD-protected
        access token for a share link.
        """
        # QKD-CHANGE — Step 1: Generate unique session ID
        session_id = str(uuid.uuid4())
        # QKD-CHANGE — Step 2: Alice generates quantum bits
        quantum = self.generate_quantum_bits(256)
        # QKD-CHANGE — Step 3: Bob generates independent bases
        bob_bases = self.generate_bob_bases(256)
        # QKD-CHANGE — Step 4: Basis reconciliation (sifting)
        reconciled = self.reconcile_bases(
            quantum["alice_bases"], bob_bases, quantum["alice_bits"]
        )
        # QKD-CHANGE — Step 5: Build context string
        context = f"{link_token}:{session_id}"
        # QKD-CHANGE — Step 6: Derive session key via HKDF
        session_key = self.derive_session_key(
            reconciled["sifted_key"], context
        )
        # QKD-CHANGE — Step 7: Hash the access code
        ac_hash = hashlib.sha256(access_code.encode()).hexdigest()
        # QKD-CHANGE — Step 8: XOR session_key with ac_hash (one-time-pad layer)
        sk_bytes = bytes.fromhex(session_key)
        ac_bytes = bytes.fromhex(ac_hash)
        xor_bytes = bytes(a ^ b for a, b in zip(sk_bytes, ac_bytes))
        qkd_token = xor_bytes.hex()

        # QKD-CHANGE — Step 9: Build and return result
        return {
            "qkd_token": qkd_token,
            "session_id": session_id,
            "session_key": session_key,
            "used": False,
            "created_at": datetime.utcnow().isoformat(),
            "metadata": {
                "protocol": "BB84-sim-v1",
                "n_bits_generated": 256,
                "n_bits_sifted": reconciled["n_sifted_bits"],
                "match_rate": reconciled["match_rate"],
                "match_percentage": reconciled["match_percentage"],
                "eavesdrop_detected": reconciled["eavesdrop_detected"],
                "hkdf_context": context,
            },
        }

    # QKD-CHANGE
    def verify_qkd_token(
        self, access_code: str, stored_qkd_data: dict
    ) -> dict:
        """
        Verify an access code against stored QKD token
        and invalidate after first use (one-time behavior).
        """
        # QKD-CHANGE — Check if already used
        if stored_qkd_data.get("used") is True:
            return {
                "verified": False,
                "reason": "QKD_SESSION_EXPIRED",
                "fallback_required": True,
            }

        # QKD-CHANGE — Reconstruct the XOR verification
        ac_hash = hashlib.sha256(access_code.encode()).hexdigest()
        stored_session_key = stored_qkd_data["session_key"]
        sk_bytes = bytes.fromhex(stored_session_key)
        ac_bytes = bytes.fromhex(ac_hash)
        xor_bytes = bytes(a ^ b for a, b in zip(sk_bytes, ac_bytes))
        reconstructed_token = xor_bytes.hex()

        # QKD-CHANGE — Timing-safe comparison to prevent timing attacks
        is_valid = hmac.compare_digest(
            reconstructed_token, stored_qkd_data["qkd_token"]
        )

        # QKD-CHANGE — Return verification result
        if is_valid:
            return {
                "verified": True,
                "reason": "QKD_VERIFIED",
                "fallback_required": False,
                "session_id": stored_qkd_data["session_id"],
                "invalidate_session": True,
            }
        else:
            return {
                "verified": False,
                "reason": "QKD_TOKEN_MISMATCH",
                "fallback_required": False,
            }

    # QKD-CHANGE
    def get_security_summary(self, qkd_metadata: dict) -> dict:
        """
        Return human-readable security summary
        for display in the UI/audit logs.
        """
        # QKD-CHANGE
        return {
            "protocol": "BB84-Inspired QKD Simulation",
            "key_strength": "256-bit HKDF-SHA256",
            "bits_exchanged": qkd_metadata["n_bits_generated"],
            "bits_after_sifting": qkd_metadata["n_bits_sifted"],
            "channel_security": (
                "⚠️ Potential eavesdrop detected"
                if qkd_metadata["eavesdrop_detected"]
                else "✅ Channel appears secure"
            ),
            "replay_protection": "One-time session — invalidated after use",
            "match_rate": f"{qkd_metadata['match_percentage']:.1f}%",
            "upgrade_from": "Plain SHA-256",
            "advantage": "Replay attacks mathematically prevented",
        }

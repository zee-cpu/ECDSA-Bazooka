"""Standalone sieve worker: solve ECDSA-HNP with a public-key predicate,
Sage-free. Reuses g6k's USVPPredSieve via bdd-predicate's usvp.py.

This is the port called for in Section 7 of the L=2 plan: the ECDSA harness
(basis + predicate + key recovery) rewritten without SageMath, while the uSVP
solver core is reused unchanged.
"""
import os
import sys

from ecdsa import SECP256k1
from fpylll import IntegerMatrix, LLL

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)

# Albrecht-Heninger bdd-predicate (upstream GPL) is an external dependency, not
# vendored -- clone it and point BDD_PREDICATE_DIR at it (default: third_party/).
# See worker/README.md.
BDD_DIR = os.environ.get(
    "BDD_PREDICATE_DIR", os.path.join(_REPO, "third_party", "bdd-predicate")
)
if BDD_DIR not in sys.path:
    sys.path.insert(0, BDD_DIR)

from usvp import usvp_pred_solve  # noqa: E402

G = SECP256k1.generator
N = SECP256k1.order

# usvp_pred_solve injects the live MatGSO object here (predicate.__globals__["M"]).
M = None


def _load_c_predicate():
    # predicate_shim.py is a sibling module (cffi loader for libbazooka_predicate).
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    from predicate_shim import predicate as c_predicate
    return c_predicate


class SieveWorker:
    def __init__(self, signatures, pubkey_hex):
        self.sigs = signatures            # list of (klen, h, r, s); klen may vary
        self.pubkey_hex = pubkey_hex
        self.m = len(signatures)
        self.dim = self.m + 1
        # Per-signature nonce centre w_i = 2**(klen_i - 1). Non-uniform klen
        # (fractional average L) is handled by scaling each column by
        # f_i = max_w / w_i so every column carries the same target magnitude.
        self.w_list = [2 ** (sig[0] - 1) for sig in signatures]
        self.max_w = max(self.w_list)
        self.f_list = [self.max_w // wi for wi in self.w_list]
        self.w0 = self.w_list[0]          # centre for signature 0 (the recovered one)
        self.f0 = self.f_list[0]
        # compressed SEC1 pubkey (0x02/0x03 || x) for the C shim
        px = int(pubkey_hex[:64], 16)
        py = int(pubkey_hex[64:], 16)
        self.pubkey_compressed = (b"\x02" if py % 2 == 0 else b"\x03") + px.to_bytes(32, "big")

    @classmethod
    def from_instance(cls, inst):
        return cls(inst.signatures, inst.pubkey_hex)

    def _build_basis(self):
        """Boneh-Venkatesan HNP basis (A&H construction), signature m-1 as reference.
        Columns are scaled by f_i so non-uniform klen contributes equal-magnitude
        targets."""
        p = N
        r = [sig[2] for sig in self.sigs]
        s = [sig[3] for sig in self.sigs]
        h = [sig[1] for sig in self.sigs]
        w_list, f_list = self.w_list, self.f_list
        rm, sm, hm, wm = r[-1], s[-1], h[-1], w_list[-1]
        inv_rm = pow(rm, -1, p)

        a_list, t_list = [], []
        for i in range(self.m - 1):
            inv_si = pow(s[i], -1, p)
            a = (w_list[i] - r[i] * inv_si * inv_rm * sm * wm - inv_si * h[i]
                 + r[i] * inv_si * hm * inv_rm) % p
            t = (-r[i] * inv_si * inv_rm * sm) % p
            a_list.append(a)
            t_list.append(t)

        d = self.dim
        A = IntegerMatrix(d, d)
        for i in range(d - 2):
            A[i, i] = int(p * f_list[i])
        for i in range(d - 2):
            A[d - 2, i] = int(t_list[i] * f_list[i])
        A[d - 2, d - 2] = int(f_list[-1])
        for i in range(d - 2):
            A[d - 1, i] = int(a_list[i] * f_list[i])
        A[d - 1, d - 1] = int(self.max_w)
        return A

    def _target_norm_sq(self):
        w, m = self.max_w, self.m
        return (m * w * w) // 3 + w * w

    def _make_predicate(self, use_c_predicate=False):
        w0, f0, tau = self.w0, self.f0, self.max_w
        h0, r0, s0 = self.sigs[0][1], self.sigs[0][2], self.sigs[0][3]
        inv_r0 = pow(r0, -1, N)
        pubkey_compressed = self.pubkey_compressed
        c_predicate = _load_c_predicate() if use_c_predicate else None

        def hits(std0):
            # std0 is the raw first coordinate (a multiple of f0); the signature-0
            # nonce is (std0 // f0) +/- w0. Check either sign against the pubkey.
            val0 = std0 // f0
            for k in ((val0 + w0) % N, (w0 - val0) % N):
                if c_predicate is not None:
                    d = inv_r0 * (k * s0 - h0) % N
                    if c_predicate(int(d).to_bytes(32, "big"), pubkey_compressed):
                        return True
                elif (k * G).x() % N == r0:
                    return True
            return False

        def predicate(v, standard_basis=True):
            if standard_basis:
                nz = int(v[-1])
                std0 = int(v[0])
            else:
                B = M.B  # injected by usvp_pred_solve
                ncols = B.ncols
                nz = sum(int(round(v[i])) * int(B[i][ncols - 1]) for i in range(len(v)))
                std0 = sum(int(round(v[i])) * int(B[i][0]) for i in range(len(v)))
            if abs(nz) != tau:
                return False
            return hits(std0)

        return predicate

    def _recover_key(self, solution):
        w0, f0 = self.w0, self.f0
        val0 = int(solution[0]) // f0
        h0, r0, s0 = self.sigs[0][1], self.sigs[0][2], self.sigs[0][3]
        inv_r0 = pow(r0, -1, N)
        for k in ((val0 + w0) % N, (w0 - val0) % N):
            if (k * G).x() % N == r0:
                dcand = inv_r0 * (k * s0 - h0) % N
                P = dcand * G
                if "%064x%064x" % (P.x(), P.y()) == self.pubkey_hex:
                    return dcand
        return None

    def solve(self, solver=None, use_c_predicate=False):
        A = self._build_basis()
        LLL.reduction(A)
        predicate = self._make_predicate(use_c_predicate=use_c_predicate)
        res = usvp_pred_solve(
            A,
            predicate,
            squared_target_norm=self._target_norm_sq(),
            solver=solver,
        )
        if not res.success:
            return None
        return self._recover_key(res.solution)

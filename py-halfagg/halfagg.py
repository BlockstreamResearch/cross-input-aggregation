#!/usr/bin/env python3
"""
Schnorr signature half-aggregation reference implementation

WARNING: This implementation is for demonstration purposes only and _not_ to
be used in production environments.
"""

from secp256k1lab.secp256k1 import (
    G,
    GE,
    Scalar,
)
from secp256k1lab.util import (
    bytes_from_int,
    int_from_bytes,
    tagged_hash,
)


# Group order
n = GE.ORDER

def Aggregate(pms):
    """
    Aggregates an array of triples (public key, message, signature) into a single aggregate signature.

    :param pms: An array of triples (public key, message, signature).
    :return: The aggregate signature.
    """

    # Let aggsig = bytes(0)
    aggsig = bytes([0] * 32)

    pm_aggd = []
    if not VerifyAggregate(aggsig, pm_aggd):
        raise

    # Return IncAggregate(aggsig, pms0..u-1); fail if that fails.
    return IncAggregate(aggsig, pm_aggd, pms)


# IncAggregate(aggsig, pm_aggd0..v-1, pms_to_agg0..u-1)
def IncAggregate(aggsig, pm_aggd, pms_to_agg):
    """
    Incrementally aggregates an additional array of triples (public key, message, signature)
    into an existing aggregate signature.

    :param aggsig: A byte array representing the aggregate signature.
    :param pm_aggd: An array of tuples (public key, message).
    :param pms_to_agg: An array of triples (public key, message, signature).
    :return: The new aggregate signature.
    """

    # Fail if v + u ≥ 2^16
    v = len(pm_aggd)
    u = len(pms_to_agg)
    if v + u >= 2**16:
        raise ValueError("v + u must be less than 2^16")

    # Fail if len(aggsig) ≠ 32 * (v + 1)
    if len(aggsig) != 32 * (v + 1):
        raise ValueError("Length of aggsig must be 32 * (v + 1)")

    r_values = []
    pmr_to_agg = []

    # For i = 0 .. v-1:
    for i in range(v):
        # Let (pki, mi) = pm_aggdi
        (pki, mi) = pm_aggd[i]

        # Let ri = aggsig[i⋅32:(i+1)⋅32]
        ri = aggsig[i * 32:(i + 1) * 32]
        r_values.append(ri)

        pmr_to_agg.append((pki, mi, ri))

    z_values = []
    s_values = []

    # For i = v .. v+u-1:
    for i in range(v, v + u):
        # Let (pki, mi, sigi) = pms_to_aggi-v
        (pki, mi, sigi) = pms_to_agg[i - v]

        # Let ri = sigi[0:32]
        ri = sigi[0:32]
        r_values.append(ri)

        # Let si = int(sigi[32:64]); fail if si ≥ n
        si = int_from_bytes(sigi[32:64])
        if si >= n:
            raise ValueError("si must be less than n")
        s_values.append(si)

        # If i = 0:
        #     Let zi = 1
        # Else:
        #     Let zi = int(hashHalfAgg/randomizer(r0 || pk0 || m0 || ... || ri || pki || mi)) mod n
        pmr_to_agg += [(pki, mi, sigi[0:32]) for (pki, mi, sigi) in pms_to_agg]
        z_values.append(hashHalfAgg_randomizer(pmr_to_agg, i))

    # Let s = int(aggsig[(v⋅32:(v+1)⋅32]) + zv⋅sv + ... + zv+u-1⋅sv+u-1 mod n
    s = int_from_bytes(aggsig[v * 32:(v + 1) * 32])
    if s >= n:
        raise ValueError("s must be less than n")

    for i in range(u):
        s = (s + z_values[i] * s_values[i]) % n

    # Return r0 || ... || rv+u-1 || bytes(s)
    return b''.join(r_values) + bytes_from_int(s)


# VerifyAggregate(aggsig, pm_aggd0..u-1)
def VerifyAggregate(aggsig, pm_aggd):
    """
    Verifies an aggregate signature against an array of public key and message tuples.

    :param aggsig: A byte array representing the aggregate signature.
    :param pm_aggd: An array of tuples (public key, message).
    :return: Boolean indicating whether the verification is successful.
    """

    # Fail if u ≥ 216
    u = len(pm_aggd)
    if u >= 2**16:
        raise ValueError("u must be less than 2^16")

    # Fail if len(aggsig) ≠ 32 * (u + 1)
    if len(aggsig) != 32 * (u + 1):
        raise ValueError("Length of aggsig must be 32 * (u + 1)")

    z_values = []
    R_values = []
    P_values = []
    e_values = []
    r_values = []

    # For i = 0 .. u-1:
    for i in range(u):
        # Let (pki, mi) = pm_aggdi
        (pki, mi) = pm_aggd[i]

        # Let Pi = lift_x(int(pki)); fail if that fails
        try:
            Pi = GE.lift_x(int_from_bytes(pki))
        except ValueError:
            return False
        P_values.append(Pi)

        # Let ri = aggsig[i⋅32:(i+1)⋅32]
        ri = aggsig[i * 32:(i + 1) * 32]
        # Let Ri = lift_x(int(ri)); fail if that fails
        try:
            Ri = GE.lift_x(int_from_bytes(ri))
        except ValueError:
            return False
        R_values.append(Ri)
        r_values.append(ri)

        # Let ei = int(hashBIP0340/challenge(bytes(ri) || pki || mi)) mod n
        ei = int_from_bytes(hashBIP0340_challenge(ri, pki, mi)) % n
        e_values.append(ei)

        # If i = 0:
        #     Let zi = 1
        # Else:
        #     Let zi = int(hashHalfAgg/randomizer(r0 || pk0 || m0 || ... || ri || pki || mi)) mod n
        pmr = [(pki, mi, ri) for (pki, mi), ri in zip(pm_aggd, r_values)]
        z_values.append(hashHalfAgg_randomizer(pmr, i))

    # Let s = int(aggsig[u⋅32:(u+1)⋅32]); fail if s ≥ n
    s = int_from_bytes(aggsig[u * 32:(u + 1) * 32])
    if s >= n:
        return False
    s = Scalar.from_int_checked(s)

    # Fail if s⋅G ≠ z0⋅(R0 + e0⋅P0) + ... + zu-1⋅(Ru-1 + eu-1⋅Pu-1)
    lhs = s * G
    rhs = GE()
    for i in range(u):
        e = Scalar.from_int_checked(e_values[i])
        P = P_values[i]
        R = R_values[i]
        rhsi = R + e * P

        z = Scalar.from_int_checked(z_values[i])
        rhsi = z * rhsi

        rhs = rhs + rhsi

    return lhs == rhs


def hashBIP0340_challenge(sig, pubkey, msg):
    return tagged_hash("BIP0340/challenge", sig + pubkey + msg)


def hashHalfAgg_randomizer(pmr, index):
    if index == 0:
        return 1

    random_input = bytes()
    for i in range(index + 1):
        (pki, mi, ri) = pmr[i]
        random_input += ri
        random_input += pki
        random_input += mi

    return int_from_bytes(tagged_hash("HalfAgg/randomizer", random_input)) % n

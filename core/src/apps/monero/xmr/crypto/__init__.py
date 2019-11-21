# Author: Dusan Klinec, ph4r05, 2018
#
# Resources:
# https://cr.yp.to
# https://github.com/monero-project/mininero
# https://godoc.org/github.com/agl/ed25519/edwards25519
# https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-00#section-4
# https://github.com/monero-project/research-lab

from trezor.crypto import hmac, monero as tcry, random
from trezor.crypto.hashlib import sha3_256
from trezor import log

NULL_KEY_ENC = b"\x00" * 32


class defaultdict:
    @staticmethod
    def __new__(cls, default_factory=None, **kwargs):
        # Some code (e.g. urllib.urlparse) expects that basic defaultdict
        # functionality will be available to subclasses without them
        # calling __init__().
        self = super(defaultdict, cls).__new__(cls)
        self.d = {}
        return self

    def __init__(self, default_factory=None, **kwargs):
        self.d = kwargs
        self.default_factory = default_factory

    def __getitem__(self, key):
        try:
            return self.d[key]
        except KeyError:
            v = self.__missing__(key)
            self.d[key] = v
            return v

    def __setitem__(self, key, v):
        self.d[key] = v

    def __delitem__(self, key):
        del self.d[key]

    def __contains__(self, key):
        return key in self.d

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        return self.default_factory()

    def clear(self):
        self.d = {}


FNCSX = [defaultdict(lambda: 0)]

def _report(logg=False):
    if logg: log.debug(__name__, "---- Crypto call report")
    else: print('Fnc call report: [')

    FNCS = FNCSX[0]
    ln = len(FNCS.d)
    for ix, k in enumerate(sorted(FNCS.d)):
        if logg: log.debug(__name__, '  %s: %s', k, FNCS.d[k])
        else: print('{"%s": %s}%s' % (k, FNCS.d[k], ',' if ix+1 < ln else ''))
    if not logg: print(']')
    FNCS.clear()

def _report_reset():
    FNCSX[0].clear()

def wrap_fncs(*funcs):
    ret = []

    def mwrapper(func, i):
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper

    for ix, func in enumerate(funcs):
        ret.append(mwrapper(func, ix))
    return ret

def _wrap_count(func, fname=None):
    def wrapper(*args, **kwargs):
        FNCSX[0][fname] += 1
        return func(*args, **kwargs)
    return wrapper

report, report_reset, wrap_count = wrap_fncs(_report, _report_reset, _wrap_count)

def report_get():
    return FNCSX[0]

def report_set(fncs):
    global FNCSX
    FNCSX[0] = fncs


random_bytes = wrap_count(random.bytes, 'random_bytes')
ct_equals = wrap_count(tcry.ct_equals, 'ct_equal')
hasher = wrap_count(tcry.hasher, 'hasher')
prng = wrap_count(tcry.prng, 'prng')


def keccak_factory(data=None):
    return hasher(data)


get_keccak = wrap_count(keccak_factory, 'keccak_factory')
keccak_hash = wrap_count(tcry.xmr_fast_hash, 'xmr_fast_hash')
keccak_hash_into = wrap_count(tcry.xmr_fast_hash, 'xmr_fast_hash')


def keccak_2hash(inp, buff=None):
    buff = buff if buff else bytearray(32)
    keccak_hash_into(buff, inp)
    keccak_hash_into(buff, buff)
    return buff


def compute_hmac(key, msg=None):
    h = hmac.new(key, msg=msg, digestmod=keccak_factory)
    return h.digest()


#
# EC
#


new_point = wrap_count(tcry.ge25519_set_neutral, 'new_point')


def _new_scalar():
    return tcry.init256_modm(0)
new_scalar = wrap_count(_new_scalar, 'new_scalar')

decodepoint = wrap_count(tcry.ge25519_unpack_vartime, 'decodepoint')
decodepoint_into = wrap_count(tcry.ge25519_unpack_vartime, 'decodepoint_into')
encodepoint = wrap_count(tcry.ge25519_pack, 'encodepoint')
encodepoint_into = wrap_count(tcry.ge25519_pack, 'encodepoint_into')

decodeint = wrap_count(tcry.unpack256_modm, 'decodeint')
decodeint_into_noreduce = wrap_count(tcry.unpack256_modm_noreduce, 'decodeint_into_noreduce')
decodeint_into = wrap_count(tcry.unpack256_modm, 'decodeint_into')
encodeint = wrap_count(tcry.pack256_modm, 'encodeint')
encodeint_into = wrap_count(tcry.pack256_modm, 'encodeint_into')

check_ed25519point = wrap_count(tcry.ge25519_check, 'check_ed25519point')

scalarmult_base = wrap_count(tcry.ge25519_scalarmult_base, 'scalarmult_base')
scalarmult_base_into = wrap_count(tcry.ge25519_scalarmult_base, 'scalarmult_base_into')
scalarmult = wrap_count(tcry.ge25519_scalarmult, 'scalarmult')
scalarmult_into = wrap_count(tcry.ge25519_scalarmult, 'scalarmult_into')

point_add = wrap_count(tcry.ge25519_add, 'point_add')
point_add_into = wrap_count(tcry.ge25519_add, 'point_add_into')
point_sub = wrap_count(tcry.ge25519_sub, 'point_sub')
point_sub_into = wrap_count(tcry.ge25519_sub, 'point_sub_into')
point_eq = wrap_count(tcry.ge25519_eq, 'point_eq')
point_double = wrap_count(tcry.ge25519_double, 'point_double')
point_double_into = wrap_count(tcry.ge25519_double, 'point_double_into')
point_mul8 = wrap_count(tcry.ge25519_mul8, 'point_mul8')
point_mul8_into = wrap_count(tcry.ge25519_mul8, 'point_mul8_into')

INV_EIGHT = b"\x79\x2f\xdc\xe2\x29\xe5\x06\x61\xd0\xda\x1c\x7d\xb3\x9d\xd3\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06"
INV_EIGHT_SC = decodeint(INV_EIGHT)


def sc_inv_eight():
    return INV_EIGHT_SC


#
# Zmod(order), scalar values field
#


def sc_0():
    return tcry.init256_modm(0)


def sc_0_into(r):
    return tcry.init256_modm(r, 0)


def sc_init(x):
    if x >= (1 << 64):
        raise ValueError("Initialization works up to 64-bit only")
    return tcry.init256_modm(x)


def sc_init_into(r, x):
    if x >= (1 << 64):
        raise ValueError("Initialization works up to 64-bit only")
    return tcry.init256_modm(r, x)


sc_copy = wrap_count(tcry.init256_modm, 'sc_copy')
sc_get64 = wrap_count(tcry.get256_modm, 'sc_get64')
sc_check = wrap_count(tcry.check256_modm, 'sc_check')
check_sc = wrap_count(tcry.check256_modm, 'check_sc')

sc_add = wrap_count(tcry.add256_modm, 'sc_add')
sc_add_into = wrap_count(tcry.add256_modm, 'sc_add_into')
sc_sub = wrap_count(tcry.sub256_modm, 'sc_sub')
sc_sub_into = wrap_count(tcry.sub256_modm, 'sc_sub_into')
sc_mul = wrap_count(tcry.mul256_modm, 'sc_mul')
sc_mul_into = wrap_count(tcry.mul256_modm, 'sc_mul_into')


def sc_isnonzero(c):
    """
    Returns true if scalar is non-zero
    """
    return not tcry.iszero256_modm(c)


sc_eq = wrap_count(tcry.eq256_modm, 'sc_eq')
sc_mulsub = wrap_count(tcry.mulsub256_modm, 'sc_mulsub')
sc_mulsub_into = wrap_count(tcry.mulsub256_modm, 'sc_mulsub_into')
sc_muladd = wrap_count(tcry.muladd256_modm, 'sc_muladd')
sc_muladd_into = wrap_count(tcry.muladd256_modm, 'sc_muladd_into')
sc_inv_into = wrap_count(tcry.inv256_modm, 'sc_inv_into')


def random_scalar(r=None):
    return tcry.xmr_random_scalar(r if r is not None else new_scalar())


#
# GE - ed25519 group
#


def ge25519_double_scalarmult_base_vartime(a, A, b):
    """
    void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2);
    r = a * A + b * B
    """
    R = tcry.ge25519_double_scalarmult_vartime(A, a, b)
    return R


ge25519_double_scalarmult_vartime2 = tcry.xmr_add_keys3


def identity(byte_enc=False):
    idd = tcry.ge25519_set_neutral()
    return idd if not byte_enc else encodepoint(idd)


identity_into = tcry.ge25519_set_neutral

"""
https://www.imperialviolet.org/2013/12/25/elligator.html
http://elligator.cr.yp.to/
http://elligator.cr.yp.to/elligator-20130828.pdf
"""

#
# Monero specific
#


cn_fast_hash = wrap_count(keccak_hash, 'cn_fast_hash')


def _hash_to_scalar(data, length=None):
    """
    H_s(P)
    """
    dt = data[:length] if length else data
    return tcry.xmr_hash_to_scalar(dt)


def _hash_to_scalar_into(r, data, length=None):
    dt = data[:length] if length else data
    return tcry.xmr_hash_to_scalar(r, dt)


hash_to_scalar = wrap_count(_hash_to_scalar, 'hash_to_scalar')
hash_to_scalar_into = wrap_count(_hash_to_scalar_into, 'hash_to_scalar_into')

"""
H_p(buf)

Code adapted from MiniNero: https://github.com/monero-project/mininero
https://github.com/monero-project/research-lab/blob/master/whitepaper/ge_fromfe_writeup/ge_fromfe.pdf
http://archive.is/yfINb
"""
hash_to_point = wrap_count(tcry.xmr_hash_to_ec, 'hash_to_point')
hash_to_point_into = wrap_count(tcry.xmr_hash_to_ec, 'hash_to_point_into')


#
# XMR
#


xmr_H = tcry.ge25519_set_h


def scalarmult_h(i):
    return scalarmult(xmr_H(), sc_init(i) if isinstance(i, int) else i)


add_keys2 = wrap_count(tcry.xmr_add_keys2_vartime, 'add_keys2')
add_keys2_into = wrap_count(tcry.xmr_add_keys2_vartime, 'add_keys2_into')
add_keys3 = wrap_count(tcry.xmr_add_keys3_vartime, 'add_keys3')
add_keys3_into = wrap_count(tcry.xmr_add_keys3_vartime, 'add_keys3_into')
gen_commitment = wrap_count(tcry.xmr_gen_c, 'gen_commitment')


def generate_key_derivation(pub, sec):
    """
    Key derivation: 8*(key2*key1)
    """
    sc_check(sec)  # checks that the secret key is uniform enough...
    check_ed25519point(pub)
    return tcry.xmr_generate_key_derivation(pub, sec)


def derivation_to_scalar(derivation, output_index):
    """
    H_s(derivation || varint(output_index))
    """
    check_ed25519point(derivation)
    return tcry.xmr_derivation_to_scalar(derivation, output_index)


def derive_public_key(derivation, output_index, B):
    """
    H_s(derivation || varint(output_index))G + B
    """
    check_ed25519point(B)
    return tcry.xmr_derive_public_key(derivation, output_index, B)


def derive_secret_key(derivation, output_index, base):
    """
    base + H_s(derivation || varint(output_index))
    """
    sc_check(base)
    return tcry.xmr_derive_private_key(derivation, output_index, base)


def get_subaddress_secret_key(secret_key, major=0, minor=0):
    """
    Builds subaddress secret key from the subaddress index
    Hs(SubAddr || a || index_major || index_minor)
    """
    return tcry.xmr_get_subaddress_secret_key(major, minor, secret_key)


#
# Repr invariant
#


def generate_signature(data, priv):
    """
    Generate EC signature
    crypto_ops::generate_signature(const hash &prefix_hash, const public_key &pub, const secret_key &sec, signature &sig)
    """
    pub = scalarmult_base(priv)

    k = random_scalar()
    comm = scalarmult_base(k)

    buff = data + encodepoint(pub) + encodepoint(comm)
    c = hash_to_scalar(buff)
    r = sc_mulsub(priv, c, k)
    return c, r, pub


def check_signature(data, c, r, pub):
    """
    EC signature verification
    """
    check_ed25519point(pub)
    if sc_check(c) != 0 or sc_check(r) != 0:
        raise ValueError("Signature error")

    tmp2 = point_add(scalarmult(pub, c), scalarmult_base(r))
    buff = data + encodepoint(pub) + encodepoint(tmp2)
    tmp_c = hash_to_scalar(buff)
    res = sc_sub(tmp_c, c)
    return not sc_isnonzero(res)


def xor8(buff, key):
    for i in range(8):
        buff[i] ^= key[i]
    return buff

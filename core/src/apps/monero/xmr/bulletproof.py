import gc
from micropython import const
import ubinascii
import sys
from trezor import utils
from trezor.utils import memcpy as tmemcpy
from trezor.crypto.hashlib import sha256

from apps.monero.xmr import crypto
from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b_into, uvarint_size

# Constants

_BP_LOG_N = const(6)
_BP_N = const(64)  # 1 << _BP_LOG_N
_BP_M = const(16)  # maximal number of bulletproofs

_ZERO = b"\x00" * 32
_ONE = b"\x01" + b"\x00" * 31
_TWO = b"\x02" + b"\x00" * 31
_EIGHT = b"\x08" + b"\x00" * 31
_INV_EIGHT = crypto.INV_EIGHT
_MINUS_ONE = b"\xec\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
# _MINUS_INV_EIGHT = b"\x74\xa4\x19\x7a\xf0\x7d\x0b\xf7\x05\xc2\xda\x25\x2b\x5c\x0b\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a"

# Monero H point
_XMR_H = b"\x8b\x65\x59\x70\x15\x37\x99\xaf\x2a\xea\xdc\x9f\xf1\xad\xd0\xea\x6c\x72\x51\xd5\x41\x54\xcf\xa9\x2c\x17\x3a\x0d\xd3\x9c\x1f\x94"
_XMR_HP = crypto.xmr_H()

# ip12 = inner_product(oneN, twoN);
_BP_IP12 = b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
_PRINT_INT = False

PRNG = crypto.prng(_ZERO)

#
# Rct keys operations
# tmp_x are global working registers to minimize memory allocations / heap fragmentation.
# Caution has to be exercised when using the registers and operations using the registers
#

_hasher = crypto.get_keccak()
_tmp_bf_0 = bytearray(32)
_tmp_bf_1 = bytearray(32)
_tmp_bf_2 = bytearray(32)
_tmp_bf_exp = bytearray(11 + 32 + 4)

_tmp_pt_1 = crypto.new_point()
_tmp_pt_2 = crypto.new_point()
_tmp_pt_3 = crypto.new_point()
_tmp_pt_4 = crypto.new_point()

_tmp_sc_1 = crypto.new_scalar()
_tmp_sc_2 = crypto.new_scalar()
_tmp_sc_3 = crypto.new_scalar()
_tmp_sc_4 = crypto.new_scalar()


def _eprint(*args, **kwargs):
    if not _PRINT_INT:
        return
    print(*args, **kwargs)


def _ehexlify(x):
    if not _PRINT_INT:
        return
    ubinascii.hexlify(x)


def _ensure_dst_key(dst=None):
    if dst is None:
        dst = bytearray(32)
    return dst


def memcpy(dst, dst_off, src, src_off, len):
    if dst is not None:
        tmemcpy(dst, dst_off, src, src_off, len)
    return dst


def _alloc_scalars(num=1):
    return (crypto.new_scalar() for _ in range(num))


def _copy_key(dst, src):
    for i in range(32):
        dst[i] = src[i]
    return dst


def _init_key(val, dst=None):
    dst = _ensure_dst_key(dst)
    return _copy_key(dst, val)


def _gc_iter(i):
    if i & 127 == 0:
        gc.collect()


def _invert(dst, x=None, x_raw=None, raw=False):
    dst = _ensure_dst_key(dst) if not raw else (crypto.new_scalar() if not dst else dst)
    if x:
        crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.sc_inv_into(_tmp_sc_2, _tmp_sc_1 if x else x_raw)
    if raw:
        return crypto.sc_copy(dst, _tmp_sc_2)
    else:
        crypto.encodeint_into(dst, _tmp_sc_2)
        return dst


def _scalarmult_key(dst, P, s, s_raw=None, tmp_pt=_tmp_pt_1):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt, P)
    if s:
        crypto.decodeint_into_noreduce(_tmp_sc_1, s)
    crypto.scalarmult_into(tmp_pt, tmp_pt, _tmp_sc_1 if s else s_raw)
    crypto.encodepoint_into(dst, tmp_pt)
    return dst


def _scalarmultH(dst, x):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into(_tmp_sc_1, x)
    crypto.scalarmult_into(_tmp_pt_1, _XMR_HP, _tmp_sc_1)
    crypto.encodepoint_into(dst, _tmp_pt_1)
    return dst


def _scalarmult_base(dst, x):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.scalarmult_base_into(_tmp_pt_1, _tmp_sc_1)
    crypto.encodepoint_into(dst, _tmp_pt_1)
    return dst


def _sc_gen(dst=None):
    dst = _ensure_dst_key(dst)
    buff = PRNG.next(32, bytearray(32))
    crypto.decodeint_into(_tmp_sc_1, buff)
    #crypto.random_scalar(_tmp_sc_1)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _sc_add(dst, a, b):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.sc_add_into(_tmp_sc_3, _tmp_sc_1, _tmp_sc_2)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_sub(dst, a, b, a_raw=None, b_raw=None):
    dst = _ensure_dst_key(dst)
    if a:
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    if b:
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.sc_sub_into(_tmp_sc_3, _tmp_sc_1 if a else a_raw, _tmp_sc_2 if b else b_raw)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_mul(dst, a=None, b=None, a_raw=None, b_raw=None):
    dst = _ensure_dst_key(dst)
    if a:
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    if b:
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_1 if a else a_raw, _tmp_sc_2 if b else b_raw)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_muladd(dst, a, b, c, a_raw=None, b_raw=None, c_raw=None, raw=False):
    dst = _ensure_dst_key(dst) if not raw else (dst if dst else crypto.new_scalar())
    if a:
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    if b:
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    if c:
        crypto.decodeint_into_noreduce(_tmp_sc_3, c)
    crypto.sc_muladd_into(
        _tmp_sc_4 if not raw else dst,
        _tmp_sc_1 if a else a_raw,
        _tmp_sc_2 if b else b_raw,
        _tmp_sc_3 if c else c_raw,
    )
    if not raw:
        crypto.encodeint_into(dst, _tmp_sc_4)
    return dst


def _sc_mulsub(dst, a, b, c):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodeint_into_noreduce(_tmp_sc_3, c)
    crypto.sc_mulsub_into(_tmp_sc_4, _tmp_sc_1, _tmp_sc_2, _tmp_sc_3)
    crypto.encodeint_into(dst, _tmp_sc_4)
    return dst


def _add_keys(dst, A, B):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.point_add_into(_tmp_pt_3, _tmp_pt_1, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _sub_keys(dst, A, B):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.point_sub_into(_tmp_pt_3, _tmp_pt_1, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _add_keys2(dst, a, b, B):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodepoint_into(_tmp_pt_1, B)
    crypto.add_keys2_into(_tmp_pt_2, _tmp_sc_1, _tmp_sc_2, _tmp_pt_1)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _add_keys3(dst, a, A, b, B):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.add_keys3_into(_tmp_pt_3, _tmp_sc_1, _tmp_pt_1, _tmp_sc_2, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _hash_to_scalar(dst, data):
    dst = _ensure_dst_key(dst)
    crypto.hash_to_scalar_into(_tmp_sc_1, data)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _hash_vct_to_scalar(dst, data):
    dst = _ensure_dst_key(dst)
    _hasher.reset()
    for x in data:
        _hasher.update(x)
    dst = _hasher.digest(dst)

    crypto.decodeint_into(_tmp_sc_1, dst)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _get_exponent(dst, base, idx):
    dst = _ensure_dst_key(dst)
    salt = b"bulletproof"
    lsalt = const(11)  # len(salt)
    final_size = lsalt + 32 + uvarint_size(idx)
    memcpy(_tmp_bf_exp, 0, base, 0, 32)
    memcpy(_tmp_bf_exp, 32, salt, 0, lsalt)
    dump_uvarint_b_into(idx, _tmp_bf_exp, 32 + lsalt)
    crypto.keccak_hash_into(_tmp_bf_1, _tmp_bf_exp, final_size)
    crypto.hash_to_point_into(_tmp_pt_4, _tmp_bf_1)
    crypto.encodepoint_into(dst, _tmp_pt_4)
    return dst


#
# Key Vectors
#

SIZE_BOOL = 1
SIZE_INT = 8
SIZE_SC = 32
SIZE_PT = 32
SIZE_PT_FULL = 10*32*4
SIZE_SC_FULL = 9*32


def sizeof(x):
    try:
        return sys.getsizeof(x)
    except:
        return 0


def getcells(x):
    try:
        return sys.getcells(x)
    except:
        return tuple()


class SizeCounter:
    def __init__(self, real=False, do_track=True, do_trace=False):
        self.real = real
        self.do_track = do_track
        self.do_trace = do_trace
        self.track = set() if do_track else None
        self.trace = [] if do_trace else None
        self.acc = 0
        self._clos = lambda x: x*int(do_track)*int(do_trace)
        self._lambda = lambda x: 0

    def comp_size(self, v, name=None, real=False):
        if v is None:
            return 0

        real = self.real if self else real
        tp = type(v)
        iid = id(v)
        addc = True

        if self and self.do_track and not isinstance(v, (int, bool, float)):
            if iid in self.track:
                return 0
            else:
                self.track.add(iid)

        c = 0
        if tp in (KeyV, KeyVPowers, KeyVEval, KeyVPrecomp, KeyR0, KeyVPrngMask):
            c = v.getsize(real, name, sslot_sizes=self.slot_sizes)
        elif tp == type(_tmp_sc_1):
            c = SIZE_SC if not real else sizeof(v)
        elif tp == type(_tmp_pt_1):
            c = SIZE_PT if not real else sizeof(v)
        elif tp == int:
            c = SIZE_INT if not real else sizeof(v)
        elif tp == bool:
            c = 1 if not real else sizeof(v)
        elif tp == bytearray:
            c = len(v) if not real else sizeof(v)
        elif tp == bytes:
            c = len(v) if not real else sizeof(v)
        elif tp == str:
            c = len(v) if not real else sizeof(v)
        elif tp == memoryview:
            c = len(v) if not real else sizeof(v)
        elif tp == type(self._lambda):
            cc = 1 if not real else sizeof(1)
        elif tp == type(self._clos):
            cc = 1 if not real else sizeof(v)
            self.acc += cc
            c = sum([self.comp_size(x, "%s[%s, %s]" % (name, i, type(x))) for i, x in enumerate(getcells(v))]) + cc
            addc = False

        elif tp == list or tp == tuple:
            cc = 0 if not real else sizeof(v)
            self.acc += cc
            c = sum([self.comp_size(x, "%s[%s, %s]" % (name, i, type(x))) for i, x in enumerate(v)]) + cc
            addc = False

        else:
            print('Unknown type: ', name, ', v', v, ', tp', tp)
            return 0

        if addc:
            self.acc += c
        if self.do_trace:
            self.trace.append((name, c))
        return c

    def slot_sizes(self, obj, slots, real=False, name=""):
        if not slots or not obj:
            return 0
        return sum([self.comp_size(getattr(obj, x, None), '%s.%s' % (name, x)) for x in slots])

    def report(self):
        if not self.do_trace:
            return
        for x in self.trace:
            print(' .. %s : %s' % x)


def slot_sizes(obj, slots, real=False, name=""):
    return 0

def comp_size(v, name=None, real=False):
    return SizeCounter(real, False).comp_size(v, name)


class KeyVBase:
    """
    Base KeyVector object
    """

    __slots__ = ("current_idx", "size")

    def __init__(self, elems=64):
        self.current_idx = 0
        self.size = elems

    def idxize(self, idx):
        if idx < 0:
            idx = self.size + idx
        if idx >= self.size:
            raise IndexError("Index out of bounds: %s vs %s" % (idx, self.size))
        return idx

    def __getitem__(self, item):
        raise ValueError("Not supported")

    def __setitem__(self, key, value):
        raise ValueError("Not supported")

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def __len__(self):
        return self.size

    def to(self, idx, buff=None, offset=0):
        buff = _ensure_dst_key(buff)
        return memcpy(buff, offset, self[self.idxize(idx)], 0, 32)

    def read(self, idx, buff, offset=0):
        raise ValueError

    def slice(self, res, start, stop):
        for i in range(start, stop):
            res[i - start] = self[i]
        return res

    def slice_view(self, start, stop):
        return KeyVSliced(self, start, stop)

    def sdump(self):
        return None

    def sload(self, st):
        return None

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = 0  # super().getsize(real, name, sslot_sizes) if isinstance(super(), KeyVBase) else 0
        return p + 2 * SIZE_INT if not real else (p + sizeof(KeyVBaseNULL) + sslot_sizes(self, KeyVBase.__slots__, real, name))


KeyVBaseNULL = KeyVBase()


_CHBITS = const(5)
_CHSIZE = const(1 << _CHBITS)


class KeyV(KeyVBase):
    """
    KeyVector abstraction
    Constant precomputed buffers = bytes, frozen. Same operation as normal.

    Non-constant KeyVector is separated to _CHSIZE elements chunks to avoid problems with
    the heap fragmentation. In this it is more probable that the chunks are correctly
    allocated as smaller continuous memory is required. Chunk is assumed to
    have _CHSIZE elements at all times to minimize corner cases handling. BP require either
    multiple of _CHSIZE elements vectors or less than _CHSIZE.

    Some chunk-dependent cases are not implemented as they are currently not needed in the BP.
    """

    __slots__ = ("d", "mv", "const", "cur", "chunked")

    def __init__(self, elems=64, buffer=None, const=False, no_init=False, buffer_chunked=False):
        super().__init__(elems)
        self.d = None
        self.mv = None
        self.const = const
        self.cur = _ensure_dst_key()
        self.chunked = False
        if no_init:
            pass
        elif buffer:
            self.d = buffer  # can be immutable (bytes)
            self.size = len(buffer) // 32 if not buffer_chunked else elems
            self.chunked = buffer_chunked
        else:
            self._set_d(elems)

        if not no_init:
            self._set_mv()

    @staticmethod
    def chunk_size():
        return _CHSIZE

    def _set_d(self, elems):
        if elems > _CHSIZE and elems % _CHSIZE == 0:
            self.chunked = True
            gc.collect()
            self.d = [bytearray(32 * _CHSIZE) for _ in range(elems // _CHSIZE)]

        else:
            self.chunked = False
            gc.collect()
            self.d = bytearray(32 * elems)

    def _set_mv(self):
        if not self.chunked:
            self.mv = memoryview(self.d)

    def __getitem__(self, item):
        """
        Returns corresponding 32 byte array.
        Creates new memoryview on access.
        """
        if self.chunked:
            return self.to(item)
        item = self.idxize(item)
        return self.mv[item * 32 : (item + 1) * 32]

    def __setitem__(self, key, value):
        if self.chunked:
            raise ValueError("Not supported")  # not needed
        if self.const:
            raise ValueError("Constant KeyV")
        ck = self[key]
        for i in range(32):
            ck[i] = value[i]

    def to(self, idx, buff=None, offset=0):
        idx = self.idxize(idx)
        if self.chunked:
            memcpy(
                buff if buff else self.cur,
                offset,
                self.d[idx >> _CHBITS],
                (idx & (_CHSIZE - 1)) << 5,
                32,
            )
        else:
            memcpy(buff if buff else self.cur, offset, self.d, idx << 5, 32)
        return buff if buff else self.cur

    def read(self, idx, buff, offset=0):
        idx = self.idxize(idx)
        if self.chunked:
            memcpy(self.d[idx >> _CHBITS], (idx & (_CHSIZE - 1)) << 5, buff, offset, 32)
        else:
            memcpy(self.d, idx << 5, buff, offset, 32)

    def resize(self, nsize, chop=False, realloc=False):
        if self.size == nsize:
            return self

        if self.chunked and nsize <= _CHSIZE:
            self.chunked = False  # de-chunk
            if self.size > nsize and realloc:
                gc.collect()
                self.d = bytearray(self.d[0][: nsize << 5])
            elif self.size > nsize and not chop:
                gc.collect()
                self.d = self.d[0][: nsize << 5]
            else:
                gc.collect()
                self.d = bytearray(nsize << 5)

        elif self.chunked and self.size < nsize:
            if nsize % _CHSIZE != 0 or realloc or chop:
                raise ValueError("Unsupported")  # not needed
            for i in range((nsize - self.size) // _CHSIZE):
                self.d.append(bytearray(32 * _CHSIZE))

        elif self.chunked:
            if nsize % _CHSIZE != 0:
                raise ValueError("Unsupported")  # not needed
            for i in range((self.size - nsize) // _CHSIZE):
                self.d.pop()
            if realloc:
                for i in range(nsize // _CHSIZE):
                    self.d[i] = bytearray(self.d[i])

        else:
            if self.size > nsize and realloc:
                gc.collect()
                self.d = bytearray(self.d[: nsize << 5])
            elif self.size > nsize and not chop:
                gc.collect()
                self.d = self.d[: nsize << 5]
            else:
                gc.collect()
                self.d = bytearray(nsize << 5)

        self.size = nsize
        self._set_mv()

    def realloc(self, nsize, collect=False):
        self.d = None
        self.mv = None
        if collect:
            gc.collect()  # gc collect prev. allocation

        self._set_d(nsize)
        self.size = nsize
        self._set_mv()

    def realloc_init_from(self, nsize, src, offset=0, collect=False):
        if not isinstance(src, KeyV):
            raise ValueError("KeyV supported only")
        self.realloc(nsize, collect)

        if not self.chunked and not src.chunked:
            memcpy(self.d, 0, src.d, offset << 5, nsize << 5)

        elif self.chunked and not src.chunked or self.chunked and src.chunked:
            for i in range(nsize):
                self.read(i, src.to(i + offset))

        elif not self.chunked and src.chunked:
            for i in range(nsize >> _CHBITS):
                memcpy(
                    self.d,
                    i << 11,
                    src.d[i + (offset >> _CHBITS)],
                    (offset & (_CHSIZE - 1)) << 5 if i == 0 else 0,
                    nsize << 5 if i <= nsize >> _CHBITS else (nsize & _CHSIZE) << 5,
                )

    def sdump(self):
        utils.ensure(self.size <= const(1152921504606846976), "Size too big")
        return self.d, (self.size | (bool(self.chunked) << 60))  # packing saves 8B for boolean (self.chunked)

    def sload(self, st):
        self.d, s = st
        self.size = s &(~(1<<60))
        self.chunked = (s & (1<<60)) > 0
        self._set_mv()

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        if self.const:
            return (p + 2 + SIZE_SC + 2) if not real else (p + sizeof(self) + sslot_sizes(self, ("mv", "const", "cur", "chunked"), real, name))
        return (p + 2 + SIZE_SC + 2 + self.size * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, KeyV.__slots__, real, name))


class KeyVEval(KeyVBase):
    """
    KeyVector computed / evaluated on demand
    """

    __slots__ = ("fnc", "raw", "scalar", "buff")

    def __init__(self, elems=64, src=None, raw=False, scalar=True):
        super().__init__(elems)
        self.fnc = src
        self.raw = raw
        self.scalar = scalar
        self.buff = (
            _ensure_dst_key()
            if not raw
            else (crypto.new_scalar() if scalar else crypto.new_point())
        )

    def __getitem__(self, item):
        return self.fnc(self.idxize(item), self.buff)

    def to(self, idx, buff=None, offset=0):
        self.fnc(self.idxize(idx), self.buff)
        if self.raw:
            if offset != 0:
                raise ValueError("Not supported")
            if self.scalar and buff:
                return crypto.sc_copy(buff, self.buff)
            elif self.scalar:
                return self.buff
            else:
                raise ValueError("Not supported")
        else:
            memcpy(buff, offset, self.buff, 0, 32)
        return buff if buff else self.buff

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + 2 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVSized(KeyVBase):
    """
    Resized vector, wrapping possibly larger vector
    (e.g., precomputed, but has to have exact size for further computations)
    """

    __slots__ = ("wrapped",)

    def __init__(self, wrapped, new_size):
        super().__init__(new_size)
        self.wrapped = wrapped

    def __getitem__(self, item):
        return self.wrapped[self.idxize(item)]

    def __setitem__(self, key, value):
        self.wrapped[self.idxize(key)] = value

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 1) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVWrapped(KeyVBase):
    """
    Resized vector, wrapping possibly larger vector
    (e.g., precomputed, but has to have exact size for further computations)
    """

    __slots__ = ("wrapped",)

    def __init__(self, wrapped, new_size, raw=False, sc=True):
        super().__init__(new_size)
        self.wrapped = wrapped
        self.raw = raw
        self.sc = sc
        self.cur = bytearray(32) if not raw else (crypto.new_scalar() if sc else crypto.new_point())

    def __getitem__(self, item):
        return self.wrapped[self.idxize(item)]

    def __setitem__(self, key, value):
        self.wrapped[self.idxize(key)] = value

    def to(self, idx, buff=None, offset=0):
        buff = buff if buff else self.cur
        if self.raw:
            if self.sc:
                return crypto.sc_copy(self.cur, self[idx])
            else:
                raise ValueError()
        else:
            return memcpy(buff, offset, self[idx], 0, 32)

    def read(self, idx, buff, offset=0):
        if self.raw:
            if self.sc:
                return crypto.sc_copy(self.wrapped[self.idxize(idx)], buff)
            else:
                raise ValueError()
        else:
            return memcpy(self.wrapped[self.idxize(idx)], 0, buff, offset, 32)

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + 2 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVConst(KeyVBase):
    __slots__ = ("elem",)

    def __init__(self, size, elem, copy=True):
        super().__init__(size)
        self.elem = _init_key(elem) if copy else elem

    def __getitem__(self, item):
        return self.elem

    def to(self, idx, buff=None, offset=0):
        memcpy(buff, offset, self.elem, 0, 32)
        return buff if buff else self.elem

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVPrecomp(KeyVBase):
    """
    Vector with possibly large size and some precomputed prefix.
    Usable for Gi vector with precomputed usual sizes (i.e., 2 output transactions)
    but possible to compute further
    """

    __slots__ = ("precomp_prefix", "aux_comp_fnc", "buff")

    def __init__(self, size, precomp_prefix, aux_comp_fnc):
        super().__init__(size)
        self.precomp_prefix = precomp_prefix
        self.aux_comp_fnc = aux_comp_fnc
        self.buff = _ensure_dst_key()

    def __getitem__(self, item):
        item = self.idxize(item)
        if item < len(self.precomp_prefix):
            return self.precomp_prefix[item]
        return self.aux_comp_fnc(item, self.buff)

    def to(self, idx, buff=None, offset=0):
        item = self.idxize(idx)
        if item < len(self.precomp_prefix):
            return self.precomp_prefix.to(item, buff if buff else self.buff, offset)
        self.aux_comp_fnc(item, self.buff)
        memcpy(buff, offset, self.buff, 0, 32)
        return buff if buff else self.buff

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVSliced(KeyVBase):
    """
    Sliced in-memory vector version, remapping
    """

    __slots__ = ("wrapped", "offset")

    def __init__(self, src, start=0, stop=None):
        stop = stop if stop is not None else len(src)
        super().__init__(stop - start)
        self.wrapped = src
        self.offset = start

    def __getitem__(self, item):
        return self.wrapped[self.offset + self.idxize(item)]

    def __setitem__(self, key, value):
        self.wrapped[self.offset + self.idxize(key)] = value

    def resize(self, nsize, chop=False):
        raise ValueError("Not supported")

    def to(self, idx, buff=None, offset=0):
        return self.wrapped.to(self.offset + self.idxize(idx), buff, offset)

    def read(self, idx, buff, offset=0):
        return self.wrapped.read(self.offset + self.idxize(idx), buff, offset)

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVPowers(KeyVBase):
    """
    Vector of x^i. Allows only sequential access (no jumping). Resets on [0,1] access.
    """

    __slots__ = ("x", "raw", "cur", "last_idx")

    def __init__(self, size, x, raw=False, **kwargs):
        super().__init__(size)
        self.x = x if not raw else crypto.decodeint_into_noreduce(None, x)
        self.raw = raw
        self.cur = bytearray(32) if not raw else crypto.new_scalar()
        self.last_idx = 0

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        if item == 0:
            return (
                _copy_key(self.cur, _ONE)
                if not self.raw
                else crypto.decodeint_into_noreduce(self.cur, _ONE)
            )
        elif item == 1:
            return (
                _copy_key(self.cur, self.x)
                if not self.raw
                else crypto.sc_copy(self.cur, self.x)
            )
        elif item == prev:
            return self.cur
        elif item == prev + 1:
            return (
                _sc_mul(self.cur, self.cur, self.x)
                if not self.raw
                else crypto.sc_mul_into(self.cur, self.cur, self.x)
            )
        else:
            raise IndexError("Only linear scan allowed: %s, %s" % (prev, item))

    def reset(self):
        return self[0]

    def rewind(self, n):
        while n > 0:
            if not self.raw:
                _sc_mul(self.cur, self.cur, self.x)
            else:
                crypto.sc_mul_into(self.cur, self.cur, self.x)
            self.last_idx += 1
            n -= 1

    def set_state(self, idx, val):
        self.item = idx
        self.last_idx = idx
        if self.raw:
            return crypto.sc_copy(self.cur, val)
        else:
            return _copy_key(self.cur, val)

    def sdump(self):
        return self.cur, self.last_idx

    def sload(self, rec):
        self.cur, self.last_idx = rec

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + 2 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVPrngMask(KeyVBase):
    """
    Vector of random elements. Allows only sequential access (no jumping). Resets on [0,1] access.
    """

    __slots__ = ("raw", "sc", "cur", "seed", "prng", "allow_nonlinear", "last_idx")

    def __init__(self, size, seed, raw=False, allow_nonlinear=False, **kwargs):
        super().__init__(size)
        self.last_idx = 0
        self.raw = raw
        self.sc = crypto.new_scalar()
        self.cur = bytearray(32)
        self.seed = bytes(seed)
        self.prng = crypto.prng(seed)
        self.allow_nonlinear = allow_nonlinear

    def reset(self):
        self.prng.reset(self.seed)
        return self._next()

    def _next(self):
        self.prng.next(32, self.cur)
        crypto.decodeint_into(self.sc, self.cur)
        return self.sc if self.raw else crypto.encodeint_into(self.cur, self.sc)

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        if item == 0:
            return self.reset()
        elif item == prev:
            return self.cur if not self.raw else self.sc
        elif item == prev + 1:
            return self._next()
        else:
            if not self.allow_nonlinear:
                raise IndexError("Only linear scan allowed: %s, %s" % (prev, item))

            if item < prev:
                self.reset()
                prev = 0

            rev = 64 * (item - prev - 1)
            self.prng.rewind(rev)
            return self._next()

    def to(self, idx, buff=None, offset=0):
        if not buff:
            return self[idx]
        buff = _ensure_dst_key(buff)
        return memcpy(buff, offset, self[idx], 0, 32)

    def sdump(self):
        return self.last_idx, self.prng, self.cur

    def sload(self, st):
        self.last_idx, self.prng, self.cur = st
        crypto.decodeint_into(self.sc, self.cur)

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 3 + 4 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyR0(KeyVBase):
    """
    Vector r0. Allows only sequential access (no jumping). Resets on [0,1] access.
    zt_i = z^{2 + \floor{i/N}} 2^{i % N}
    r0_i = ((a_{Ri} + z) y^{i}) + zt_i

    Could be composed from smaller vectors, but RAW returns are required
    """

    __slots__ = (
        "N",
        "aR",
        "raw",
        "y",
        "yp",
        "z",
        "zt",
        "p2",
        "res",
        "cur",
        "last_idx",
    )

    def __init__(self, size, N, aR, y, z, raw=False, **kwargs):
        super().__init__(size)
        self.N = N
        self.aR = aR
        self.raw = raw
        self.y = crypto.decodeint_into_noreduce(None, y)
        self.yp = crypto.new_scalar()  # y^{i}
        self.z = crypto.decodeint_into_noreduce(None, z)
        self.zt = crypto.new_scalar()  # z^{2 + \floor{i/N}}
        self.p2 = crypto.new_scalar()  # 2^{i \% N}
        self.res = crypto.new_scalar()  # tmp_sc_1

        self.cur = bytearray(32) if not raw else None
        self.last_idx = 0
        self.reset()

    def reset(self):
        crypto.decodeint_into_noreduce(self.yp, _ONE)
        crypto.decodeint_into_noreduce(self.p2, _ONE)
        crypto.sc_mul_into(self.zt, self.z, self.z)

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        # Const init for eval
        if item == 0:  # Reset on first item access
            self.reset()

        elif item == prev + 1:
            crypto.sc_mul_into(self.yp, self.yp, self.y)  # ypow
            if item % self.N == 0:
                crypto.sc_mul_into(self.zt, self.zt, self.z)  # zt
                crypto.decodeint_into_noreduce(self.p2, _ONE)  # p2 reset
            else:
                crypto.decodeint_into_noreduce(self.res, _TWO)  # p2
                crypto.sc_mul_into(self.p2, self.p2, self.res)  # p2

        elif item == prev:  # No advancing
            pass

        else:
            raise IndexError("Only linear scan allowed")

        # Eval r0[i]
        if (
            item == 0 or item != prev
        ):  # if True not present, fails with cross dot product
            crypto.decodeint_into_noreduce(self.res, self.aR.to(item))  # aR[i]
            crypto.sc_add_into(self.res, self.res, self.z)  # aR[i] + z
            crypto.sc_mul_into(self.res, self.res, self.yp)  # (aR[i] + z) * y^i
            crypto.sc_muladd_into(
                self.res, self.zt, self.p2, self.res
            )  # (aR[i] + z) * y^i + z^{2 + \floor{i/N}} 2^{i \% N}

        if self.raw:
            return self.res

        crypto.encodeint_into(self.cur, self.res)
        return self.cur

    def to(self, idx, buff=None, offset=0):
        r = self[idx]
        if buff is None:
            return r
        return memcpy(buff, offset, r, 0, 32)

    def sdump(self):
        return self.yp, self.zt, self.p2, self.last_idx

    def sload(self, st):
        self.yp, self.zt, self.p2, self.last_idx = st

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 4 + 7 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


def _ensure_dst_keyvect(dst=None, size=None):
    if dst is None:
        dst = KeyV(elems=size)
        return dst
    if size is not None and size != len(dst):
        dst.resize(size)
    return dst


def _const_vector(val, elems=_BP_N, copy=True):
    return KeyVConst(elems, val, copy)


def _vector_sum_aA(dst, a, A, a_raw=None):
    """
    \sum_{i=0}^{|A|}  a_i A_i
    """
    dst = _ensure_dst_key(dst)
    crypto.identity_into(_tmp_pt_2)

    for i in range(len(a or a_raw)):
        if a:
            crypto.decodeint_into_noreduce(_tmp_sc_1, a.to(i))
        crypto.decodepoint_into(_tmp_pt_3, A.to(i))
        crypto.scalarmult_into(_tmp_pt_1, _tmp_pt_3, _tmp_sc_1)
        crypto.point_add_into(_tmp_pt_2, _tmp_pt_2, _tmp_pt_1)
        _gc_iter(i)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _vector_exponent_custom(A, B, a, b, dst=None, a_raw=None, b_raw=None):
    """
    \\sum_{i=0}^{|A|}  a_i A_i + b_i B_i
    """
    dst = _ensure_dst_key(dst)
    crypto.identity_into(_tmp_pt_2)

    for i in range(len(a or a_raw)):
        if a:
            crypto.decodeint_into_noreduce(_tmp_sc_1, a.to(i))
        crypto.decodepoint_into(_tmp_pt_3, A.to(i))
        if b:
            crypto.decodeint_into_noreduce(_tmp_sc_2, b.to(i))
        crypto.decodepoint_into(_tmp_pt_4, B.to(i))
        crypto.add_keys3_into(
            _tmp_pt_1,
            _tmp_sc_1 if a else a_raw.to(i),
            _tmp_pt_3,
            _tmp_sc_2 if b else b_raw.to(i),
            _tmp_pt_4,
        )
        crypto.point_add_into(_tmp_pt_2, _tmp_pt_2, _tmp_pt_1)
        _gc_iter(i)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _vector_powers(x, n, dst=None, dynamic=False, **kwargs):
    """
    r_i = x^i
    """
    if dynamic:
        return KeyVPowers(n, x, **kwargs)
    dst = _ensure_dst_keyvect(dst, n)
    if n == 0:
        return dst
    dst.read(0, _ONE)
    if n == 1:
        return dst
    dst.read(1, x)

    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.decodeint_into_noreduce(_tmp_sc_2, x)
    for i in range(2, n):
        crypto.sc_mul_into(_tmp_sc_1, _tmp_sc_1, _tmp_sc_2)
        crypto.encodeint_into(_tmp_bf_0, _tmp_sc_1)
        dst.read(i, _tmp_bf_0)
        _gc_iter(i)
    return dst


def _vector_power_sum(x, n, dst=None):
    """
    \\sum_{i=0}^{n-1} x^i
    """
    dst = _ensure_dst_key(dst)
    if n == 0:
        return _copy_key(dst, _ZERO)
    if n == 1:
        _copy_key(dst, _ONE)

    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.decodeint_into_noreduce(_tmp_sc_3, _ONE)
    crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_1)
    crypto.sc_copy(_tmp_sc_2, _tmp_sc_1)

    for i in range(2, n):
        crypto.sc_mul_into(_tmp_sc_2, _tmp_sc_2, _tmp_sc_1)
        crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_2)
        _gc_iter(i)

    return crypto.encodeint_into(dst, _tmp_sc_3)


def _inner_product(a, b, dst=None):
    """
    \\sum_{i=0}^{|a|} a_i b_i
    """
    if len(a) != len(b):
        raise ValueError("Incompatible sizes of a and b")
    dst = _ensure_dst_key(dst)
    crypto.sc_init_into(_tmp_sc_1, 0)

    for i in range(len(a)):
        crypto.decodeint_into_noreduce(_tmp_sc_2, a.to(i))
        crypto.decodeint_into_noreduce(_tmp_sc_3, b.to(i))
        crypto.sc_muladd_into(_tmp_sc_1, _tmp_sc_2, _tmp_sc_3, _tmp_sc_1)
        _gc_iter(i)

    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _hadamard_fold(v, a, b, into=None, into_offset=0, vR=None, vRoff=0):
    """
    Folds a curvepoint array using a two way scaled Hadamard product

    ln = len(v); h = ln // 2
    v_i = a v_i + b v_{h + i}
    """
    h = len(v) // 2
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    into = into if into else v

    for i in range(h):
        crypto.decodepoint_into(_tmp_pt_1, v.to(i))
        crypto.decodepoint_into(_tmp_pt_2, v.to(h + i) if not vR else vR.to(i + vRoff))
        crypto.add_keys3_into(_tmp_pt_3, _tmp_sc_1, _tmp_pt_1, _tmp_sc_2, _tmp_pt_2)
        crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_3)
        into.read(i + into_offset, _tmp_bf_0)
        _gc_iter(i)

    return into


def _hadamard_fold_linear(v, a, b, into=None, into_offset=0):
    """
    Folds a curvepoint array using a two way scaled Hadamard product.
    Iterates v linearly to support linear-scan evaluated vectors (on the fly)

    ln = len(v); h = ln // 2
    v_i = a v_i + b v_{h + i}
    """
    h = len(v) // 2
    into = into if into else v

    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    for i in range(h):
        crypto.decodepoint_into(_tmp_pt_1, v.to(i))
        crypto.scalarmult_into(_tmp_pt_1, _tmp_pt_1, _tmp_sc_1)
        crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_1)
        into.read(i + into_offset, _tmp_bf_0)
        _gc_iter(i)

    crypto.decodeint_into_noreduce(_tmp_sc_1, b)
    for i in range(h):
        crypto.decodepoint_into(_tmp_pt_1, v.to(i + h))
        crypto.scalarmult_into(_tmp_pt_1, _tmp_pt_1, _tmp_sc_1)
        crypto.decodepoint_into(_tmp_pt_2, into.to(i + into_offset))
        crypto.point_add_into(_tmp_pt_1, _tmp_pt_1, _tmp_pt_2)
        crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_1)
        into.read(i + into_offset, _tmp_bf_0)

        _gc_iter(i)
    return into


def _scalar_fold(v, a, b, into=None, into_offset=0):
    """
    ln = len(v); h = ln // 2
    v_i = a v_i + b v_{h + i}
    """
    h = len(v) // 2
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    into = into if into else v

    for i in range(h):
        crypto.decodeint_into_noreduce(_tmp_sc_3, v.to(i))
        crypto.decodeint_into_noreduce(_tmp_sc_4, v.to(h + i))
        crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_1)
        crypto.sc_mul_into(_tmp_sc_4, _tmp_sc_4, _tmp_sc_2)
        crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_4)
        crypto.encodeint_into(_tmp_bf_0, _tmp_sc_3)
        into.read(i + into_offset, _tmp_bf_0)
        _gc_iter(i)

    return into


def _cross_inner_product(l0, r0, l1, r1):
    """
    t1   = l0 . r1 + l1 . r0
    t2   = l1 . r1
    """
    sc_t1 = crypto.new_scalar()
    sc_t2 = crypto.new_scalar()
    tl = crypto.new_scalar()
    tr = crypto.new_scalar()

    for i in range(len(l0)):
        crypto.decodeint_into_noreduce(tl, l0.to(i))
        crypto.decodeint_into_noreduce(tr, r1.to(i))
        crypto.sc_muladd_into(sc_t1, tl, tr, sc_t1)

        crypto.decodeint_into_noreduce(tl, l1.to(i))
        crypto.sc_muladd_into(sc_t2, tl, tr, sc_t2)

        crypto.decodeint_into_noreduce(tr, r0.to(i))
        crypto.sc_muladd_into(sc_t1, tl, tr, sc_t1)

        _gc_iter(i)

    return crypto.encodeint(sc_t1), crypto.encodeint(sc_t2)


def _vector_gen(dst, size, op):
    dst = _ensure_dst_keyvect(dst, size)
    for i in range(size):
        dst.to(i, _tmp_bf_0)
        op(i, _tmp_bf_0)
        dst.read(i, _tmp_bf_0)
        _gc_iter(i)
    return dst


def _vector_dup(x, n, dst=None):
    dst = _ensure_dst_keyvect(dst, n)
    for i in range(n):
        dst[i] = x
        _gc_iter(i)
    return dst


def _hash_cache_mash(dst, hash_cache, *args):
    dst = _ensure_dst_key(dst)
    _hasher.reset()
    _hasher.update(hash_cache)

    for x in args:
        if x is None:
            break
        _hasher.update(x)
    _hasher.digest(dst)

    crypto.decodeint_into(_tmp_sc_1, dst)
    crypto.encodeint_into(hash_cache, _tmp_sc_1)
    _copy_key(dst, hash_cache)
    return dst


def _is_reduced(sc):
    return crypto.encodeint_into(_tmp_bf_0, crypto.decodeint_into(_tmp_sc_1, sc)) == sc


class MultiExpSequential:
    """
    MultiExp object similar to MultiExp array of [(scalar, point), ]
    MultiExp computes simply: res = \\sum_i scalar_i * point_i
    Straus / Pippenger algorithms are implemented in the original Monero C++ code for the speed
    but the memory cost is around 1 MB which is not affordable here in HW devices.

    Moreover, Monero needs speed for very fast verification for blockchain verification which is not
    priority in this use case.

    MultiExp holder with sequential evaluation
    """

    def __init__(self, size=None, points=None, point_fnc=None):
        self.current_idx = 0
        self.size = size if size else None
        self.points = points if points else []
        self.point_fnc = point_fnc
        if points and size is None:
            self.size = len(points) if points else 0
        else:
            self.size = 0

        self.acc = crypto.identity()
        self.tmp = _ensure_dst_key()

    def get_point(self, idx):
        return (
            self.point_fnc(idx, None) if idx >= len(self.points) else self.points[idx]
        )

    def add_pair(self, scalar, point):
        self._acc(scalar, point)

    def add_scalar(self, scalar):
        self._acc(scalar, self.get_point(self.current_idx))

    def _acc(self, scalar, point):
        crypto.decodeint_into_noreduce(_tmp_sc_1, scalar)
        crypto.decodepoint_into(_tmp_pt_2, point)
        crypto.scalarmult_into(_tmp_pt_3, _tmp_pt_2, _tmp_sc_1)
        crypto.point_add_into(self.acc, self.acc, _tmp_pt_3)
        self.current_idx += 1
        self.size += 1

    def eval(self, dst, GiHi=False):
        dst = _ensure_dst_key(dst)
        return crypto.encodepoint_into(dst, self.acc)


def _multiexp(dst=None, data=None, GiHi=False):
    return data.eval(dst, GiHi)


def _e_xL(sv, idx, d=None, is_a=True):
    j, i = idx // _BP_N, idx % _BP_N
    r = None
    if j >= len(sv):
        r = _ZERO if is_a else _MINUS_ONE
    elif sv[j][i // 8] & (1 << i % 8):
        r = _ONE if is_a else _ZERO
    else:
        r = _ZERO if is_a else _MINUS_ONE
    if d:
        return memcpy(d, 0, r, 0, 32)
    return r


class BulletProofBuilder:
    COUNT_STATE = False
    STATE_VARS = ('use_det_masks', 'proof_sec',
                  'do_blind', 'offload', 'batching', 'off_method', 'nprime_thresh', 'off2_thresh',
                  'MN', 'M', 'logMN', 'sv', 'gamma',
                  'A', 'S', 'T1', 'T2', 'tau1', 'tau2', 'taux', 'mu', 't', 'ts', 'x', 'x_ip', 'y', 'z', 'zc',  # V
                  'l0l1r0r1st', 'hash_cache', 'nprime', 'round', 'rho', 'alpha', 'Xbuffs',  # l, r
                  'w_round', 'winv', 'cL', 'cR', 'LcA', 'LcB', 'RcA', 'RcB',
                  'HprimeLRst', 'a', 'b',
                  'offstate', 'offpos', 'blinds')

    def __init__(self):
        self.use_det_masks = True
        self.proof_sec = None

        # BP_GI_PRE = get_exponent(Gi[i], _XMR_H, i * 2 + 1)
        self.Gprec = KeyV(buffer=crypto.tcry.BP_GI_PRE, const=True)
        # BP_HI_PRE = get_exponent(Hi[i], _XMR_H, i * 2)
        self.Hprec = KeyV(buffer=crypto.tcry.BP_HI_PRE, const=True)
        # BP_TWO_N = vector_powers(_TWO, _BP_N);
        self.twoN = None
        self.fnc_det_mask = None

        self.tmp_sc_1 = crypto.new_scalar()
        self.tmp_det_buff = bytearray(64 + 1 + 4)

        self.gc_fnc = gc.collect
        self.gc_trace = None

        self.do_blind = True
        self.offload = False

        # Number of elements per one vector to batch in one message.
        # Message can contain multiple vectors.
        self.batching = 32

        # 0 = full offload, no blinding, just encrypted dummy storage
        # 1 = offload dot product, blinding (cL, cR, LcA, LcB, RcA, RcB)
        # 2 = offload dot product + folding.
        self.off_method = 0

        # Threshold for in-memory operation per one vector.
        self.nprime_thresh = 64

        # Threshold for in-memory operation with off_method=2.
        # When reached, host sends vectors for the last folding to the host,
        # then host operates in-memory (requires off2_thresh <= nprime_thresh)
        self.off2_thresh = 32

        self.MN = 1
        self.M = 1
        self.logMN = 1
        self.Gprec2 = None
        self.Hprec2 = None

        # Values, blinding masks
        self.sv = None
        self.gamma = None

        # Bulletproof result / intermediate state
        self.V = None
        self.A = None
        self.S = None
        self.T1 = None
        self.T2 = None
        self.tau1 = None
        self.tau2 = None
        self.taux = None
        self.mu = None
        self.t = None
        self.ts = None
        self.x = None
        self.x_ip = None
        self.y = None
        self.z = None
        self.zc = None
        self.l = None
        self.r = None
        self.rho = None
        self.alpha = None
        self.l0l1r0r1st = None
        self.hash_cache = None
        self.Xbuffs = [None, None, None, None, None, None, None]  # Gprime, Hprime, aprime, bprime, L, R, V
        self.Xprime = [None, None, None, None]  # Gprime, Hprime, aprime, bprime KeyVs

        self.L = None
        self.R = None
        self.a = None
        self.b = None

        # Folding (w), incremental Lc, Rc computation
        self.nprime = None
        self.round = 0
        self.w_round = None
        self.winv = None
        self.cL = None
        self.cR = None
        self.LcA = None
        self.LcB = None
        self.RcA = None
        self.RcB = None
        self.tmp_k_1 = None

        # Folding in round 0
        self.yinvpowL = None
        self.yinvpowR = None
        self.tmp_pt = None
        self.HprimeL = None
        self.HprimeR = None
        self.HprimeLRst = None

        # Offloading state management
        self.offstate = 0
        self.offpos = 0

        # 2 blinds per vector, one for lo, one for hi. 2*i, 2*i+1. Ordering G, H, a, b
        # blinds[0] current blinds
        # blinds[1] new blinds
        self.blinds = [[], []]

    def _save_xbuff(self, idx, val):
        self.Xbuffs[idx] = val.sdump()

    def _load_xbuff(self, idx):
        if not self.Xbuffs[idx]:
            return None
        kv = KeyV(0, no_init=True)
        kv.sload(self.Xbuffs[idx])
        self.Xbuffs[idx] = None
        self.gc(1)
        return kv

    def dump_xbuffs(self):
        if self.round > 0 and self.Gprime:
            self._save_xbuff(0, self.Gprime)
            self.Gprime = None
        if self.round > 0 and self.Hprime:
            self._save_xbuff(1, self.Hprime)
            self.Hprime = None
        if self.aprime:
            self._save_xbuff(2, self.aprime)
            self.aprime = None
        if self.bprime:
            self._save_xbuff(3, self.bprime)
            self.bprime = None
        if self.L:
            self._save_xbuff(4, self.L)
            self.L = None
        if self.R:
            self._save_xbuff(5, self.R)
            self.R = None
        if self.V:
            self._save_xbuff(6, self.V)
            self.V = None

    def load_xbuffs(self):
        if self.round > 0:
            self.Gprime = self._load_xbuff(0)
            self.Hprime = self._load_xbuff(1)
        self.aprime = self._load_xbuff(2)
        self.bprime = self._load_xbuff(3)
        self.L = self._load_xbuff(4)
        self.R = self._load_xbuff(5)
        self.V = self._load_xbuff(6)

    def dump_state(self, state=None):
        state = state if state is not None else [None] * len(BulletProofBuilder.STATE_VARS)
        if len(state) != len(BulletProofBuilder.STATE_VARS):
            state += [None] * (len(BulletProofBuilder.STATE_VARS) - len(state))

        # Serialize KeyV to buffers
        self.dump_xbuffs()
        self.gc(1)

        if BulletProofBuilder.COUNT_STATE:
            ctr_i = SizeCounter(False, False, False)
            ctr_r = SizeCounter(True, True, True)

        for ix, x in enumerate(BulletProofBuilder.STATE_VARS):
            v = getattr(self, x, None)
            setattr(self, x, None)
            state[ix] = v
            if BulletProofBuilder.COUNT_STATE:
                ctr_i.comp_size(v, x)
                ctr_r.comp_size(v, x)
        self.gc(1)

        if BulletProofBuilder.COUNT_STATE:
            ctr_r.acc += sizeof(state)
            print('!!!!!!!!!!!!!!!!Dump finished: ', ctr_i.acc, ': r: ', ctr_r.acc)
            ctr_i.report()
            ctr_r.report()
            self.gc(1)
        return state

    def load_state(self, state):
        for ix, x in enumerate(BulletProofBuilder.STATE_VARS):
            if state[ix] is None:
                continue
            setattr(self, x, state[ix])
            state[ix] = None
        self.gc(1)

        # Unserialize KeyV buffers
        self.load_xbuffs()
        self.gc(1)

    @property
    def Gprime(self):
        return self.Xprime[0] if self.Xprime else None

    @property
    def Hprime(self):
        return self.Xprime[1] if self.Xprime else None

    @property
    def aprime(self):
        return self.Xprime[2] if self.Xprime else None

    @property
    def bprime(self):
        return self.Xprime[3] if self.Xprime else None

    @Gprime.setter
    def Gprime(self, val):
        self.Xprime[0] = val

    @Hprime.setter
    def Hprime(self, val):
        self.Xprime[1] = val

    @aprime.setter
    def aprime(self, val):
        self.Xprime[2] = val

    @bprime.setter
    def bprime(self, val):
        self.Xprime[3] = val

    def gc(self, *args):
        if self.gc_trace:
            self.gc_trace(*args)
        if self.gc_fnc:
            self.gc_fnc()

    def aX_vcts(self, sv, MN):
        aL = KeyVEval(MN, lambda i, d: _e_xL(sv, i, d, True))
        aR = KeyVEval(MN, lambda i, d: _e_xL(sv, i, d, False))
        return aL, aR

    def _det_mask_init(self):
        memcpy(self.tmp_det_buff, 0, self.proof_sec, 0, len(self.proof_sec))

    def _det_mask(self, i, is_sL=True, dst=None):
        dst = _ensure_dst_key(dst)
        if self.fnc_det_mask:
            return self.fnc_det_mask(i, is_sL, dst)
        self.tmp_det_buff[64] = int(is_sL)
        memcpy(self.tmp_det_buff, 65, _ZERO, 0, 4)
        dump_uvarint_b_into(i, self.tmp_det_buff, 65)
        crypto.hash_to_scalar_into(self.tmp_sc_1, self.tmp_det_buff)
        crypto.encodeint_into(dst, self.tmp_sc_1)
        return dst

    def _gprec_aux(self, size):
        return KeyVPrecomp(
            size, self.Gprec, lambda i, d: _get_exponent(d, _XMR_H, i * 2 + 1)
        )

    def _hprec_aux(self, size):
        return KeyVPrecomp(
            size, self.Hprec, lambda i, d: _get_exponent(d, _XMR_H, i * 2)
        )

    def _two_aux(self, size):
        # Simple recursive exponentiation from precomputed results
        if self.twoN is None:
            self.twoN = KeyV(buffer=crypto.tcry.BP_TWO_N, const=True)

        lx = len(self.twoN)

        def pow_two(i, d=None):
            if i < lx:
                return self.twoN[i]

            d = _ensure_dst_key(d)
            flr = i // 2

            lw = pow_two(flr)
            rw = pow_two(flr + 1 if flr != i / 2.0 else lw)
            return _sc_mul(d, lw, rw)

        return KeyVPrecomp(size, self.twoN, pow_two)

    def sL_vct(self, ln=_BP_N):
        return (
            KeyVPrngMask(ln, _ZERO) #crypto.random_bytes(32))
            # KeyVEval(ln, lambda i, dst: self._det_mask(i, True, dst))
            if self.use_det_masks
            else self.sX_gen(ln)
        )

    def sR_vct(self, ln=_BP_N):
        return (
            KeyVPrngMask(ln, _ONE) #crypto.random_bytes(32))
            # KeyVEval(ln, lambda i, dst: self._det_mask(i, False, dst))
            if self.use_det_masks
            else self.sX_gen(ln)
        )

    def sX_gen(self, ln=_BP_N):
        gc.collect()
        buff = bytearray(ln * 32)
        buff_mv = memoryview(buff)
        sc = crypto.new_scalar()
        for i in range(ln):
            buff0 = PRNG.next(32, bytearray(32))
            crypto.decodeint_into(sc, buff0)
            crypto.random_scalar(sc)
            crypto.encodeint_into(buff_mv[i * 32 : (i + 1) * 32], sc)
            _gc_iter(i)
        return KeyV(buffer=buff)

    def vector_exponent(self, a, b, dst=None, a_raw=None, b_raw=None):
        return _vector_exponent_custom(self.Gprec, self.Hprec, a, b, dst, a_raw, b_raw)

    def prove(self, sv, gamma):
        return self.prove_batch([sv], [gamma])

    def _comp_m(self, ln):
        M, logM = 1, 0
        while M <= _BP_M and M < ln:
            logM += 1
            M = 1 << logM
        MN = M * _BP_N
        return M, logM, MN

    def _comp_V(self, sv, gamma):
        V = _ensure_dst_keyvect(None, len(sv))
        for i in range(len(sv)):
            _add_keys2(_tmp_bf_0, gamma[i], sv[i], _XMR_H)
            _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
            V.read(i, _tmp_bf_0)
        return V

    def prove_setup(self, sv, gamma):
        utils.ensure(len(sv) == len(gamma), "|sv| != |gamma|")
        utils.ensure(len(sv) > 0, "sv empty")

        self.proof_sec = b"\x00"*32  #crypto.random_bytes(64)
        self._det_mask_init()
        gc.collect()
        self.sv = [crypto.encodeint(x) for x in sv]
        gamma = [crypto.encodeint(x) for x in gamma]

        M, logM, MN = self._comp_m(len(self.sv))
        V = self._comp_V(self.sv, gamma)
        aL, aR = self.aX_vcts(self.sv, MN)
        return M, logM, aL, aR, V, gamma

    def prove_batch(self, sv, gamma):
        M, logM, aL, aR, V, gamma = self.prove_setup(sv, gamma)
        hash_cache = _ensure_dst_key()
        while True:
            self.gc(10)
            r = self._prove_batch_main(
                V, gamma, aL, aR, hash_cache, logM, _BP_LOG_N, M, _BP_N
            )
            if r[0]:
                break
        return r[1]

    def prove_batch_off(self, sv, gamma):
        M, logM, aL, aR, V, gamma = self.prove_setup(sv, gamma)
        hash_cache = _ensure_dst_key()

        logMN = logM + _BP_LOG_N
        MN = M * _BP_N
        _hash_vct_to_scalar(hash_cache, V)

        # Extended precomputed GiHi
        Gprec = self._gprec_aux(MN)
        Hprec = self._hprec_aux(MN)
        self.offload = True
        return self._prove_phase1(
            _BP_N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec
        )

    def prove_batch_off_step(self, buffers=None):
        if self.offstate == 0:
            return self._phase1_lr()
        elif self.offstate == 1:
            return self._phase1_post()
        elif self.offstate == 2:
            return self._phase2_loop_offdot(buffers)
        elif self.offstate in [3, 4, 5, 6]:
            return self._phase2_loop_fold(buffers)
        elif self.offstate in [20, 21, 22, 23, 24, 25]:
            return self._phase2_loop0_clcr(buffers)
        elif self.offstate == 10:
            return self._phase2_loop_full()
        elif self.offstate == 12:
            return self._phase2_final()
        else:
            raise ValueError('Internal state error')

    def _prove_batch_main(self, V, gamma, aL, aR, hash_cache, logM, logN, M, N):
        logMN = logM + logN
        MN = M * N
        _hash_vct_to_scalar(hash_cache, V)

        # Extended precomputed GiHi
        Gprec = self._gprec_aux(MN)
        Hprec = self._hprec_aux(MN)

        # PHASE 1
        self._prove_phase1(
            N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec
        )

        # PHASE 2
        L, R, a, b = self._prove_loop(
            MN, logMN, self.l, self.r, self.y, self.x_ip, self.hash_cache, Gprec, Hprec
        )

        from apps.monero.xmr.serialize_messages.tx_rsig_bulletproof import Bulletproof

        return (
            1,
            Bulletproof(
                V=self.V, A=self.A, S=self.S, T1=self.T1, T2=self.T2, taux=self.taux, mu=self.mu,
                L=L, R=R, a=a, b=b, t=self.t
            ),
        )

    def _comp_l0l1r0r1(self, MN, aL, aR, sL, sR, y, z, zc, l0l1r0r1st=None):
        # Polynomial construction by coefficients
        # l0 = aL - z           r0   = ((aR + z) . ypow) + zt
        # l1 = sL               r1   =   sR      . ypow
        l0 = KeyVEval(MN, lambda i, d: _sc_sub(d, aL.to(i), None, None, zc))
        l1 = sL
        self.gc(13)

        # This computes the ugly sum/concatenation from PAPER LINE 65
        # r0_i = ((a_{Ri} + z) y^{i}) + zt_i
        # r1_i = s_{Ri} y^{i}
        r0 = KeyR0(MN, _BP_N, aR, y, z)
        ypow = KeyVPowers(MN, y, raw=True)
        r1 = KeyVEval(MN, lambda i, d: _sc_mul(d, sR.to(i), None, None, ypow[i]))

        if l0l1r0r1st:
            sL.sload(l0l1r0r1st[0])
            sR.sload(l0l1r0r1st[1])
            r0.sload(l0l1r0r1st[2])
            ypow.sload(l0l1r0r1st[3])
        return l0, l1, r0, r1, ypow

    def _sdump_l0l1r0r1(self, l1, sR, r0, ypow):
        return l1.sdump(), sR.sdump(), r0.sdump(), ypow.sdump()

    def _prove_phase1(self, N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec):
        self.MN = M * N
        self.M = M
        self.logMN = logMN
        self.V = V
        self.gamma = gamma
        self.hash_cache = hash_cache
        self.Gprec2, self.Hprec2 = Gprec, Hprec

        # PAPER LINES 38-39, compute A = 8^{-1} ( \alpha G + \sum_{i=0}^{MN-1} a_{L,i} \Gi_i + a_{R,i} \Hi_i)
        self.alpha = _sc_gen()
        self.A = _ensure_dst_key()
        _vector_exponent_custom(Gprec, Hprec, aL, aR, self.A)
        _add_keys(self.A, self.A, _scalarmult_base(_tmp_bf_1, self.alpha))
        _scalarmult_key(self.A, self.A, _INV_EIGHT)
        self.gc(11)

        # PAPER LINES 40-42, compute S =  8^{-1} ( \rho G + \sum_{i=0}^{MN-1} s_{L,i} \Gi_i + s_{R,i} \Hi_i)
        sL = self.sL_vct(self.MN)
        sR = self.sR_vct(self.MN)
        self.rho = _sc_gen()
        self.S = _ensure_dst_key()
        _vector_exponent_custom(Gprec, Hprec, sL, sR, self.S)
        _add_keys(self.S, self.S, _scalarmult_base(_tmp_bf_1, self.rho))
        _scalarmult_key(self.S, self.S, _INV_EIGHT)
        self.gc(12)

        # PAPER LINES 43-45
        self.y = _ensure_dst_key()
        _hash_cache_mash(self.y, self.hash_cache, self.A, self.S)
        if self.y == _ZERO:
            return (0,)

        self.z = _ensure_dst_key()
        _hash_to_scalar(self.hash_cache, self.y)
        _copy_key(self.z, self.hash_cache)
        self.zc = crypto.decodeint_into_noreduce(None, self.z)
        if self.z == _ZERO:
            return (0,)

        # Polynomial construction by coefficients
        l0, l1, r0, r1, ypow = self._comp_l0l1r0r1(self.MN, aL, aR, sL, sR, self.y, self.z, self.zc)
        del (aL, aR, sL, sR, ypow)
        self.gc(14)

        # Evaluate per index
        #  - $t_1 = l_0 . r_1 + l_1 . r0$
        #  - $t_2 = l_1 . r_1$
        #  - compute then T1, T2, x
        t1, t2 = _cross_inner_product(l0, r0, l1, r1)

        # PAPER LINES 47-48, Compute: T1, T2
        # T1 = 8^{-1} (\tau_1G + t_1H )
        # T2 = 8^{-1} (\tau_2G + t_2H )
        self.tau1, self.tau2 = _sc_gen(), _sc_gen()
        self.T1, self.T2 = _ensure_dst_key(), _ensure_dst_key()

        _add_keys2(self.T1, self.tau1, t1, _XMR_H)
        _scalarmult_key(self.T1, self.T1, _INV_EIGHT)

        _add_keys2(self.T2, self.tau2, t2, _XMR_H)
        _scalarmult_key(self.T2, self.T2, _INV_EIGHT)
        del (t1, t2)
        self.gc(16)

        # PAPER LINES 49-51, compute x
        self.x = _ensure_dst_key()
        _hash_cache_mash(self.x, self.hash_cache, self.z, self.T1, self.T2)
        if self.x == _ZERO:
            return (0,)

        if not self.offload:
            return self._phase1_fulllr(l0, l1, r0, r1)

        # Offloading code
        del(l0, l1, r0, r1)
        self.gc(17)

        self.ts = crypto.new_scalar()
        self._prove_new_blinds()
        self.offstate = 0
        self.offpos = 0
        return self._phase1_lr()

    def _phase1_fulllr(self, l0, l1, r0, r1):
        # Second pass, compute l, r
        # Offloaded version does this incrementally and produces l, r outs in chunks
        # Message offloaded sends blinded vectors with random constants.
        #  - $l_i = l_{0,i} + xl_{1,i}
        #  - $r_i = r_{0,i} + xr_{1,i}
        #  - $t   = l . r$
        self.l = _ensure_dst_keyvect(None, self.MN)
        self.r = _ensure_dst_keyvect(None, self.MN)
        ts = crypto.new_scalar()
        for i in range(self.MN):
            _sc_muladd(_tmp_bf_0, self.x, l1.to(i), l0.to(i))
            self.l.read(i, _tmp_bf_0)

            _sc_muladd(_tmp_bf_1, self.x, r1.to(i), r0.to(i))
            self.r.read(i, _tmp_bf_1)

            _sc_muladd(ts, _tmp_bf_0, _tmp_bf_1, None, c_raw=ts, raw=True)

        self.t = crypto.encodeint(ts)
        del (l0, l1, r0, r1, ts)
        self.gc(17)

        return self._phase1_post()

    def _phase1_lr(self):
        """
        Computes l, r vectors per chunks
        """
        print('Phase1_lr, state: %s, off: %s, MN: %s' % (self.offstate, self.offpos, self.MN))
        self.gc(2)
        l = KeyV(self.batching)
        self.gc(3)
        r = KeyV(self.batching)
        self.gc(4)

        # Reconstruct l0, l1, r0, r1 from the saved state
        aL, aR = self.aX_vcts(self.sv, self.MN)
        sL, sR = self.sL_vct(self.MN), self.sR_vct(self.MN)
        l0, l1, r0, r1, ypow = self._comp_l0l1r0r1(self.MN, aL, aR, sL, sR,
                                                   self.y, self.z, self.zc, self.l0l1r0r1st)
        self.l0l1r0r1st = None
        del (aL, aR, sL)
        self.gc(14)

        for i in range(self.offpos, self.offpos + self.batching):
            bloff = int(i >= (self.MN >> 1))
            _sc_muladd(_tmp_bf_0, self.x, l1.to(i), l0.to(i))
            _sc_muladd(_tmp_bf_1, self.x, r1.to(i), r0.to(i))
            _sc_muladd(self.ts, _tmp_bf_0, _tmp_bf_1, None, c_raw=self.ts, raw=True)
            _sc_mul(_tmp_bf_0, _tmp_bf_0, None, b_raw=self.blinds[0][4+bloff])  # blinding a
            _sc_mul(_tmp_bf_1, _tmp_bf_1, None, b_raw=self.blinds[0][6+bloff])  # blinding b
            l.read(i - self.offpos, _tmp_bf_0)
            r.read(i - self.offpos, _tmp_bf_1)
        del(l0, r1)
        self.gc(5)

        self.offstate = 0
        self.offpos += self.batching
        if self.offpos >= self.MN:
            self.t = crypto.encodeint(self.ts)
            del(self.ts, self.l0l1r0r1st)
            print('Moving to next state')
            self.offstate = 1
            self.offpos = 0

        else:
            self.l0l1r0r1st = self._sdump_l0l1r0r1(l1, sR, r0, ypow)

        ld, rd = l.d, r.d
        del(l1, r0, ypow, sR, l, r)
        self.gc(6)
        return ld, rd

    def _phase1_post(self):
        """
        Part after l, r, t are computed.
        Offstate = 1
        """
        print('phase1_post, state: %s, off: %s' % (self.offstate, self.offpos))

        # PAPER LINES 52-53, Compute \tau_x
        self.taux = _ensure_dst_key()
        _sc_mul(self.taux, self.tau1, self.x)
        _sc_mul(_tmp_bf_0, self.x, self.x)
        _sc_muladd(self.taux, self.tau2, _tmp_bf_0, self.taux)
        del (self.tau1, self.tau2)
        self.gc(10)

        zpow = crypto.sc_mul_into(None, self.zc, self.zc)
        for j in range(1, len(self.V) + 1):
            _sc_muladd(self.taux, None, self.gamma[j - 1], self.taux, a_raw=zpow)
            crypto.sc_mul_into(zpow, zpow, self.zc)
        self.sv = None
        self.gamma = None
        del (self.zc, zpow)
        self.gc(18)

        self.mu = _ensure_dst_key()
        _sc_muladd(self.mu, self.x, self.rho, self.alpha)
        del (self.rho, self.alpha)
        self.gc(19)

        # PAPER LINES 32-33
        self.x_ip = _hash_cache_mash(None, self.hash_cache, self.x, self.taux, self.mu, self.t)
        if self.x_ip == _ZERO:
            return 0, None

        # prepare for looping
        self.offstate = 20 if self.off_method == 0 else 2
        self.offpos = 0
        self.round = 0
        self.nprime = self.MN >> 1
        print('MN: %s, nprime: %s' % (self.MN, self.nprime))
        self.L = _ensure_dst_keyvect(None, self.logMN)
        self.R = _ensure_dst_keyvect(None, self.logMN)
        self.gc(20)

        if self.l is None:
            self.l = tuple()
            self.r = self.l

        return self.y,

    def _new_blinds(self, ix):
        if self.blinds[ix] is None or len(self.blinds[ix]) != 8 or self.blinds[ix][0] is None:
            self.blinds[ix] = [(crypto.random_scalar() if self.do_blind else crypto.sc_init(1)) for _ in range(8)]
        else:
            for i in range(8):
                if self.do_blind:
                    crypto.random_scalar(self.blinds[ix][i])
                else:
                    crypto.sc_init_into(self.blinds[ix][i], 1)

    def _swap_blinds(self):
        self.blinds[0], self.blinds[1] = self.blinds[1], self.blinds[0]

    def _prove_new_blinds(self):
        self._new_blinds(0)

    def _prove_new_blindsN(self):
        self._new_blinds(1)

    def _phase2_loop0_clcr(self, buffers):
        """
        Loop0 for offloaded operation.
        Caller passes a[0..nprime], b[nprime..np2] in chunks
        1 sub phase: a0, b1, G1, H0   - computes cL, Lc; state = 20
        2 sub phase: a1, b0, G0, H1   - computes cR, Rc; state = 21
        state 22, 23 = folding; G, H from the memory
        state 24, 25 = folding a, b; maps to state 5, 6
        """
        print('phase2_loop0_clcr, state: %s, off: %s, round: %s, nprime: %s' % (self.offstate, self.offpos, self.round, self.nprime))
        if self.round == 0 and (self.Gprime is None or self.Hprime is None or self.HprimeL is None):
            self._phase2_loop_body_r0init()

        if self.cL is None or (self.offstate == 20 and self.offpos == 0):
            self.cL = _ensure_dst_key()
            self.cR = _ensure_dst_key()
            self.winv = _ensure_dst_key()
            self.w_round = _ensure_dst_key()

        if self.LcA is None or (self.offstate == 20 and self.offpos == 0):
            crypto.identity_into(_tmp_pt_1)
            self.LcA = bytearray(crypto.encodepoint(_tmp_pt_1))
            self.LcB = bytearray(crypto.encodepoint(_tmp_pt_1))
            self.RcA = bytearray(crypto.encodepoint(_tmp_pt_1))
            self.RcB = bytearray(crypto.encodepoint(_tmp_pt_1))

        a, b = KeyV(self.batching, buffers[0]), KeyV(self.batching, buffers[1])
        G, H = None, None
        if self.round == 0:
            if self.offstate == 20:
                H = KeyVSliced(self.Hprime, self.offpos, min(self.offpos + self.batching, self.nprime))
                G = KeyVSliced(self.Gprime, self.nprime + self.offpos, self.nprime + min(self.offpos + self.batching, 2 * self.nprime))
            else:
                G = KeyVSliced(self.Gprime, self.offpos, min(self.offpos + self.batching, self.nprime))
                H = KeyVSliced(self.Hprime, self.nprime + self.offpos, self.nprime + min(self.offpos + self.batching, 2 * self.nprime))
        else:
            G, H = KeyV(self.batching, buffers[2]), KeyV(self.batching, buffers[3])

        cX = self.cL if self.offstate == 20 else self.cR
        XcA = self.LcA if self.offstate == 20 else self.RcA
        XcB = self.LcB if self.offstate == 20 else self.RcB
        tmp = _ensure_dst_key()
        self.gc(2)

        for i in range(len(a)):
            _sc_muladd(cX, a.to(i), b.to(i), cX)  # cX dot product

            _scalarmult_key(tmp, G.to(i), a.to(i))  # XcA scalarmult
            _add_keys(XcA, XcA, tmp)

            _scalarmult_key(tmp, H.to(i), b.to(i))  # XcA scalarmult
            _add_keys(XcB, XcB, tmp)

        self.gc(10)
        self.offpos += min(len(a), self.batching)
        if self.offpos >= self.nprime:# * 2:
            # Unblinding vectors with half-blinded masks
            # Ordering: G,  H,  a,  b,  (01, 23, 45, 67)
            # State 20: G1, H0, a0, b1; 1, 2, 4, 7
            # State 21: G0, H1, a1, b0; 0, 3, 5, 6
            blidx = (1, 2, 4, 7) if self.offstate == 20 else (0, 3, 5, 6)
            cbl = [self.blinds[0][x] for x in blidx]

            # unblind cX
            _sc_mul(tmp, a_raw=cbl[2], b_raw=cbl[3])
            _invert(tmp, tmp)
            _sc_mul(cX, cX, tmp)

            # unblind XcA
            _sc_mul(tmp, a_raw=cbl[2], b_raw=cbl[0] if self.round > 0 else crypto.decodeint(_ONE))
            _invert(tmp, tmp)
            _scalarmult_key(XcA, XcA, tmp)

            # unblind XcB
            _sc_mul(tmp, a_raw=cbl[3], b_raw=cbl[1] if self.round > 0 else crypto.decodeint(_ONE))
            _invert(tmp, tmp)
            _scalarmult_key(XcB, XcB, tmp)
            self.gc(11)

            if self.offstate == 20:  # Finish Lc
                # print('x_ip: ', ubinascii.hexlify(self.x_ip))
                _eprint('r: %s, cL ' % self.round, ubinascii.hexlify(self.cL))
                _add_keys(_tmp_bf_0, self.LcA, self.LcB)
                _sc_mul(tmp, self.cL, self.x_ip)
                _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, tmp))
                _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
                self.L.read(self.round, _tmp_bf_0)
                _eprint('r: %s, Lc ' % self.round, ubinascii.hexlify(self.L.to(self.round)))
                self.gc(12)

            elif self.offstate == 21:  # finish Rc, w
                # print('x_ip: ', ubinascii.hexlify(self.x_ip))
                _eprint('r: %s, cR ' % self.round, ubinascii.hexlify(self.cR))
                _add_keys(_tmp_bf_0, self.RcA, self.RcB)
                _sc_mul(tmp, self.cR, self.x_ip)
                _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, tmp))
                _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
                self.R.read(self.round, _tmp_bf_0)
                _eprint('r: %s, Rc ' % self.round, ubinascii.hexlify(self.R.to(self.round)))
                self.gc(13)

                # PAPER LINES 21-22
                _hash_cache_mash(self.w_round, self.hash_cache, self.L.to(self.round), self.R.to(self.round))
                if self.w_round == _ZERO:
                    return (0,)

                # PAPER LINES 24-25, fold {G~, H~}
                _invert(self.winv, self.w_round)
                self.gc(26)
                _eprint('r: %s, w0 ' % self.round, ubinascii.hexlify(self.w_round))
                _eprint('r: %s, wi ' % self.round, ubinascii.hexlify(self.winv))

                # New blinding factors to use for newly folded vectors
                self._prove_new_blindsN()
                self.gc(14)

            else:
                raise ValueError('Invalid state: %s' % self.offstate)

            self.offpos = 0
            self.offstate += 1
            print('Moved to state ', self.offstate)

        self.gc(15)
        if self.round == 0:
            self._phase2_loop_body_r0dump()

        # In the round0 we do Trezor folding anyway due to G, H being only on the Trezor
        # Optimization: aprime, bprime could be computed on the Host
        if self.offstate >= 22:
            print('Move to state 3 (folding)')
            self.offstate = 3

            if self.off_method == 2:
                print('fold offload')
                return self._compute_folding_consts()

    def _phase2_loop_offdot(self, buffers):
        """
        Comp computes dot products, blinded, de-blind
        Computes cL, cR, Lc, Rc, w
        Offstate = 2
        """
        print('_phase2_loop_offdot, state: %s, off: %s, round: %s, nprime: %s' % (self.offstate, self.offpos, self.round, self.nprime))
        if not self.w_round:
            self.winv = _ensure_dst_key()
            self.w_round = _ensure_dst_key()

        if self.Gprime is None and self.round == 0:
            self._phase2_loop_body_r0init()

        self.gc(2)
        tmp = _ensure_dst_key()
        self.tmp_k_1 = _ensure_dst_key()

        cL, cR = buffers[0], buffers[1]
        LcA, LcB = buffers[2], buffers[3]
        RcA, RcB = buffers[4], buffers[5]

        # blind masks: G0 G1 H0 H1 a0 a1 b0 b1
        # blind masks: 0  1  2  3  4  5  6  7
        ibls = [_invert(None, crypto.encodeint(x)) for x in self.blinds[0]]

        cL = _sc_mul(cL, cL, ibls[4])  # unblind a0
        cL = _sc_mul(cL, cL, ibls[7])  # unblind b1

        cR = _sc_mul(cR, cR, ibls[5])  # unblind a1
        cR = _sc_mul(cR, cR, ibls[6])  # unblind b0
        self.gc(10)

        _eprint('r:', self.round, 'cL', _ehexlify(cL))
        _eprint('r:', self.round, 'cR', _ehexlify(cR))

        # products from round 0 are not blinded as Gprime and Hprime are protocol constants
        if self.round == 0:
            ibls[0], ibls[1], ibls[2], ibls[3] = _ONE, _ONE, _ONE, _ONE

        LcA = _scalarmult_key(LcA, LcA, _sc_mul(None, ibls[4], ibls[1]))  # a0 G1
        RcA = _scalarmult_key(RcA, RcA, _sc_mul(None, ibls[5], ibls[0]))  # a1 G0

        LcB = _scalarmult_key(LcB, LcB, _sc_mul(None, ibls[7], ibls[2]))  # b1 H0
        RcB = _scalarmult_key(RcB, RcB, _sc_mul(None, ibls[6], ibls[3]))  # b0 H1
        del(ibls)
        self.gc(11)

        _add_keys(LcA, LcA, LcB)
        _sc_mul(tmp, cL, self.x_ip)
        _add_keys(LcA, LcA, _scalarmultH(self.tmp_k_1, tmp))
        _scalarmult_key(LcA, LcA, _INV_EIGHT)
        self.L.read(self.round, LcA)
        del(cL, LcA, LcB)
        self.gc(12)

        _add_keys(RcA, RcA, RcB)
        _sc_mul(tmp, cR, self.x_ip)
        _add_keys(RcA, RcA, _scalarmultH(self.tmp_k_1, tmp))
        _scalarmult_key(RcA, RcA, _INV_EIGHT)
        self.R.read(self.round, RcA)
        del(cR, RcA, RcB, tmp)
        self.gc(13)

        _eprint('r:', self.round, 'Lc', _ehexlify(self.L.to(self.round)))
        _eprint('r:', self.round, 'Rc', _ehexlify(self.R.to(self.round)))

        # PAPER LINES 21-22
        _hash_cache_mash(self.w_round, self.hash_cache, self.L.to(self.round), self.R.to(self.round))
        if self.w_round == _ZERO:
            return (0,)

        # PAPER LINES 24-25, fold {G~, H~}
        _invert(self.winv, self.w_round)
        self.gc(14)

        _eprint('r:', self.round, 'w0', _ehexlify(self.w_round))
        _eprint('r:', self.round, 'w1', _ehexlify(self.winv))

        # New blinding factors to use for newly folded vectors
        self._prove_new_blindsN()
        self.offstate, self.offpos = 3, 0
        self.gc(15)

        # Backup state if needed
        if self.round == 0:
            self._phase2_loop_body_r0dump()

        # If the first round of the ofdot, we cannot do in
        if self.off_method >= 1 and self.round == 0:
            print('Fold now')
            tconst = self._compute_folding_consts() if self.off_method >= 2 else None
            return tconst

        # When offloading also the folding - return blinding constants
        if self.off_method == 2 and self.nprime <= self.off2_thresh:
            print('Off2, fold anyway - threshold reached')
            return

        # Offload the folding - compute constants
        if self.off_method == 2:
            print('fold offload')
            tconst = self._compute_folding_consts()

            # State 20 - clcr, dot products by the host
            self.offstate = 2
            self.nprime >>= 1
            self.round += 1
            self._swap_blinds()
            if self.round == 1:
                self._phase2_loop_body_r0del()
            self.Gprime = None
            self.Hprime = None
            self.aprime = None
            self.bprime = None
            return tconst

    def _compute_folding_consts(self):
        """
        Computes offloaded folding constants
        """
        # Constatns: 4 per vector.
        # Example, folding of the Gprime:
        # Gp_{LO, i} = m_0 bl0^{-1} w^{-1} G_i   +   m_0 bl1^{-1} w G_{i+h}, i \in [0,        nprime/2]
        # Gp_{HI, i} = m_1 bl0^{-1} w^{-1} G_i   +   m_1 bl1^{-1} w G_{i+h}, i \in [nprime/2, nprime]
        # w constants: G H a b: -1 1 1 -1
        w0 = crypto.decodeint_into_noreduce(self.w_round)
        wi = crypto.sc_inv_into(None, w0)
        blinvs = [crypto.sc_inv_into(None, x) for x in self.blinds[0]]
        tconst = [_ensure_dst_key() for _ in range(4*4)]
        for i in range(16):
            mi = self.blinds[1][i // 2]
            bi = blinvs[2 * (i // 4) + (i % 2)]
            x0, x1 = (wi, w0) if i // 4 in (0, 3) else (w0, wi)
            xi = x0 if i % 2 == 0 else x1

            crypto.sc_mul_into(_tmp_sc_1, mi, bi)
            crypto.sc_mul_into(_tmp_sc_1, _tmp_sc_1, xi)
            crypto.encodeint_into(tconst[i], _tmp_sc_1)
        del(blinvs, w0, wi)
        self.gc(22)
        return tconst

    def _phase2_loop_fold(self, buffers):
        """
        Computes folding per partes
        States: 3, 4, 5, 6
        """
        print('phase2_loop_fold, state: %s, off: %s, round: %s, nprime: %s, btch: %s' % (self.offstate, self.offpos, self.round, self.nprime, self.batching))
        self.gc(2)

        # Input buffer processing.
        # The first round has in-memory G, H buffers
        lo, hi = None, None
        tgt = min(self.batching, self.nprime)
        if self.round == 0 and self.offstate in (3, 4):
            if self.Gprime is None or self.HprimeL is None:
                self._phase2_loop_body_r0init()

            if self.offpos == 0 and self.offstate == 4:
                self.yinvpowR.reset()
                self.yinvpowR.rewind(self.nprime)

            if self.offstate == 3:
                lo = KeyVSliced(self.Gprime, self.offpos, min(self.offpos + tgt, self.nprime))
                hi = KeyVSliced(self.Gprime, self.nprime + self.offpos, self.nprime + min(self.offpos + tgt, 2 * self.nprime))
            else:
                lo = KeyVSliced(self.HprimeL, self.offpos, min(self.offpos + tgt, self.nprime))
                hi = KeyVSliced(self.HprimeR, self.nprime + self.offpos, self.nprime + min(self.offpos + tgt, 2 * self.nprime))

        else:
            lo, hi = KeyV(len(buffers[0])//32, buffers[0]), KeyV(len(buffers[1])//32, buffers[1])

        # In memory caching from some point
        self.gc(5)
        utils.ensure(self.off_method != 2 or self.off2_thresh <= self.nprime_thresh, "off2 threshold invalid")
        inmem = self.round > 0 and (self.nprime <= self.nprime_thresh or (self.off_method == 2 and self.nprime <= self.off2_thresh))
        fld = None

        if inmem:
            if self.offpos == 0:  # allocate in-memory buffers now
                fldS = KeyV(self.nprime)
                self.Xprime[self.offstate - 3] = fldS
            fld = KeyVSliced(self.Xprime[self.offstate - 3], self.offpos, min(self.offpos + tgt, self.nprime))
        else:
            fld = KeyV(tgt)

        # Consider blinding by halves
        # Folding has 4 different blind masks
        self.gc(10)
        if self.round == 0 and self.offstate in [3, 4]:
            blinv = (_ONE, _ONE)  # no blinding for in-memory Gprime, Hprime in the round 0
        else:
            blinv = (_invert(None, x_raw=self.blinds[0][2*(self.offstate - 3)]),
                     _invert(None, x_raw=self.blinds[0][2*(self.offstate - 3) + 1]))

        nbli  = None if inmem else (
            self.blinds[1][2*(self.offstate - 3)],
            self.blinds[1][2*(self.offstate - 3) + 1]
        )

        a0 = crypto.new_scalar()
        b0 = crypto.new_scalar()
        if self.offstate in [3, 6]:
            crypto.decodeint_into_noreduce(a0, _sc_mul(None, self.winv, blinv[0]))
            crypto.decodeint_into_noreduce(b0, _sc_mul(None, self.w_round, blinv[1]))
        elif self.offstate in [4, 5]:
            crypto.decodeint_into_noreduce(a0, _sc_mul(None, self.w_round, blinv[0]))
            crypto.decodeint_into_noreduce(b0, _sc_mul(None, self.winv, blinv[1]))

        del(blinv)
        self.gc(12)
        if self.offstate in [3, 4]:  # G, H
            for i in range(0, tgt):
                crypto.decodepoint_into(_tmp_pt_1, lo.to(i))
                crypto.decodepoint_into(_tmp_pt_2, hi.to(i))
                crypto.add_keys3_into(_tmp_pt_3, a0, _tmp_pt_1, b0, _tmp_pt_2)
                if nbli:
                    noff = int(i + self.offpos >= (self.nprime>>1))
                    crypto.scalarmult_into(_tmp_pt_3, _tmp_pt_3, nbli[noff])  # blind again
                crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_3)
                fld.read(i, _tmp_bf_0)
                _gc_iter(i)

        elif self.offstate in [5, 6]:  # a, b
            for i in range(0, tgt):
                crypto.decodeint_into_noreduce(_tmp_sc_3, lo.to(i))
                crypto.decodeint_into_noreduce(_tmp_sc_4, hi.to(i))
                crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_3, a0)
                crypto.sc_mul_into(_tmp_sc_4, _tmp_sc_4, b0)
                crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_4)
                if nbli:
                    noff = int(i + self.offpos >= (self.nprime>>1))
                    crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_3, nbli[noff])  # blind again
                crypto.encodeint_into(_tmp_bf_0, _tmp_sc_3)
                fld.read(i, _tmp_bf_0)
                _gc_iter(i)

        del(a0, b0, lo, hi, nbli)
        self.gc(15)
        # State transition
        self.offpos += tgt
        if self.offpos >= self.nprime:
            self.offpos = 0
            self.offstate += 1
            print('Moved to state %s, npr %s' % (self.offstate, self.nprime))

            if self.nprime == 1:
                if self.offstate == 6:
                    self.a = fld.to(0)

                if self.offstate == 7:
                    self.b = fld.to(0)

        if self.offstate >= 7 or (self.round == 0 and self.off_method == 2 and self.offstate >= 5):
            self.nprime >>= 1
            self.round += 1

            if self.round == 1:
                self._phase2_loop_body_r0del()

            self.gc(16)

            if inmem:
                self.offstate = 10  # finish in-memory, _phase2_loop_full

            elif self.off_method >= 1:
                self.offstate = 2   # another loop, cLcR offdot

            else:
                self.offstate = 20  # manual cLcR

            print('Moved to state', self.offstate)

            # Rotate blindings
            self._swap_blinds()

        elif self.round == 0 and self.offstate in (3, 4):
            self._phase2_loop_body_r0dump()

        if self.nprime <= 0:
            self.offstate = 12  # final, _phase2_final
            print('Terminating')

        if not inmem:
            fldd = fld.d
            del(fld)
            return fldd

    def _phase2_final(self):
        from apps.monero.xmr.serialize_messages.tx_rsig_bulletproof import Bulletproof

        return (
            1,
            Bulletproof(
                V=self.V, A=self.A, S=self.S, T1=self.T1, T2=self.T2, taux=self.taux, mu=self.mu, L=self.L, R=self.R, a=self.a, b=self.b, t=self.t
            ),
        )

    def _phase2_loop_full(self):
        while self.nprime >= 1:
            self._phase2_loop_body()
        self.a = self.aprime.to(0)
        self.b = self.bprime.to(0)
        return self._phase2_final()

    def _phase2_loop_body_r0init(self):
        """
        Initializes Gprime, HPrime for the round0, state in self.HprimeLRst
        """
        print('_phase2_loop_body_r0init, state: %s, off: %s' % (self.offstate, self.offpos))
        if self.Gprec is None or self.Hprec2 is None:
            self.Gprec2 = self._gprec_aux(self.MN)
            self.Hprec2 = self._hprec_aux(self.MN)

        self.yinvpowL = KeyVPowers(self.MN, _invert(_tmp_bf_0, self.y), raw=True)
        self.yinvpowR = KeyVPowers(self.MN, _tmp_bf_0, raw=True)
        self.tmp_pt = crypto.new_point()

        self.Gprime = self.Gprec2
        self.HprimeL = KeyVEval(
            self.MN, lambda i, d: _scalarmult_key(d, self.Hprec2.to(i), None, self.yinvpowL[i])
        )

        self.HprimeR = KeyVEval(
            self.MN, lambda i, d: _scalarmult_key(d, self.Hprec2.to(i), None, self.yinvpowR[i], self.tmp_pt)
        )
        self.Hprime = self.HprimeL

        if self.HprimeLRst:
            self.yinvpowL.sload(self.HprimeLRst[0])
            self.yinvpowR.sload(self.HprimeLRst[1])
            self.HprimeLRst = None

        self.gc(34)

    def _phase2_loop_body_r0del(self):
        del (self.Gprec2, self.Hprec2, self.yinvpowL, self.yinvpowR, self.HprimeL, self.HprimeR, self.tmp_pt, self.HprimeLRst)

    def _phase2_loop_body_r0clear(self):
        self.yinvpowL = None
        self.yinvpowR = None
        self.HprimeL = None
        self.HprimeR = None
        self.tmp_pt = None
        self.Gprec2 = None
        self.Hprec2 = None

    def _phase2_loop_body_r0dump(self):
        self.HprimeLRst = self.yinvpowL.sdump(), self.yinvpowR.sdump()
        self._phase2_loop_body_r0clear()

    def _phase2_loop_body(self):
        """
        One loop for the prover loop.
        Assumes nprime = MN/2 on the beginning.
        """
        print('_phase2_loop_body, state: %s, off: %s' % (self.offstate, self.offpos))
        print('wloop: M: %s, r: %s, nprime: %s' % (self.M, self.round, self.nprime))

        if self.round == 0 and (self.Gprime is None or len(self.Gprime) != 2*self.nprime):
            self._phase2_loop_body_r0init()

        if self.cL is None:
            self.cL = _ensure_dst_key()
            self.cR = _ensure_dst_key()

        # PAPER LINE 15
        nprime = self.nprime
        npr2 = self.nprime * 2
        cL = self.cL
        cR = self.cR
        self.tmp = _ensure_dst_key()
        self.gc(22)

        # PAPER LINES 16-17
        # cL = \ap_{\left(\inta\right)} \cdot \bp_{\left(\intb\right)}
        # cR = \ap_{\left(\intb\right)} \cdot \bp_{\left(\inta\right)}
        _inner_product(
            self.aprime.slice_view(0, nprime), self.bprime.slice_view(nprime, npr2), cL
        )

        _inner_product(
            self.aprime.slice_view(nprime, npr2), self.bprime.slice_view(0, nprime), cR
        )
        # print('r: %s, cL ' % self.round, ubinascii.hexlify(cL))
        # print('r: %s, cR ' % self.round, ubinascii.hexlify(cR))
        self.gc(23)

        # PAPER LINES 18-19
        # Lc = 8^{-1} \left(\left( \sum_{i=0}^{\np} \ap_{i}\quad\Gp_{i+\np} + \bp_{i+\np}\Hp_{i} \right)
        # 		    + \left(c_L x_{ip}\right)H \right)
        _vector_exponent_custom(
            self.Gprime.slice_view(nprime, npr2),
            self.Hprime.slice_view(0, nprime),
            self.aprime.slice_view(0, nprime),
            self.bprime.slice_view(nprime, npr2),
            _tmp_bf_0,
        )

        # In round 0 backup the y^{prime - 1}
        if self.round == 0:
            self.yinvpowR.set_state(self.yinvpowL.last_idx, self.yinvpowL.cur)

        _sc_mul(self.tmp, cL, self.x_ip)
        _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, self.tmp))
        _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
        self.L.read(self.round, _tmp_bf_0)
        self.gc(24)

        # Rc = 8^{-1} \left(\left( \sum_{i=0}^{\np} \ap_{i+\np}\Gp_{i}\quad + \bp_{i}\quad\Hp_{i+\np} \right)
        #           + \left(c_R x_{ip}\right)H \right)
        _vector_exponent_custom(
            self.Gprime.slice_view(0, nprime),
            self.Hprime.slice_view(nprime, npr2),
            self.aprime.slice_view(nprime, npr2),
            self.bprime.slice_view(0, nprime),
            _tmp_bf_0,
        )

        _sc_mul(self.tmp, cR, self.x_ip)
        _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, self.tmp))
        _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
        self.R.read(self.round, _tmp_bf_0)
        self.gc(25)

        # print('r: %s, Lc ' % self.round, ubinascii.hexlify(self.L.to(self.round)))
        # print('r: %s, Rc ' % self.round, ubinascii.hexlify(self.R.to(self.round)))

        # PAPER LINES 21-22
        _hash_cache_mash(self.w_round, self.hash_cache, self.L.to(self.round), self.R.to(self.round))
        if self.w_round == _ZERO:
            return (0,)

        # PAPER LINES 24-25, fold {G~, H~}
        _invert(self.winv, self.w_round)
        self.gc(26)

        # print('r: %s, w0 ' % self.round, ubinascii.hexlify(self.w_round))
        # print('r: %s, wi ' % self.round, ubinascii.hexlify(self.winv))

        # PAPER LINES 28-29, fold {a, b} vectors
        # aprime's high part is used as a buffer for other operations
        _scalar_fold(self.aprime, self.w_round, self.winv)
        self.aprime.resize(nprime)
        self.gc(27)

        _scalar_fold(self.bprime, self.winv, self.w_round)
        self.bprime.resize(nprime)
        self.gc(28)

        # First fold produced to a new buffer, smaller one (G~ on-the-fly)
        Gprime_new = KeyV(nprime) if self.round == 0 else self.Gprime
        self.Gprime = _hadamard_fold(self.Gprime, self.winv, self.w_round, Gprime_new, 0)
        self.Gprime.resize(nprime)
        self.gc(30)

        # Hadamard fold for H is special - linear scan only.
        # Linear scan is slow, thus we have HprimeR.
        if self.round == 0:
            Hprime_new = KeyV(nprime)
            self.Hprime = _hadamard_fold(
                self.Hprime, self.w_round, self.winv, Hprime_new, 0, self.HprimeR, nprime
            )
            # Hprime = _hadamard_fold_linear(Hprime, w_round, winv, Hprime_new, 0)

        else:
            _hadamard_fold(self.Hprime, self.w_round, self.winv)
            self.Hprime.resize(nprime)

        # print('r: %s, ap ' % self.round, ubinascii.hexlify(self.aprime.d[-64:]))
        # print('r: %s, bp ' % self.round, ubinascii.hexlify(self.bprime.d[-64:]))
        # print('r: %s, Gp ' % self.round, ubinascii.hexlify(self.Gprime.d[-64:]))
        # print('r: %s, Hp ' % self.round, ubinascii.hexlify(self.Hprime.d[-64:]))

        if self.round == 0:
            # del (Gprec, Hprec, yinvpowL, HprimeL)
            del (self.Gprec2, self.Hprec2, self.yinvpowL, self.yinvpowR, self.HprimeL, self.HprimeR, self.tmp_pt)

        self.gc(31)
        self.round += 1
        self.nprime >>= 1

    def _prove_loop(self, MN, logMN, l, r, y, x_ip, hash_cache, Gprec, Hprec):
        """
        Prover phase 2 - loop.
        Used only for in-memory computations.
        """
        self.nprime = MN >> 1
        self.aprime = l
        self.bprime = r
        self.hash_cache = hash_cache
        self.x_ip = x_ip
        self.y = y

        self.Gprec2 = Gprec
        self.Hprec2 = Hprec
        self.gc(20)

        self.L = _ensure_dst_keyvect(None, logMN)
        self.R = _ensure_dst_keyvect(None, logMN)
        self.cL = _ensure_dst_key()
        self.cR = _ensure_dst_key()
        self.winv = _ensure_dst_key()
        self.w_round = _ensure_dst_key()
        self.tmp = _ensure_dst_key()
        self.tmp_k_1 = _ensure_dst_key()
        self.round = 0

        # PAPER LINE 13
        while self.nprime >= 1:
            self._phase2_loop_body()
            self.gc(31)

        return self.L, self.R, self.aprime.to(0), self.bprime.to(0)

    def verify(self, proof):
        return self.verify_batch([proof])

    def verify_batch(self, proofs, single_optim=True):
        """
        BP batch verification
        :param proofs:
        :param single_optim: single proof memory optimization
        :return:
        """
        max_length = 0
        for proof in proofs:
            utils.ensure(_is_reduced(proof.taux), "Input scalar not in range")
            utils.ensure(_is_reduced(proof.mu), "Input scalar not in range")
            utils.ensure(_is_reduced(proof.a), "Input scalar not in range")
            utils.ensure(_is_reduced(proof.b), "Input scalar not in range")
            utils.ensure(_is_reduced(proof.t), "Input scalar not in range")
            utils.ensure(len(proof.V) >= 1, "V does not have at least one element")
            utils.ensure(len(proof.L) == len(proof.R), "|L| != |R|")
            utils.ensure(len(proof.L) > 0, "Empty proof")
            max_length = max(max_length, len(proof.L))

        utils.ensure(max_length < 32, "At least one proof is too large")

        maxMN = 1 << max_length
        logN = 6
        N = 1 << logN
        tmp = _ensure_dst_key()

        # setup weighted aggregates
        is_single = len(proofs) == 1 and single_optim  # ph4
        z1 = _init_key(_ZERO)
        z3 = _init_key(_ZERO)
        m_z4 = _vector_dup(_ZERO, maxMN) if not is_single else None
        m_z5 = _vector_dup(_ZERO, maxMN) if not is_single else None
        m_y0 = _init_key(_ZERO)
        y1 = _init_key(_ZERO)
        muex_acc = _init_key(_ONE)

        Gprec = self._gprec_aux(maxMN)
        Hprec = self._hprec_aux(maxMN)

        for proof in proofs:
            M = 1
            logM = 0
            while M <= _BP_M and M < len(proof.V):
                logM += 1
                M = 1 << logM

            utils.ensure(len(proof.L) == 6 + logM, "Proof is not the expected size")
            MN = M * N
            weight_y = crypto.encodeint(crypto.random_scalar())
            weight_z = crypto.encodeint(crypto.random_scalar())

            # Reconstruct the challenges
            hash_cache = _hash_vct_to_scalar(None, proof.V)
            y = _hash_cache_mash(None, hash_cache, proof.A, proof.S)
            utils.ensure(y != _ZERO, "y == 0")
            z = _hash_to_scalar(None, y)
            _copy_key(hash_cache, z)
            utils.ensure(z != _ZERO, "z == 0")

            x = _hash_cache_mash(None, hash_cache, z, proof.T1, proof.T2)
            utils.ensure(x != _ZERO, "x == 0")
            x_ip = _hash_cache_mash(None, hash_cache, x, proof.taux, proof.mu, proof.t)
            utils.ensure(x_ip != _ZERO, "x_ip == 0")

            # PAPER LINE 61
            _sc_mulsub(m_y0, proof.taux, weight_y, m_y0)
            zpow = _vector_powers(z, M + 3)

            k = _ensure_dst_key()
            ip1y = _vector_power_sum(y, MN)
            _sc_mulsub(k, zpow.to(2), ip1y, _ZERO)
            for j in range(1, M + 1):
                utils.ensure(j + 2 < len(zpow), "invalid zpow index")
                _sc_mulsub(k, zpow.to(j + 2), _BP_IP12, k)

            # VERIFY_line_61rl_new
            _sc_muladd(tmp, z, ip1y, k)
            _sc_sub(tmp, proof.t, tmp)

            _sc_muladd(y1, tmp, weight_y, y1)
            weight_y8 = _init_key(weight_y)
            weight_y8 = _sc_mul(None, weight_y, _EIGHT)

            muex = MultiExpSequential(points=[pt for pt in proof.V])
            for j in range(len(proof.V)):
                _sc_mul(tmp, zpow.to(j + 2), weight_y8)
                muex.add_scalar(_init_key(tmp))

            _sc_mul(tmp, x, weight_y8)
            muex.add_pair(_init_key(tmp), proof.T1)

            xsq = _ensure_dst_key()
            _sc_mul(xsq, x, x)

            _sc_mul(tmp, xsq, weight_y8)
            muex.add_pair(_init_key(tmp), proof.T2)

            weight_z8 = _init_key(weight_z)
            weight_z8 = _sc_mul(None, weight_z, _EIGHT)

            muex.add_pair(weight_z8, proof.A)
            _sc_mul(tmp, x, weight_z8)
            muex.add_pair(_init_key(tmp), proof.S)

            _multiexp(tmp, muex, False)
            _add_keys(muex_acc, muex_acc, tmp)
            del muex

            # Compute the number of rounds for the inner product
            rounds = logM + logN
            utils.ensure(rounds > 0, "Zero rounds")

            # PAPER LINES 21-22
            # The inner product challenges are computed per round
            w = _ensure_dst_keyvect(None, rounds)
            for i in range(rounds):
                _hash_cache_mash(_tmp_bf_0, hash_cache, proof.L[i], proof.R[i])
                w.read(i, _tmp_bf_0)
                utils.ensure(w.to(i) != _ZERO, "w[i] == 0")

            # Basically PAPER LINES 24-25
            # Compute the curvepoints from G[i] and H[i]
            yinvpow = _init_key(_ONE)
            ypow = _init_key(_ONE)
            yinv = _invert(None, y)
            self.gc(61)

            winv = _ensure_dst_keyvect(None, rounds)
            for i in range(rounds):
                _invert(_tmp_bf_0, w.to(i))
                winv.read(i, _tmp_bf_0)
                self.gc(62)

            g_scalar = _ensure_dst_key()
            h_scalar = _ensure_dst_key()
            twoN = self._two_aux(N)
            for i in range(MN):
                _copy_key(g_scalar, proof.a)
                _sc_mul(h_scalar, proof.b, yinvpow)

                for j in range(rounds - 1, -1, -1):
                    J = len(w) - j - 1

                    if (i & (1 << j)) == 0:
                        _sc_mul(g_scalar, g_scalar, winv.to(J))
                        _sc_mul(h_scalar, h_scalar, w.to(J))
                    else:
                        _sc_mul(g_scalar, g_scalar, w.to(J))
                        _sc_mul(h_scalar, h_scalar, winv.to(J))

                # Adjust the scalars using the exponents from PAPER LINE 62
                _sc_add(g_scalar, g_scalar, z)
                utils.ensure(2 + i // N < len(zpow), "invalid zpow index")
                utils.ensure(i % N < len(twoN), "invalid twoN index")
                _sc_mul(tmp, zpow.to(2 + i // N), twoN.to(i % N))
                _sc_muladd(tmp, z, ypow, tmp)
                _sc_mulsub(h_scalar, tmp, yinvpow, h_scalar)

                if not is_single:  # ph4
                    _sc_mulsub(m_z4[i], g_scalar, weight_z, m_z4[i])
                    _sc_mulsub(m_z5[i], h_scalar, weight_z, m_z5[i])
                else:
                    _sc_mul(tmp, g_scalar, weight_z)
                    _sub_keys(
                        muex_acc, muex_acc, _scalarmult_key(tmp, Gprec.to(i), tmp)
                    )

                    _sc_mul(tmp, h_scalar, weight_z)
                    _sub_keys(
                        muex_acc, muex_acc, _scalarmult_key(tmp, Hprec.to(i), tmp)
                    )

                if i != MN - 1:
                    _sc_mul(yinvpow, yinvpow, yinv)
                    _sc_mul(ypow, ypow, y)
                if i & 15 == 0:
                    self.gc(62)

            del (g_scalar, h_scalar, twoN)
            self.gc(63)

            _sc_muladd(z1, proof.mu, weight_z, z1)
            muex = MultiExpSequential(
                point_fnc=lambda i, d: proof.L[i // 2]
                if i & 1 == 0
                else proof.R[i // 2]
            )
            for i in range(rounds):
                _sc_mul(tmp, w.to(i), w.to(i))
                _sc_mul(tmp, tmp, weight_z8)
                muex.add_scalar(tmp)
                _sc_mul(tmp, winv.to(i), winv.to(i))
                _sc_mul(tmp, tmp, weight_z8)
                muex.add_scalar(tmp)

            acc = _multiexp(None, muex, False)
            _add_keys(muex_acc, muex_acc, acc)

            _sc_mulsub(tmp, proof.a, proof.b, proof.t)
            _sc_mul(tmp, tmp, x_ip)
            _sc_muladd(z3, tmp, weight_z, z3)

        _sc_sub(tmp, m_y0, z1)
        z3p = _sc_sub(None, z3, y1)

        check2 = crypto.encodepoint(
            crypto.ge25519_double_scalarmult_base_vartime(
                crypto.decodeint(z3p), crypto.xmr_H(), crypto.decodeint(tmp)
            )
        )
        _add_keys(muex_acc, muex_acc, check2)

        if not is_single:  # ph4
            muex = MultiExpSequential(
                point_fnc=lambda i, d: Gprec.to(i // 2)
                if i & 1 == 0
                else Hprec.to(i // 2)
            )
            for i in range(maxMN):
                muex.add_scalar(m_z4[i])
                muex.add_scalar(m_z5[i])
            _add_keys(muex_acc, muex_acc, _multiexp(None, muex, True))

        if muex_acc != _ONE:
            raise ValueError("Verification failure at step 2")
        return True

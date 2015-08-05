#!/usr/bin/python
import ctypes as c
import random
import ecdsa
import hashlib
import binascii
import os
import pytest

def bytes2num(s):
    res = 0
    for i, b in enumerate(reversed(bytearray(s))):
        res += b << (i * 8)
    return res


curves = {
    'nist256p1': ecdsa.curves.NIST256p,
    'secp256k1': ecdsa.curves.SECP256k1
}

random_iters = int(os.environ.get('ITERS', 1))

lib = c.cdll.LoadLibrary('./libtrezor-crypto.so')

lib.get_curve_by_name.restype = c.c_void_p

BIGNUM = c.c_uint32 * 9


class Random(random.Random):
    def randbytes(self, n):
        buf = (c.c_uint8 * n)()
        for i in range(n):
            buf[i] = self.randrange(0, 256)
        return buf

    def randpoint(self, curve):
        k = self.randrange(0, curve.order)
        return k * curve.generator


def int2bn(x, bn_type=BIGNUM):
    b = bn_type()
    b._int = x
    for i in range(len(b)):
        b[i] = x % (1 << 30)
        x = x >> 30
    return b


def bn2int(b):
    x = 0
    for i in range(len(b)):
        x += (b[i] << (30 * i))
    return x


@pytest.fixture(params=range(random_iters))
def r(request):
    seed = request.param
    return Random(seed + int(os.environ.get('SEED', 0)))


@pytest.fixture(params=list(sorted(curves)))
def curve(request):
    name = request.param
    curve_ptr = lib.get_curve_by_name(name)
    assert curve_ptr, 'curve {} not found'.format(name)
    curve_obj = curves[name]
    curve_obj.ptr = c.c_void_p(curve_ptr)
    curve_obj.p = curve_obj.curve.p()  # shorthand
    return curve_obj


def test_inverse(curve, r):
    x = r.randrange(1, curve.p)
    y = int2bn(x)
    lib.bn_inverse(y, int2bn(curve.p))
    y = bn2int(y)
    y_ = ecdsa.numbertheory.inverse_mod(x, curve.p)
    assert y == y_


def test_is_less(curve, r):
    x = r.randrange(0, curve.p)
    y = r.randrange(0, curve.p)
    x_ = int2bn(x)
    y_ = int2bn(y)

    res = lib.bn_is_less(x_, y_)
    assert res == (x < y)

    res = lib.bn_is_less(y_, x_)
    assert res == (y < x)


def test_is_equal(curve, r):
    x = r.randrange(0, curve.p)
    y = r.randrange(0, curve.p)
    x_ = int2bn(x)
    y_ = int2bn(y)

    assert lib.bn_is_equal(x_, y_) == (x == y)
    assert lib.bn_is_equal(x_, x_) == 1
    assert lib.bn_is_equal(y_, y_) == 1


def test_is_zero(curve, r):
    x = r.randrange(0, curve.p);
    assert lib.bn_is_zero(int2bn(x)) == (not x)


def test_simple_comparisons():
    assert lib.bn_is_zero(int2bn(0)) == 1
    assert lib.bn_is_zero(int2bn(1)) == 0

    assert lib.bn_is_less(int2bn(0), int2bn(0)) == 0
    assert lib.bn_is_less(int2bn(1), int2bn(0)) == 0
    assert lib.bn_is_less(int2bn(0), int2bn(1)) == 1

    assert lib.bn_is_equal(int2bn(0), int2bn(0)) == 1
    assert lib.bn_is_equal(int2bn(1), int2bn(0)) == 0
    assert lib.bn_is_equal(int2bn(0), int2bn(1)) == 0


def test_mult_half(curve, r):
    x = r.randrange(0, 2*curve.p)
    y = int2bn(x)
    lib.bn_mult_half(y, int2bn(curve.p))
    y = bn2int(y)
    if y > curve.p:
        y -= curve.p
    half = ecdsa.numbertheory.inverse_mod(2, curve.p)
    assert y == (x * half) % curve.p


def test_subtractmod(curve, r):
    x = r.randrange(0, 2 ** 256)
    y = r.randrange(0, 2 ** 256)
    z = int2bn(0)
    lib.bn_subtractmod(int2bn(x), int2bn(y), z, int2bn(curve.p))
    z = bn2int(z)
    z_ = x + 2*curve.p - y
    assert z == z_


def test_subtract2(r):
    x = r.randrange(0, 2 ** 256)
    y = r.randrange(0, 2 ** 256)
    x, y = max(x, y), min(x, y)
    z = int2bn(0)
    lib.bn_subtract(int2bn(x), int2bn(y), z)
    z = bn2int(z)
    z_ = x - y
    assert z == z_


def test_addmod(curve, r):
    x = r.randrange(0, 2 ** 256)
    y = r.randrange(0, 2 ** 256)
    z_ = (x + y) % curve.p
    z = int2bn(x)
    lib.bn_addmod(z, int2bn(y), int2bn(curve.p))
    z = bn2int(z)

    assert z == z_


def test_multiply(curve, r):
    k = r.randrange(0, 2 * curve.p)
    x = r.randrange(0, 2 * curve.p)
    z = (k * x) % curve.p
    k = int2bn(k)
    z_ = int2bn(x)
    p_ = int2bn(curve.p)
    lib.bn_multiply(k, z_, p_)
    z_ = bn2int(z_)
    assert z_ < 2*curve.p
    if z_ >= curve.p:
        z_ = z_ - curve.p
    assert z_ == z


def test_multiply1(curve, r):
    k = r.randrange(0, 2 * curve.p)
    x = r.randrange(0, 2 * curve.p)
    kx = k * x
    res = int2bn(0, bn_type=(c.c_uint32 * 18))
    lib.bn_multiply_long(int2bn(k), int2bn(x), res)
    res = bn2int(res)
    assert res == kx


def test_multiply2(curve, r):
    x = int2bn(0)
    s = r.randrange(0, 2 ** 526)
    res = int2bn(s, bn_type=(c.c_uint32 * 18))
    prime = int2bn(curve.p)
    lib.bn_multiply_reduce(x, res, prime)

    x = bn2int(x)
    x_ = s % curve.p

    assert x == x_


def test_fast_mod(curve, r):
    x = r.randrange(0, 128*curve.p)
    y = int2bn(x)
    lib.bn_fast_mod(y, int2bn(curve.p))
    y = bn2int(y)
    assert y < 2*curve.p
    if y >= curve.p:
        y -= curve.p
    assert x % curve.p == y


def test_mod(curve, r):
    x = r.randrange(0, 2*curve.p)
    y = int2bn(x)
    lib.bn_mod(y, int2bn(curve.p))
    assert bn2int(y) == x % curve.p

POINT = BIGNUM * 2
to_POINT = lambda p: POINT(int2bn(p.x()), int2bn(p.y()))
from_POINT = lambda p: (bn2int(p[0]), bn2int(p[1]))

JACOBIAN = BIGNUM * 3
to_JACOBIAN = lambda jp: JACOBIAN(int2bn(jp[0]), int2bn(jp[1]), int2bn(jp[2]))
from_JACOBIAN = lambda p: (bn2int(p[0]), bn2int(p[1]), bn2int(p[2]))


def test_point_multiply(curve, r):
    p = r.randpoint(curve)
    k = r.randrange(0, 2 ** 256)
    kp = k * p
    res = POINT(int2bn(0), int2bn(0))
    lib.point_multiply(curve.ptr, int2bn(k), to_POINT(p), res)
    res = from_POINT(res)
    assert res == (kp.x(), kp.y())


def test_point_add(curve, r):
    p1 = r.randpoint(curve)
    p2 = r.randpoint(curve)
    #print '-' * 80
    q = p1 + p2
    q1 = to_POINT(p1)
    q2 = to_POINT(p2)
    lib.point_add(curve.ptr, q1, q2)
    q_ = from_POINT(q2)
    assert q_ == (q.x(), q.y())


def test_point_double(curve, r):
    p = r.randpoint(curve)
    q = p.double()
    q_ = to_POINT(p)
    lib.point_double(curve.ptr, q_)
    q_ = from_POINT(q_)
    assert q_ == (q.x(), q.y())


def test_point_to_jacobian(curve, r):
	p = r.randpoint(curve)
	jp = JACOBIAN()
	lib.curve_to_jacobian(to_POINT(p), jp, int2bn(curve.p))
	jx, jy, jz = from_JACOBIAN(jp)
	assert jx == (p.x() * jz ** 2) % curve.p
	assert jy == (p.y() * jz ** 3) % curve.p

	q = POINT()
	lib.jacobian_to_curve(jp, q, int2bn(curve.p))
	q = from_POINT(q)
	assert q == (p.x(), p.y())


def test_cond_negate(curve, r):
    x = r.randrange(0, curve.p)
    a = int2bn(x)
    lib.conditional_negate(0, a, int2bn(curve.p))
    assert bn2int(a) == x
    lib.conditional_negate(-1, a, int2bn(curve.p))
    assert bn2int(a) == curve.p - x


def test_jacobian_add(curve, r):
    p1 = r.randpoint(curve)
    p2 = r.randpoint(curve)
    prime = int2bn(curve.p)
    q = POINT()
    jp2 = JACOBIAN()
    lib.curve_to_jacobian(to_POINT(p2), jp2, prime)
    lib.point_jacobian_add(to_POINT(p1), jp2, prime)
    lib.jacobian_to_curve(jp2, q, prime)
    q = from_POINT(q)
    p_ = p1 + p2
    assert (p_.x(), p_.y()) == q

def test_jacobian_double(curve, r):
    p = r.randpoint(curve)
    p2 = p.double()
    prime = int2bn(curve.p)
    q = POINT()
    jp = JACOBIAN()
    lib.curve_to_jacobian(to_POINT(p), jp, prime)
    lib.point_jacobian_double(jp, curve.ptr)
    lib.jacobian_to_curve(jp, q, prime)
    q = from_POINT(q)
    assert (p2.x(), p2.y()) == q

def sigdecode(sig, _):
    return map(bytes2num, [sig[:32], sig[32:]])


def test_sign(curve, r):
    priv = r.randbytes(32)
    digest = r.randbytes(32)
    sig = r.randbytes(64)

    lib.ecdsa_sign_digest(curve.ptr, priv, digest, sig, c.c_void_p(0))

    exp = bytes2num(priv)
    sk = ecdsa.SigningKey.from_secret_exponent(exp, curve,
                                               hashfunc=hashlib.sha256)
    vk = sk.get_verifying_key()

    sig_ref = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string_canonize)
    assert binascii.hexlify(sig) == binascii.hexlify(sig_ref)

    assert vk.verify_digest(sig, digest, sigdecode)

def test_validate_pubkey(curve, r):
    p = r.randpoint(curve)
    assert lib.ecdsa_validate_pubkey(curve.ptr, to_POINT(p))

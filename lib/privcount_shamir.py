#!/usr/bin/python3

"""Dummy example of the shamir secret-splitting based privcount design

   This code is meant to show how we can store split values in a way
   that provides secrecy at the data collector (assuming no tally keys
   are lost).

   This algorithm provides resilience to S-T malfunctioning tally
   reporters (where S is the number of shares and T is the trusted
   threshold), but it doesn't do anything about malfunctioning
   collectors.  I am not at all clear how that's supposed to work!

   Noise is not currently implemented.  Public-key encryption is only
   simulated.

"""

# Large 64-bit prime.  We might want to choose something else for
# convenience, though, like 2**64 - 257 or even 2**61 - 1.
P = 2**64 - 59

import os

class FE(object):
    """Field element modulo P.  Immutable."""
    def __init__(self, n):
        self._n = n % P

    def __mul__(self, rhs):
        """
        >>> FE(1) * FE(10)
        FE(10)
        >>> FE(P-1) * FE(P-2)
        FE(2)
        """
        return FE(self._n * rhs._n)

    def __add__(self, rhs):
        """
        >>> FE(1) + FE(10)
        FE(11)
        >>> FE(P-99) + FE(101)
        FE(2)
        """
        return FE(self._n + rhs._n)

    def __sub__(self, rhs):
        """
        >>> FE(10) - FE(9)
        FE(1)
        >>> FE(10) - FE(P-5)
        FE(15)
        """
        return FE(self._n - rhs._n)

    def __neg__(self):
        """
        >>> - FE(P-99)
        FE(99)
        >>> - FE(0)
        FE(0)
        """
        return FE(- self._n)

    def __truediv__(self, rhs):
        """
        >>> FE(10) / FE(5)
        FE(2)
        >>> FE(5) / FE(2)
        FE(9223372036854775781)
        >>> FE(9223372036854775781) * FE(2)
        FE(5)
        """
        return self * rhs.recip()

    def __eq__(self, rhs):
        """
        >>> FE(1) == FE(0)
        False
        >>> FE(0) == FE(0)
        True
        """
        return self._n == rhs._n

    def __hash__(self):
        return hash(self._n)

    def recip(self):
        """Return the multiplicative inverse of self.

        >>> FE(10).recip() * FE(10)
        FE(1)
        >>> FE(1).recip()
        FE(1)
        >>> FE(10).recip() * FE(200)
        FE(20)
        >>> FE(0).recip()
        Traceback (most recent call last):
            ...
        ZeroDivisionError
        """
        # Euler's theorem: n^-1 == n^(p-2)   [mod p]
        if self._n == 0:
            raise ZeroDivisionError()
        return FE(pow(self._n, P-2, P))

    def __repr__(self):
        return "FE({})".format(self._n)

    def split(self):
        """Return two random FE values (a,b) such that a+b==self

        >>> a,b = FE(12345).split()
        >>> a + b
        FE(12345)
        """
        m = FE.random()
        return (m, self - m)

    @staticmethod
    def random():
        """Return a random field element."""
        while True:
            n = int.from_bytes(os.urandom(8), 'little')
            if n < P:
                return FE(n)

class EncryptedFE(object):
    """
    Represets an encrypted field element, encrypted using the public key
    of some tally reporter.  No real encryption is actually preformed here.
    """
    def __init__(self, fe, owner):
        self._fe = fe
        self._owner = owner

    def __repr__(self):
        return "ENC({},{})".format(self._owner, self._fe)

    def decrypt(self):
        return self._fe

class Polynomial(object):
    def __init__(self, coeffs):
        """
        A polynomial in our field, represented as a list of its coefficients in
        ascending order.
        """
        self._coeffs = coeffs

    def evaluate_at(self, x):
        """
        Return the value of this polynomial evaluated at some x.

        >>> p = Polynomial([ FE(5), FE(100), FE(1) ] )
        >>> p.evaluate_at(FE(0))
        FE(5)
        >>> p.evaluate_at(FE(1))
        FE(106)
        >>> p.evaluate_at(FE(2))
        FE(209)
        >>> p.evaluate_at(FE(3))
        FE(314)
        """
        accumulator = FE(0)
        for c in reversed(self._coeffs):
            accumulator *= x
            accumulator += c
        return accumulator

    def __str__(self):
        return " + ".join("{} * x^{}".format(self._coeffs[i], i)
                          for i in range(len(self._coeffs)))

    @staticmethod
    def random(degree, value_at_0=FE(0)):
        """
        Return a polynomial of a given degree with random coefficients,
        execpt for its y-intercept, which should be value_at_0.

        >>> p = Polynomial.random(3, FE(6))
        >>> len(p._coeffs)
        4
        >>> p._coeffs[0]
        FE(6)
        >>> p.evaluate_at(FE(0))
        FE(6)
        """
        coeffs = [ value_at_0 ] + [ FE.random() for d in range(degree) ]
        return Polynomial(coeffs)


class Counter(object):
    def __init__(self, name, threshold, n_shares, initial_value=0):
        # Here's what the DCs do in order to construct a counter.

        # They begin by creating a polynomial to secret-share the
        # initial value, and sampling it at enough points to construct
        # enough shares.
        poly = Polynomial.random(threshold-1, FE(initial_value))
        raw_shares = [ (FE(x), poly.evaluate_at(FE(x)))
                       for x in range(1, n_shares+1) ]

        # Next, for each share's y-coordinate, the client splits that
        # y-coordinate into two separate values and encrypts one to
        # the corresponding TR. Now the counter value can't be
        # recovered without knowing (enough of) the TRs' public keys.

        # (As a further optimization, instead of encrypting each y2
        # separately, we could generate them based on a random seed,
        # and encrypt only the random seed to each public key.)
        offsets = [ ]
        secrets = [ ]
        for x, y in raw_shares:
            y1, y2 = y.split()
            offsets.append(y1)
            secrets.append((x, EncryptedFE(y2, "Party_{}".format(x))))

        # If we stopped at this point, the DC could increment the counter
        # by incrementing each of the unencrypted share-shares.  But that's
        # inefficient: we want counter increments to be super fast!  So
        # we pick some random z to be our counter, and subtract z from each
        # of our unencrypted share-shares.  Now, we just increment z whenever
        # we want to increment the counter.  We will add z back into each
        # of the unencrypted share-shares before transmitting it.
        z = FE.random()
        offsets = [ y - z for y in offsets ]

        self._name = name
        self._threshold = threshold
        self._n_shares = n_shares
        self._offsets = offsets
        self._secrets = secrets
        self._z = z

    def inc(self, n):
        self._z += FE(n)

    def finalize(self):
        """
        Return the shares for this counter, as a ClientCounterShare
        """
        result = [ ]
        for off, (x, sec) in zip(self._offsets, self._secrets):
            result.append(ClientCounterShare(name=self._name,
                                             x=x,
                                             y1=(off + self._z),
                                             ey2=sec))
        return result

class ClientCounterShare(object):
    """A share of a single counter, as reported by a DC to a single
       TR.
    """
    def __init__(self, name, x, y1, ey2):
        self._name = name
        self._x = x
        self._y1 = y1
        self._ey2 = ey2

    def __repr__(self):
        return "ClientCounterShare({}, {}, {}, {})".format(
            self._name, self._x, self._y1, self._ey2)


    def decrypt(self):
        """Decrypt a ClientCounterShare.  This operation is performed at
           the TR, who is the only one that knows the key to
           decrypt ey2."""
        return CounterShare(self._name,
                            self._x,
                            self._y1 + self._ey2.decrypt())

class CounterShare(object):
    """A single share of a single counter, as decrypted at a TR."""
    def __init__(self, name, x, y):
        self._name = name
        self._x = x
        self._y = y

    def __repr__(self):
        return "CounterShare({}, {}, {})".format(
            self._name, self._x, self._y)

    def __add__(self, rhs):
        if self._name != rhs._name or self._x != rhs._x:
            raise ValueError()
        return CounterShare(self._name, self._x, self._y + rhs._y)


def interpolate(shares):
    """
    Given a set of exactly 'threshold' CounterShares from the same
    counter, interpolate the original polynomial and find its y
    intercept.

    >>> p = Polynomial([FE(1234), FE(56), FE(78), FE(1238189)])
    >>> shares = [ CounterShare("t", FE(x), p.evaluate_at(FE(x)))
    ...             for x in range(1, 5) ]
    >>> len(shares)
    4
    >>> interpolate(shares)
    FE(1234)

    """

    xs = set()

    for sh in shares:
        if sh._name != shares[0]._name:
            raise ValueError()
        if sh._x in xs:
            raise ValueError()
        xs.add(sh._x)

    accumulator = FE(0)
    for sh in shares:
        product_num = FE(1)
        product_denom = FE(1)
        for sh2 in shares:
            if sh2 is sh:
                continue
            product_num *= sh2._x
            product_denom *= (sh2._x - sh._x)

        accumulator += (sh._y * product_num) / product_denom

    return accumulator

def xsum(iterable):
    """
    Like sum(), but requires an input with at least one element, and doesn't
    take a 0 element.

    >>> xsum([FE(1), FE(2), FE(100)])
    FE(103)
    """
    it = iter(iterable)
    first = it.__next__()
    return sum(it, first)

def example(threshold, n_shares):
    """
    Demonstrate privcount, using 2 clients, and threshold/n_shares
    secret splitting.
    """
    # DC 1 creates a counter, and adds 10 to it.
    client1_c = Counter("cells", threshold=threshold, n_shares=n_shares)
    client1_c.inc(10)
    client1_shares = client1_c.finalize()

    # DC 2 creates a counter and adds 1000 to it.
    client2_c = Counter("cells", threshold=threshold, n_shares=n_shares)
    client2_c.inc(990)
    client2_c.inc(9)
    client2_c.inc(1)
    client2_shares = client2_c.finalize()

    # Each TR adds up all the shares it got for each counter:
    # So TR 1 adds its shares for client1 and client2,
    #    TR 2 adds its shares for client1 and client2, and so on.
    tr_shares = zip(client1_shares, client2_shares)
    published_added_shares = []
    for myshares in tr_shares:
        # Each TR performs one of these.
        published_added_shares.append(xsum(cs.decrypt() for cs in myshares))

    # Finally, some random subset of the TRs can reconstruct the sum of
    # c1's counter and c2's counter.
    import random
    random.shuffle(published_added_shares)
    input_shares = published_added_shares[:threshold]

    result = interpolate(input_shares)

    return result

if __name__ == '__main__':
    import doctest
    doctest.testmod()

    if example(3,6) == FE(1010):
        print("Yup, it worked.")
    else:
        print("Error: reconstruction didn't give us a good result.")

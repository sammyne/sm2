package sm2

// References:
//   [HAC]: Handbook of Applied Cryptography Menezes, van Oorschot, Vanstone.
//     http://cacr.uwaterloo.ca/hac/

// All elliptic curve operations for sm2 are done in a finite field
// characterized by a 256-bit prime.  Given this precision is larger than the
// biggest available native type, obviously some form of bignum math is needed.
// This package implements specialized fixed-precision field arithmetic rather
// than relying on an arbitrary-precision arithmetic package such as math/big
// for dealing with the field math since the size is known.  As a result, rather
// large performance gains are achieved by taking advantage of many
// optimizations not available to arbitrary-precision arithmetic and generic
// modular arithmetic algorithms.
//
// There are various ways to internally represent each finite field element.
// For example, the most obvious representation would be to use an array of 4
// uint64s (64 bits * 4 = 256 bits).  However, that representation suffers from
// a couple of issues.  First, there is no native Go type large enough to handle
// the intermediate results while adding or multiplying two 64-bit numbers, and
// second there is no space left for overflows when performing the intermediate
// arithmetic between each array element which would lead to expensive carry
// propagation.
//
// Given the above, this implementation represents the the field elements as
// 10 uint32s with each word (array entry) treated as base 2^26.  This was
// chosen for the following reasons:
// 1) Most systems at the current time are 64-bit (or at least have 64-bit
//    registers available for specialized purposes such as MMX) so the
//    intermediate results can typically be done using a native register (and
//    using uint64s to avoid the need for additional half-word arithmetic)
// 2) In order to allow addition of the internal words without having to
//    propagate the the carry, the max normalized value for each register must
//    be less than the number of bits available in the register
// 3) Since we're dealing with 32-bit values, 64-bits of overflow is a
//    reasonable choice for #2
// 4) Given the need for 256-bits of precision and the properties stated in #1,
//    #2, and #3, the representation which best accommodates this is 10 uint32s
//    with base 2^26 (26 bits * 10 = 260 bits, so the final word only needs 22
//    bits) which leaves the desired 64 bits (32 * 10 = 320, 320 - 256 = 64) for
//    overflow
//
// Since it is so important that the field arithmetic is extremely fast for
// high performance crypto, this package does not perform any validation where
// it ordinarily would.  For example, some functions only give the correct
// result is the field is normalized and there is no checking to ensure it is.
// While I typically prefer to ensure all state and input is valid for most
// packages, this code is really only used internally and every extra check
// counts.

import (
	"encoding/hex"
)

// Constants used to make the code more readable.
const (
	twoBitsMask   = 0x3
	fourBitsMask  = 0xf
	sixBitsMask   = 0x3f
	eightBitsMask = 0xff
)

// Constants related to the field representation.
const (
	// fieldWords is the number of words used to internally represent the
	// 256-bit value.
	fieldWords = 10

	// fieldBase is the exponent used to form the numeric base of each word.
	// 2^(fieldBase*i) where i is the word position.
	fieldBase = 26

	// fieldOverflowBits is the minimum number of "overflow" bits for each
	// word in the field value.
	fieldOverflowBits = 32 - fieldBase

	// fieldBaseMask is the mask for the bits in each word needed to
	// represent the numeric base of each word (except the most significant
	// word).
	fieldBaseMask = (1 << fieldBase) - 1

	// fieldMSBBits is the number of bits in the most significant word used
	// to represent the value.
	fieldMSBBits = 256 - (fieldBase * (fieldWords - 1))

	// fieldMSBMask is the mask for the bits in the most significant word
	// needed to represent the value.
	fieldMSBMask = (1 << fieldMSBBits) - 1

	// fieldPrimeWordZero is word zero of the sm2 prime in the
	// internal field representation.  It is used during negation.
	fieldPrimeWordZero = 0x3fffc2f

	// fieldPrimeWordOne is word one of the sm2 prime in the
	// internal field representation.  It is used during negation.
	fieldPrimeWordOne = 0x3ffffbf

	fieldPrimeWord2 = 0x0000fff
	fieldPrimeWord3 = 0x3fc0000
	fieldPrimeWord8 = 0x3feffff

	fieldCWord0 = 0x0000001
	fieldCWord2 = 0x3fff000
	fieldCWord3 = 0x003ffff
	fieldCWord8 = 0x0010000
)

// fieldVal implements optimized fixed-precision arithmetic over the
// sm2 finite field.  This means all arithmetic is performed modulo
// 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f.  It
// represents each 256-bit value as 10 32-bit integers in base 2^26.  This
// provides 6 bits of overflow in each word (10 bits in the most significant
// word) for a total of 64 bits of overflow (9*6 + 10 = 64).  It only implements
// the arithmetic needed for elliptic curve operations.
//
// The following depicts the internal representation:
// 	 -----------------------------------------------------------------
// 	|        n[9]       |        n[8]       | ... |        n[0]       |
// 	| 32 bits available | 32 bits available | ... | 32 bits available |
// 	| 22 bits for value | 26 bits for value | ... | 26 bits for value |
// 	| 10 bits overflow  |  6 bits overflow  | ... |  6 bits overflow  |
// 	| Mult: 2^(26*9)    | Mult: 2^(26*8)    | ... | Mult: 2^(26*0)    |
// 	 -----------------------------------------------------------------
//
// For example, consider the number 2^49 + 1.  It would be represented as:
// 	n[0] = 1
// 	n[1] = 2^23
// 	n[2..9] = 0
//
// The full 256-bit value is then calculated by looping i from 9..0 and
// doing sum(n[i] * 2^(26i)) like so:
// 	n[9] * 2^(26*9) = 0    * 2^234 = 0
// 	n[8] * 2^(26*8) = 0    * 2^208 = 0
// 	...
// 	n[1] * 2^(26*1) = 2^23 * 2^26  = 2^49
// 	n[0] * 2^(26*0) = 1    * 2^0   = 1
// 	Sum: 0 + 0 + ... + 2^49 + 1 = 2^49 + 1
type fieldVal struct {
	n [10]uint32
}

// Add adds the passed value to the existing field value and stores the result
// in f.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.Add(f2).AddInt(1) so that f = f + f2 + 1.
func (f *fieldVal) Add(val *fieldVal) *fieldVal {
	// Since the field representation intentionally provides overflow bits,
	// it's ok to use carryless addition as the carry bit is safely part of
	// each word and will be normalized out.  This could obviously be done
	// in a loop, but the unrolled version is faster.
	f.n[0] += val.n[0]
	f.n[1] += val.n[1]
	f.n[2] += val.n[2]
	f.n[3] += val.n[3]
	f.n[4] += val.n[4]
	f.n[5] += val.n[5]
	f.n[6] += val.n[6]
	f.n[7] += val.n[7]
	f.n[8] += val.n[8]
	f.n[9] += val.n[9]

	return f
}

// AddInt adds the passed integer to the existing field value and stores the
// result in f.  This is a convenience function since it is fairly common to
// perform some arithemetic with small native integers.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.AddInt(1).Add(f2) so that f = f + 1 + f2.
func (f *fieldVal) AddInt(ui uint) *fieldVal {
	// Since the field representation intentionally provides overflow bits,
	// it's ok to use carryless addition as the carry bit is safely part of
	// the word and will be normalized out.
	f.n[0] += uint32(ui)

	return f
}

// Add2 adds the passed two field values together and stores the result in f.
//
// The field value is returned to support chaining.  This enables syntax like:
// f3.Add2(f, f2).AddInt(1) so that f3 = f + f2 + 1.
func (f *fieldVal) Add2(val *fieldVal, val2 *fieldVal) *fieldVal {
	// Since the field representation intentionally provides overflow bits,
	// it's ok to use carryless addition as the carry bit is safely part of
	// each word and will be normalized out.  This could obviously be done
	// in a loop, but the unrolled version is faster.
	f.n[0] = val.n[0] + val2.n[0]
	f.n[1] = val.n[1] + val2.n[1]
	f.n[2] = val.n[2] + val2.n[2]
	f.n[3] = val.n[3] + val2.n[3]
	f.n[4] = val.n[4] + val2.n[4]
	f.n[5] = val.n[5] + val2.n[5]
	f.n[6] = val.n[6] + val2.n[6]
	f.n[7] = val.n[7] + val2.n[7]
	f.n[8] = val.n[8] + val2.n[8]
	f.n[9] = val.n[9] + val2.n[9]

	return f
}

// Bytes unpacks the field value to a 32-byte big-endian value.  See PutBytes
// for a variant that allows the a buffer to be passed which can be useful to
// to cut down on the number of allocations by allowing the caller to reuse a
// buffer.
//
// The field value must be normalized for this function to return correct
// result.
func (f *fieldVal) Bytes() *[32]byte {
	b := new([32]byte)
	f.PutBytes(b)
	return b
}

// Equals returns whether or not the two field values are the same.  Both
// field values being compared must be normalized for this function to return
// the correct result.
func (f *fieldVal) Equals(val *fieldVal) bool {
	// Xor only sets bits when they are different, so the two field values
	// can only be the same if no bits are set after xoring each word.
	// This is a constant time implementation.
	bits := (f.n[0] ^ val.n[0]) | (f.n[1] ^ val.n[1]) | (f.n[2] ^ val.n[2]) |
		(f.n[3] ^ val.n[3]) | (f.n[4] ^ val.n[4]) | (f.n[5] ^ val.n[5]) |
		(f.n[6] ^ val.n[6]) | (f.n[7] ^ val.n[7]) | (f.n[8] ^ val.n[8]) |
		(f.n[9] ^ val.n[9])

	return bits == 0
}

// Inverse finds the modular multiplicative inverse of the field value.  The
// existing field value is modified.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.Inverse().Mul(f2) so that f = f^-1 * f2.
func (f *fieldVal) Inverse() *fieldVal {
	// Fermat's little theorem states that for a nonzero number a and prime
	// prime p, a^(p-1) = 1 (mod p).  Since the multipliciative inverse is
	// a*b = 1 (mod p), it follows that b = a*a^(p-2) = a^(p-1) = 1 (mod p).
	// Thus, a^(p-2) is the multiplicative inverse.
	//
	// In order to efficiently compute a^(p-2), p-2 needs to be split into
	// a sequence of squares and multipications that minimizes the number of
	// multiplications needed (since they are more costly than squarings).
	// Intermediate results are saved and reused as well.
	//
	// The sm2 prime - 2 is 2^256 - 4294968275.
	//
	// This has a cost of 258 field squarings and 33 field multiplications.
	var a2, a3, a4, a10, a11, a21, a42, a45, a63, a1019, a1023 fieldVal
	a2.SquareVal(f)
	a3.Mul2(&a2, f)
	a4.SquareVal(&a2)
	a10.SquareVal(&a4).Mul(&a2)
	a11.Mul2(&a10, f)
	a21.Mul2(&a10, &a11)
	a42.SquareVal(&a21)
	a45.Mul2(&a42, &a3)
	a63.Mul2(&a42, &a21)
	a1019.SquareVal(&a63).Square().Square().Square().Mul(&a11)
	a1023.Mul2(&a1019, &a4)
	f.Set(&a63)                                    // f = a^(2^6 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^11 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^16 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^16 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^21 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^26 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^26 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^31 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^36 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^36 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^41 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^46 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^46 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^51 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^56 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^56 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^61 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^66 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^66 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^71 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^76 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^76 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^81 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^86 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^86 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^91 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^96 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^96 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^101 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^106 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^106 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^111 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^116 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^116 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^121 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^126 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^126 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^131 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^136 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^136 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^141 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^146 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^146 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^151 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^156 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^156 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^161 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^166 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^166 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^171 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^176 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^176 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^181 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^186 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^186 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^191 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^196 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^196 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^201 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^206 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^206 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^211 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^216 - 1024)
	f.Mul(&a1023)                                  // f = a^(2^216 - 1)
	f.Square().Square().Square().Square().Square() // f = a^(2^221 - 32)
	f.Square().Square().Square().Square().Square() // f = a^(2^226 - 1024)
	f.Mul(&a1019)                                  // f = a^(2^226 - 5)
	f.Square().Square().Square().Square().Square() // f = a^(2^231 - 160)
	f.Square().Square().Square().Square().Square() // f = a^(2^236 - 5120)
	f.Mul(&a1023)                                  // f = a^(2^236 - 4097)
	f.Square().Square().Square().Square().Square() // f = a^(2^241 - 131104)
	f.Square().Square().Square().Square().Square() // f = a^(2^246 - 4195328)
	f.Mul(&a1023)                                  // f = a^(2^246 - 4194305)
	f.Square().Square().Square().Square().Square() // f = a^(2^251 - 134217760)
	f.Square().Square().Square().Square().Square() // f = a^(2^256 - 4294968320)
	return f.Mul(&a45)                             // f = a^(2^256 - 4294968275) = a^(p-2)
}

// IsOdd returns whether or not the field value is an odd number.
//
// The field value must be normalized for this function to return correct
// result.
func (f *fieldVal) IsOdd() bool {
	// Only odd numbers have the bottom bit set.
	return f.n[0]&1 == 1
}

// IsZero returns whether or not the field value is equal to zero.
func (f *fieldVal) IsZero() bool {
	// The value can only be zero if no bits are set in any of the words.
	// This is a constant time implementation.
	bits := f.n[0] | f.n[1] | f.n[2] | f.n[3] | f.n[4] |
		f.n[5] | f.n[6] | f.n[7] | f.n[8] | f.n[9]

	return bits == 0
}

// Mul multiplies the passed value to the existing field value and stores the
// result in f.  Note that this function can overflow if multiplying any
// of the individual words exceeds a max uint32.  In practice, this means the
// magnitude of either value involved in the multiplication must be a max of
// 8.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.Mul(f2).AddInt(1) so that f = (f * f2) + 1.
func (f *fieldVal) Mul(val *fieldVal) *fieldVal {
	return f.Mul2(f, val)
}

// MulInt multiplies the field value by the passed int and stores the result in
// f.  Note that this function can overflow if multiplying the value by any of
// the individual words exceeds a max uint32.  Therefore it is important that
// the caller ensures no overflows will occur before using this function.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.MulInt(2).Add(f2) so that f = 2 * f + f2.
func (f *fieldVal) MulInt(val uint) *fieldVal {
	// Since each word of the field representation can hold up to
	// fieldOverflowBits extra bits which will be normalized out, it's safe
	// to multiply each word without using a larger type or carry
	// propagation so long as the values won't overflow a uint32.  This
	// could obviously be done in a loop, but the unrolled version is
	// faster.
	ui := uint32(val)
	f.n[0] *= ui
	f.n[1] *= ui
	f.n[2] *= ui
	f.n[3] *= ui
	f.n[4] *= ui
	f.n[5] *= ui
	f.n[6] *= ui
	f.n[7] *= ui
	f.n[8] *= ui
	f.n[9] *= ui

	return f
}

// Mul2 multiplies the passed two field values together and stores the result
// result in f.  Note that this function can overflow if multiplying any of
// the individual words exceeds a max uint32.  In practice, this means the
// magnitude of either value involved in the multiplication must be a max of
// 8.
//
// The field value is returned to support chaining.  This enables syntax like:
// f3.Mul2(f, f2).AddInt(1) so that f3 = (f * f2) + 1.
func (f *fieldVal) Mul2(val *fieldVal, val2 *fieldVal) *fieldVal {
	// This could be done with a couple of for loops and an array to store
	// the intermediate terms, but this unrolled version is significantly
	// faster.

	// Terms for 2^(fieldBase*0).
	m := uint64(val.n[0]) * uint64(val2.n[0])
	t0 := m & fieldBaseMask

	// Terms for 2^(fieldBase*1).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[1]) +
		uint64(val.n[1])*uint64(val2.n[0])
	t1 := m & fieldBaseMask

	// Terms for 2^(fieldBase*2).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[2]) +
		uint64(val.n[1])*uint64(val2.n[1]) +
		uint64(val.n[2])*uint64(val2.n[0])
	t2 := m & fieldBaseMask

	// Terms for 2^(fieldBase*3).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[3]) +
		uint64(val.n[1])*uint64(val2.n[2]) +
		uint64(val.n[2])*uint64(val2.n[1]) +
		uint64(val.n[3])*uint64(val2.n[0])
	t3 := m & fieldBaseMask

	// Terms for 2^(fieldBase*4).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[4]) +
		uint64(val.n[1])*uint64(val2.n[3]) +
		uint64(val.n[2])*uint64(val2.n[2]) +
		uint64(val.n[3])*uint64(val2.n[1]) +
		uint64(val.n[4])*uint64(val2.n[0])
	t4 := m & fieldBaseMask

	// Terms for 2^(fieldBase*5).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[5]) +
		uint64(val.n[1])*uint64(val2.n[4]) +
		uint64(val.n[2])*uint64(val2.n[3]) +
		uint64(val.n[3])*uint64(val2.n[2]) +
		uint64(val.n[4])*uint64(val2.n[1]) +
		uint64(val.n[5])*uint64(val2.n[0])
	t5 := m & fieldBaseMask

	// Terms for 2^(fieldBase*6).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[6]) +
		uint64(val.n[1])*uint64(val2.n[5]) +
		uint64(val.n[2])*uint64(val2.n[4]) +
		uint64(val.n[3])*uint64(val2.n[3]) +
		uint64(val.n[4])*uint64(val2.n[2]) +
		uint64(val.n[5])*uint64(val2.n[1]) +
		uint64(val.n[6])*uint64(val2.n[0])
	t6 := m & fieldBaseMask

	// Terms for 2^(fieldBase*7).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[7]) +
		uint64(val.n[1])*uint64(val2.n[6]) +
		uint64(val.n[2])*uint64(val2.n[5]) +
		uint64(val.n[3])*uint64(val2.n[4]) +
		uint64(val.n[4])*uint64(val2.n[3]) +
		uint64(val.n[5])*uint64(val2.n[2]) +
		uint64(val.n[6])*uint64(val2.n[1]) +
		uint64(val.n[7])*uint64(val2.n[0])
	t7 := m & fieldBaseMask

	// Terms for 2^(fieldBase*8).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[8]) +
		uint64(val.n[1])*uint64(val2.n[7]) +
		uint64(val.n[2])*uint64(val2.n[6]) +
		uint64(val.n[3])*uint64(val2.n[5]) +
		uint64(val.n[4])*uint64(val2.n[4]) +
		uint64(val.n[5])*uint64(val2.n[3]) +
		uint64(val.n[6])*uint64(val2.n[2]) +
		uint64(val.n[7])*uint64(val2.n[1]) +
		uint64(val.n[8])*uint64(val2.n[0])
	t8 := m & fieldBaseMask

	// Terms for 2^(fieldBase*9).
	m = (m >> fieldBase) +
		uint64(val.n[0])*uint64(val2.n[9]) +
		uint64(val.n[1])*uint64(val2.n[8]) +
		uint64(val.n[2])*uint64(val2.n[7]) +
		uint64(val.n[3])*uint64(val2.n[6]) +
		uint64(val.n[4])*uint64(val2.n[5]) +
		uint64(val.n[5])*uint64(val2.n[4]) +
		uint64(val.n[6])*uint64(val2.n[3]) +
		uint64(val.n[7])*uint64(val2.n[2]) +
		uint64(val.n[8])*uint64(val2.n[1]) +
		uint64(val.n[9])*uint64(val2.n[0])
	t9 := m & fieldBaseMask

	// Terms for 2^(fieldBase*10).
	m = (m >> fieldBase) +
		uint64(val.n[1])*uint64(val2.n[9]) +
		uint64(val.n[2])*uint64(val2.n[8]) +
		uint64(val.n[3])*uint64(val2.n[7]) +
		uint64(val.n[4])*uint64(val2.n[6]) +
		uint64(val.n[5])*uint64(val2.n[5]) +
		uint64(val.n[6])*uint64(val2.n[4]) +
		uint64(val.n[7])*uint64(val2.n[3]) +
		uint64(val.n[8])*uint64(val2.n[2]) +
		uint64(val.n[9])*uint64(val2.n[1])
	t10 := m & fieldBaseMask

	// Terms for 2^(fieldBase*11).
	m = (m >> fieldBase) +
		uint64(val.n[2])*uint64(val2.n[9]) +
		uint64(val.n[3])*uint64(val2.n[8]) +
		uint64(val.n[4])*uint64(val2.n[7]) +
		uint64(val.n[5])*uint64(val2.n[6]) +
		uint64(val.n[6])*uint64(val2.n[5]) +
		uint64(val.n[7])*uint64(val2.n[4]) +
		uint64(val.n[8])*uint64(val2.n[3]) +
		uint64(val.n[9])*uint64(val2.n[2])
	t11 := m & fieldBaseMask

	// Terms for 2^(fieldBase*12).
	m = (m >> fieldBase) +
		uint64(val.n[3])*uint64(val2.n[9]) +
		uint64(val.n[4])*uint64(val2.n[8]) +
		uint64(val.n[5])*uint64(val2.n[7]) +
		uint64(val.n[6])*uint64(val2.n[6]) +
		uint64(val.n[7])*uint64(val2.n[5]) +
		uint64(val.n[8])*uint64(val2.n[4]) +
		uint64(val.n[9])*uint64(val2.n[3])
	t12 := m & fieldBaseMask

	// Terms for 2^(fieldBase*13).
	m = (m >> fieldBase) +
		uint64(val.n[4])*uint64(val2.n[9]) +
		uint64(val.n[5])*uint64(val2.n[8]) +
		uint64(val.n[6])*uint64(val2.n[7]) +
		uint64(val.n[7])*uint64(val2.n[6]) +
		uint64(val.n[8])*uint64(val2.n[5]) +
		uint64(val.n[9])*uint64(val2.n[4])
	t13 := m & fieldBaseMask

	// Terms for 2^(fieldBase*14).
	m = (m >> fieldBase) +
		uint64(val.n[5])*uint64(val2.n[9]) +
		uint64(val.n[6])*uint64(val2.n[8]) +
		uint64(val.n[7])*uint64(val2.n[7]) +
		uint64(val.n[8])*uint64(val2.n[6]) +
		uint64(val.n[9])*uint64(val2.n[5])
	t14 := m & fieldBaseMask

	// Terms for 2^(fieldBase*15).
	m = (m >> fieldBase) +
		uint64(val.n[6])*uint64(val2.n[9]) +
		uint64(val.n[7])*uint64(val2.n[8]) +
		uint64(val.n[8])*uint64(val2.n[7]) +
		uint64(val.n[9])*uint64(val2.n[6])
	t15 := m & fieldBaseMask

	// Terms for 2^(fieldBase*16).
	m = (m >> fieldBase) +
		uint64(val.n[7])*uint64(val2.n[9]) +
		uint64(val.n[8])*uint64(val2.n[8]) +
		uint64(val.n[9])*uint64(val2.n[7])
	t16 := m & fieldBaseMask

	// Terms for 2^(fieldBase*17).
	m = (m >> fieldBase) +
		uint64(val.n[8])*uint64(val2.n[9]) +
		uint64(val.n[9])*uint64(val2.n[8])
	t17 := m & fieldBaseMask

	// Terms for 2^(fieldBase*18).
	m = (m >> fieldBase) + uint64(val.n[9])*uint64(val2.n[9])
	t18 := m & fieldBaseMask

	// What's left is for 2^(fieldBase*19).
	t19 := m >> fieldBase

	// At this point, all of the terms are grouped into their respective
	// base.
	//
	// Per [HAC] section 14.3.4: Reduction method of moduli of special form,
	// when the modulus is of the special form m = b^t - c, highly efficient
	// reduction can be achieved per the provided algorithm.
	//
	// let cc = 0x0000000100000000000000000000000000000000ffffffff0000000000000001
	// The sm2 prime P = 2^256 - cc, so it fits this criteria.
	//
	// cc in field representation (base 2^26) is:
	// n[0] = 1
	// n[1] = 0
	// n[2] = 0x3fff000
	// n[3] = 0x3ffff
	// n[4] = 0
	// n[5] = 0
	// n[6] = 0
	// n[7] = 0
	// n[8] = 0x10000
	// n[9] = 0
	// That is to say
	// cc = 2^(26*8) * 0x10000 		+
	//		2^(26*3) * 0x3ffff 		+
	//		2^(26*2) * 0x3fff000 	+
	//		2^(26*0) * 1
	//
	// Since each word is in base 26, the upper terms (t10 and up) start
	// at 260 bits (versus the final desired range of 256 bits), so the
	// field representation of 'c' from above needs to be adjusted for the
	// extra 4 bits by multiplying it by 2^4 = 16.
	//
	// Suppose B=2^26, and let
	//	V=(v_i,v_(i-1),...,v_0)=v_i*B^i + v_(i-1)*B^(i-1) + ... + v_0
	// denote a base-B integer, and
	// 	T=(t19,t18,...,t0),
	//  q0=(t19,t18,...,t10).
	// Calculate
	//	 T - (q0<<4) * P
	// = T - q0 * ((2^256 - cc) << 4)
	// = T - q0 * B^10 + q0 * (cc << 4)
	// = (t9,t8,...,t0) + (q0 * cc)<<4
	// = (t9,t8,...,t0) + (q0 * (n[0] + n[2]*B^2 + n[3]*B^3 + n[8]*B^8))<<4
	// Further expansion would give calculation as follows.
	// @TODO: unroll the loop
	const bits = 4
	// output for each round
	// 0: t19<2^38
	// 1: t19<2^7
	// 2: t19=0, t18<2^4
	// 3: t19=t18=t17=0, t16<2^25
	// 4: t19=...=t16=0, t15<2^20
	// 5: t19=...=t15=0, t14<2^15
	// 6: t19=...=t14=0, t13<2^10
	// 7: t19=...=t13=0, t12<2^5
	// 8: t19=...=t11=0, t10<2^26
	// 9: t19=...=t11=0, t10<=1
	for i := 1; i <= 9; i++ {
		// each d is at most 56 bits
		d := t0 + (t10*fieldCWord0)<<bits
		t0 = d & fieldBaseMask
		d = d>>fieldBase + t1 + (t11*fieldCWord0)<<bits
		t1 = d & fieldBaseMask
		d = d>>fieldBase + t2 + (t12*fieldCWord0+t10*fieldCWord2)<<bits
		t2 = d & fieldBaseMask
		d = d>>fieldBase + t3 + (t13*fieldCWord0+t11*fieldCWord2+t10*fieldCWord3)<<bits
		t3 = d & fieldBaseMask
		d = d>>fieldBase + t4 + (t14*fieldCWord0+t12*fieldCWord2+t11*fieldCWord3)<<bits
		t4 = d & fieldBaseMask
		d = d>>fieldBase + t5 + (t15*fieldCWord0+t13*fieldCWord2+t12*fieldCWord3)<<bits
		t5 = d & fieldBaseMask
		d = d>>fieldBase + t6 + (t16*fieldCWord0+t14*fieldCWord2+t13*fieldCWord3)<<bits
		t6 = d & fieldBaseMask
		d = d>>fieldBase + t7 + (t17*fieldCWord0+t15*fieldCWord2+t14*fieldCWord3)<<bits
		t7 = d & fieldBaseMask
		d = d>>fieldBase + t8 +
			(t18*fieldCWord0+t16*fieldCWord2+t15*fieldCWord3+t10*fieldCWord8)<<bits
		t8 = d & fieldBaseMask
		d = d>>fieldBase + t9 +
			(t19*fieldCWord0+t17*fieldCWord2+t16*fieldCWord3+t11*fieldCWord8)<<bits
		t9 = d & fieldBaseMask
		d = d>>fieldBase + (t18*fieldCWord2+t17*fieldCWord3+t12*fieldCWord8)<<bits
		t10 = d & fieldBaseMask
		d = d>>fieldBase + (t19*fieldCWord2+t18*fieldCWord3+t13*fieldCWord8)<<bits
		t11 = d & fieldBaseMask
		d = d>>fieldBase + (t19*fieldCWord3+t14*fieldCWord8)<<bits
		t12 = d & fieldBaseMask
		d = d>>fieldBase + (t15*fieldCWord8)<<bits
		t13 = d & fieldBaseMask
		d = d>>fieldBase + (t16*fieldCWord8)<<bits
		t14 = d & fieldBaseMask
		d = d>>fieldBase + (t17*fieldCWord8)<<bits
		t15 = d & fieldBaseMask
		d = d>>fieldBase + (t18*fieldCWord8)<<bits
		t16 = d & fieldBaseMask
		d = d>>fieldBase + (t19*fieldCWord8)<<bits
		t17 = d & fieldBaseMask
		d = d >> fieldBase
		t18 = d & fieldBaseMask
		d = d >> fieldBase
		t19 = d & fieldBaseMask
	}
	m = (t9 >> fieldMSBBits) | (t10 << bits) // m<2^5
	t9 &= fieldMSBMask

	// At this point, if the magnitude is greater than 0, the overall value
	// is greater than the max possible 256-bit value.  In particular, it is
	// "how many times larger" than the max value it is.
	//
	// The algorithm presented in [HAC] section 14.3.4 repeats until the
	// quotient is zero.  However, due to the above, we already know at
	// least how many times we would need to repeat as it's the value
	// currently in m.  Thus we can simply multiply the magnitude by the
	// field representation of the prime and do a single iteration.  Notice
	// that nothing will be changed when the magnitude is zero, so we could
	// skip this in that case, however always running regardless allows it
	// to run in constant time.  The final result will be in the range
	// ~~0 <= result <= prime + (2^64 - c)~~, so it is guaranteed to have a
	// magnitude of 1, but it is denormalized.
	f.n[0] = uint32(t0 + m)
	f.n[1] = uint32(t1)
	f.n[2] = uint32(t2 + m*fieldCWord2) // m*fieldCWord2 < 2^5 * 2^26 = 2^31
	f.n[3] = uint32(t3 + m*fieldCWord3) // m*fieldCWord3 < 2^5 * 2^18 = 2^23
	f.n[4] = uint32(t4)
	f.n[5] = uint32(t5)
	f.n[6] = uint32(t6)
	f.n[7] = uint32(t7)
	f.n[8] = uint32(t8 + m<<16) // m*fieldCWord8 = m<<16, m*fieldCWord8 < 2^5 * 2^16 = 2^21
	f.n[9] = uint32(t9)

	return f
}

// Negate negates the field value.  The existing field value is modified.  The
// caller must provide the magnitude of the field value for a correct result.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.Negate().AddInt(1) so that f = -f + 1.
func (f *fieldVal) Negate(magnitude uint32) *fieldVal {
	return f.NegateVal(f, magnitude)
}

// NegateVal negates the passed value and stores the result in f.  The caller
// must provide the magnitude of the passed value for a correct result.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.NegateVal(f2).AddInt(1) so that f = -f2 + 1.
// @dev what if overflow due to multiplication.
// @dev val should have been normalized.
func (f *fieldVal) NegateVal(val *fieldVal, magnitude uint32) *fieldVal {
	// Negation in the field is just the prime minus the value.  However,
	// in order to allow negation against a field value without having to
	// normalize/reduce it first, multiply by the magnitude (that is how
	// "far" away it is from the normalized value) to adjust.  Also, since
	// negating a value pushes it one more order of magnitude away from the
	// normalized range, add 1 to compensate.
	//
	// For some intuition here, imagine you're performing mod 12 arithmetic
	// (picture a clock) and you are negating the number 7.  So you start at
	// 12 (which is of course 0 under mod 12) and count backwards (left on
	// the clock) 7 times to arrive at 5.  Notice this is just 12-7 = 5.
	// Now, assume you're starting with 19, which is a number that is
	// already larger than the modulus and congruent to 7 (mod 12).  When a
	// value is already in the desired range, its magnitude is 1.  Since 19
	// is an additional "step", its magnitude (mod 12) is 2.  Since any
	// multiple of the modulus is conguent to zero (mod m), the answer can
	// be shortcut by simply mulplying the magnitude by the modulus and
	// subtracting.  Keeping with the example, this would be (2*12)-19 = 5.

	f.n[0] = (magnitude+1)*fieldBaseMask - val.n[0]
	f.n[1] = (magnitude+1)*fieldBaseMask - val.n[1]
	// borrow 2^26 from higher word to avoid **underflow**
	f.n[2] = (1 << fieldBase) + (magnitude+1)*fieldPrimeWord2 - val.n[2]
	// to borrow from higher word to avoid underflow, we should add 2^26
	// to compensate for borrowing by lower word, we should subtract 1.
	// totally, we should add borrow-1=fieldBaseMask
	f.n[3] = fieldBaseMask + (magnitude+1)*fieldPrimeWord3 - val.n[3]
	f.n[4] = fieldBaseMask + (magnitude+1)*fieldBaseMask - val.n[4]
	f.n[5] = fieldBaseMask + (magnitude+1)*fieldBaseMask - val.n[5]
	f.n[6] = fieldBaseMask + (magnitude+1)*fieldBaseMask - val.n[6]
	f.n[7] = fieldBaseMask + (magnitude+1)*fieldBaseMask - val.n[7]
	f.n[8] = fieldBaseMask + (magnitude+1)*fieldPrimeWord8 - val.n[8]
	// sadly, the most significant word have no one to borrow,
	// and need to pay for the borrow by the 8th word
	f.n[9] = (magnitude+1)*fieldMSBMask - val.n[9] - 1

	return f
}

// Normalize normalizes the internal field words into the desired range and
// performs fast modular reduction over the sm2 prime by making use of the
// special form of the prime.
func (f *fieldVal) Normalize() *fieldVal {
	// The field representation leaves 6 bits of overflow in each word so
	// intermediate calculations can be performed without needing to
	// propagate the carry to each higher word during the calculations.  In
	// order to normalize, we need to "compact" the full 256-bit value to
	// the right while propagating any carries through to the high order
	// word.
	//
	// Since this field is doing arithmetic modulo the sm2 prime, we
	// also need to perform modular reduction over the prime.
	//
	// Per [HAC] section 14.3.4: Reduction method of moduli of special form,
	// when the modulus is of the special form m = b^t - c, highly efficient
	// reduction can be achieved.
	//
	// let cc = 0x0000000100000000000000000000000000000000ffffffff0000000000000001
	// The sm2 prime is equivalent to 2^256 - cc, so it fits
	// this criteria.
	//
	// cc in field representation (base 2^26) is:
	// n[0] = 1
	// n[1] = 0
	// n[2] = 0x3fff000
	// n[3] = 0x3ffff
	// n[4] = 0
	// n[5] = 0
	// n[6] = 0
	// n[7] = 0
	// n[8] = 0x10000
	// n[9] = 0
	// That is to say
	// cc = 2^(26*8) * 0x10000 		+
	//		2^(26*3) * 0x3ffff 		+
	//		2^(26*2) * 0x3fff000 	+
	//		2^(26*0) * 1
	//
	// The algorithm presented in the referenced section typically repeats
	// until the quotient is zero.  However, due to our field representation
	// we already know to within one reduction how many times we would need
	// to repeat as it's the uppermost bits of the high order word.  Thus we
	// can simply multiply the magnitude by the field representation of the
	// prime and do a single iteration.  After this step there might be an
	// additional carry to bit 256 (bit 22 of the high order word).
	t9 := f.n[9]
	m := t9 >> fieldMSBBits
	t9 = t9 & fieldMSBMask

	// d takes uint64 to address the overflow
	d := uint64(f.n[0]) + uint64(m)
	t0 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[1])
	t1 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[2]) + uint64(m)*fieldCWord2
	t2 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[3]) + uint64(m)*fieldCWord3
	t3 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[4])
	t4 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[5])
	t5 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[6])
	t6 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[7])
	t7 := uint32(d & fieldBaseMask)
	d = (d >> fieldBase) + uint64(f.n[8]) + uint64(m)*fieldCWord8
	t8 := uint32(d & fieldBaseMask)
	t9 = uint32(d>>fieldBase) + t9 // at most carry 1 here

	// At this point, the magnitude is guaranteed to be one or two, however, the
	// value could still be greater than the prime if there was either a
	// carry through to bit 256 (bit 22 of the higher order word) or the
	// value is greater than or equal to the field characteristic.  The
	// following determines if either or these conditions are true and does
	// the final reduction in constant time.
	//
	// Note that the if/else statements here intentionally do the bitwise
	// operators even when it won't change the value to ensure constant time
	// between the branches.  Also note that 'm' will be zero when neither
	// of the aforementioned conditions are true and the value will not be
	// changed when 'm' is zero.
	m = 1
	if t9 == fieldMSBMask {
		m &= 1
	} else {
		m &= 0
	}

	{
		c := (t0 + fieldCWord0) >> fieldBase
		c = (c + t1) >> fieldBase
		c = (c + t2 + fieldCWord2) >> fieldBase
		c = (c + t3 + fieldCWord3) >> fieldBase
		c = (c + t4) >> fieldBase
		c = (c + t5) >> fieldBase
		c = (c + t6) >> fieldBase
		c = (c + t7) >> fieldBase

		if c+t8+fieldCWord8 > fieldBaseMask {
			m &= 1
		} else {
			m &= 0
		}
	}

	if t9>>fieldMSBBits != 0 {
		m |= 1
	} else {
		m |= 0
	}

	// After all checks above, let
	//	r  = t9*2^(26*9)+t8*2^(26*8)+...+t0,
	// 	P  = 2^256-c be the sm2 prime, where c < 2^225
	//  m' = m at the **beginning** of the 1st reduction derived by (t9 >> fieldMSBBits),
	//		we should have m'<2^10 since at most 10 bits left for overflow in the 9th word of f
	// If m = 0, then r < P (i.e. sm2 prime).
	// If m = 1, then P < T < 2^256+m'c < 2^256+2^235 < 2^256+2^256-2^226 < 2*(2^256-c) = 2*P.
	// So we just need calculate T-P=T+c-2^256 if m=1.

	t0 = t0 + m
	t1 = (t0 >> fieldBase) + t1
	t0 = t0 & fieldBaseMask
	t2 = (t1 >> fieldBase) + t2 + m*fieldCWord2
	t1 = t1 & fieldBaseMask
	t3 = (t2 >> fieldBase) + t3 + m*fieldCWord3
	t2 = t2 & fieldBaseMask
	t4 = (t3 >> fieldBase) + t4
	t3 = t3 & fieldBaseMask
	t5 = (t4 >> fieldBase) + t5
	t4 = t4 & fieldBaseMask
	t6 = (t5 >> fieldBase) + t6
	t5 = t5 & fieldBaseMask
	t7 = (t6 >> fieldBase) + t7
	t6 = t6 & fieldBaseMask
	// m*fieldCWord8 = m<<16
	t8 = (t7 >> fieldBase) + t8 + (m << 16)
	t7 = t7 & fieldBaseMask
	t9 = (t8 >> fieldBase) + t9
	t8 = t8 & fieldBaseMask
	t9 = t9 & fieldMSBMask // Remove potential multiple of 2^256, equivalently to T-2^256.

	// Finally, set the normalized and reduced words.
	f.n[0] = t0
	f.n[1] = t1
	f.n[2] = t2
	f.n[3] = t3
	f.n[4] = t4
	f.n[5] = t5
	f.n[6] = t6
	f.n[7] = t7
	f.n[8] = t8
	f.n[9] = t9
	return f
}

// PutBytes unpacks the field value to a 32-byte big-endian value using the
// passed byte array.  There is a similar function, Bytes, which unpacks the
// field value into a new array and returns that.  This version is provided
// since it can be useful to cut down on the number of allocations by allowing
// the caller to reuse a buffer.
//
// The field value must be normalized for this function to return the correct
// result.
func (f *fieldVal) PutBytes(b *[32]byte) {
	// Unpack the 256 total bits from the 10 uint32 words with a max of
	// 26-bits per word.  This could be done with a couple of for loops,
	// but this unrolled version is a bit faster.  Benchmarks show this is
	// about 10 times faster than the variant which uses loops.
	b[31] = byte(f.n[0] & eightBitsMask)
	b[30] = byte((f.n[0] >> 8) & eightBitsMask)
	b[29] = byte((f.n[0] >> 16) & eightBitsMask)
	b[28] = byte((f.n[0]>>24)&twoBitsMask | (f.n[1]&sixBitsMask)<<2)
	b[27] = byte((f.n[1] >> 6) & eightBitsMask)
	b[26] = byte((f.n[1] >> 14) & eightBitsMask)
	b[25] = byte((f.n[1]>>22)&fourBitsMask | (f.n[2]&fourBitsMask)<<4)
	b[24] = byte((f.n[2] >> 4) & eightBitsMask)
	b[23] = byte((f.n[2] >> 12) & eightBitsMask)
	b[22] = byte((f.n[2]>>20)&sixBitsMask | (f.n[3]&twoBitsMask)<<6)
	b[21] = byte((f.n[3] >> 2) & eightBitsMask)
	b[20] = byte((f.n[3] >> 10) & eightBitsMask)
	b[19] = byte((f.n[3] >> 18) & eightBitsMask)
	b[18] = byte(f.n[4] & eightBitsMask)
	b[17] = byte((f.n[4] >> 8) & eightBitsMask)
	b[16] = byte((f.n[4] >> 16) & eightBitsMask)
	b[15] = byte((f.n[4]>>24)&twoBitsMask | (f.n[5]&sixBitsMask)<<2)
	b[14] = byte((f.n[5] >> 6) & eightBitsMask)
	b[13] = byte((f.n[5] >> 14) & eightBitsMask)
	b[12] = byte((f.n[5]>>22)&fourBitsMask | (f.n[6]&fourBitsMask)<<4)
	b[11] = byte((f.n[6] >> 4) & eightBitsMask)
	b[10] = byte((f.n[6] >> 12) & eightBitsMask)
	b[9] = byte((f.n[6]>>20)&sixBitsMask | (f.n[7]&twoBitsMask)<<6)
	b[8] = byte((f.n[7] >> 2) & eightBitsMask)
	b[7] = byte((f.n[7] >> 10) & eightBitsMask)
	b[6] = byte((f.n[7] >> 18) & eightBitsMask)
	b[5] = byte(f.n[8] & eightBitsMask)
	b[4] = byte((f.n[8] >> 8) & eightBitsMask)
	b[3] = byte((f.n[8] >> 16) & eightBitsMask)
	b[2] = byte((f.n[8]>>24)&twoBitsMask | (f.n[9]&sixBitsMask)<<2)
	b[1] = byte((f.n[9] >> 6) & eightBitsMask)
	b[0] = byte((f.n[9] >> 14) & eightBitsMask)
}

// Square squares the field value.  The existing field value is modified.  Note
// that this function can overflow if multiplying any of the individual words
// exceeds a max uint32.  In practice, this means the magnitude of the field
// must be a max of 8 to prevent overflow.
//
// The field value is returned to support chaining.  This enables syntax like:
// f.Square().Mul(f2) so that f = f^2 * f2.
func (f *fieldVal) Square() *fieldVal {
	return f.SquareVal(f)
}

// SquareVal squares the passed value and stores the result in f.  Note that
// this function can overflow if multiplying any of the individual words
// exceeds a max uint32.  In practice, this means the magnitude of the field
// being squred must be a max of 8 to prevent overflow.
//
// The field value is returned to support chaining.  This enables syntax like:
// f3.SquareVal(f).Mul(f) so that f3 = f^2 * f = f^3.
func (f *fieldVal) SquareVal(val *fieldVal) *fieldVal {
	// This could be done with a couple of for loops and an array to store
	// the intermediate terms, but this unrolled version is significantly
	// faster.

	// Terms for 2^(fieldBase*0).
	m := uint64(val.n[0]) * uint64(val.n[0])
	t0 := m & fieldBaseMask

	// Terms for 2^(fieldBase*1).
	m = (m >> fieldBase) + 2*uint64(val.n[0])*uint64(val.n[1])
	t1 := m & fieldBaseMask

	// Terms for 2^(fieldBase*2).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[2]) +
		uint64(val.n[1])*uint64(val.n[1])
	t2 := m & fieldBaseMask

	// Terms for 2^(fieldBase*3).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[3]) +
		2*uint64(val.n[1])*uint64(val.n[2])
	t3 := m & fieldBaseMask

	// Terms for 2^(fieldBase*4).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[4]) +
		2*uint64(val.n[1])*uint64(val.n[3]) +
		uint64(val.n[2])*uint64(val.n[2])
	t4 := m & fieldBaseMask

	// Terms for 2^(fieldBase*5).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[5]) +
		2*uint64(val.n[1])*uint64(val.n[4]) +
		2*uint64(val.n[2])*uint64(val.n[3])
	t5 := m & fieldBaseMask

	// Terms for 2^(fieldBase*6).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[6]) +
		2*uint64(val.n[1])*uint64(val.n[5]) +
		2*uint64(val.n[2])*uint64(val.n[4]) +
		uint64(val.n[3])*uint64(val.n[3])
	t6 := m & fieldBaseMask

	// Terms for 2^(fieldBase*7).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[7]) +
		2*uint64(val.n[1])*uint64(val.n[6]) +
		2*uint64(val.n[2])*uint64(val.n[5]) +
		2*uint64(val.n[3])*uint64(val.n[4])
	t7 := m & fieldBaseMask

	// Terms for 2^(fieldBase*8).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[8]) +
		2*uint64(val.n[1])*uint64(val.n[7]) +
		2*uint64(val.n[2])*uint64(val.n[6]) +
		2*uint64(val.n[3])*uint64(val.n[5]) +
		uint64(val.n[4])*uint64(val.n[4])
	t8 := m & fieldBaseMask

	// Terms for 2^(fieldBase*9).
	m = (m >> fieldBase) +
		2*uint64(val.n[0])*uint64(val.n[9]) +
		2*uint64(val.n[1])*uint64(val.n[8]) +
		2*uint64(val.n[2])*uint64(val.n[7]) +
		2*uint64(val.n[3])*uint64(val.n[6]) +
		2*uint64(val.n[4])*uint64(val.n[5])
	t9 := m & fieldBaseMask

	// Terms for 2^(fieldBase*10).
	m = (m >> fieldBase) +
		2*uint64(val.n[1])*uint64(val.n[9]) +
		2*uint64(val.n[2])*uint64(val.n[8]) +
		2*uint64(val.n[3])*uint64(val.n[7]) +
		2*uint64(val.n[4])*uint64(val.n[6]) +
		uint64(val.n[5])*uint64(val.n[5])
	t10 := m & fieldBaseMask

	// Terms for 2^(fieldBase*11).
	m = (m >> fieldBase) +
		2*uint64(val.n[2])*uint64(val.n[9]) +
		2*uint64(val.n[3])*uint64(val.n[8]) +
		2*uint64(val.n[4])*uint64(val.n[7]) +
		2*uint64(val.n[5])*uint64(val.n[6])
	t11 := m & fieldBaseMask

	// Terms for 2^(fieldBase*12).
	m = (m >> fieldBase) +
		2*uint64(val.n[3])*uint64(val.n[9]) +
		2*uint64(val.n[4])*uint64(val.n[8]) +
		2*uint64(val.n[5])*uint64(val.n[7]) +
		uint64(val.n[6])*uint64(val.n[6])
	t12 := m & fieldBaseMask

	// Terms for 2^(fieldBase*13).
	m = (m >> fieldBase) +
		2*uint64(val.n[4])*uint64(val.n[9]) +
		2*uint64(val.n[5])*uint64(val.n[8]) +
		2*uint64(val.n[6])*uint64(val.n[7])
	t13 := m & fieldBaseMask

	// Terms for 2^(fieldBase*14).
	m = (m >> fieldBase) +
		2*uint64(val.n[5])*uint64(val.n[9]) +
		2*uint64(val.n[6])*uint64(val.n[8]) +
		uint64(val.n[7])*uint64(val.n[7])
	t14 := m & fieldBaseMask

	// Terms for 2^(fieldBase*15).
	m = (m >> fieldBase) +
		2*uint64(val.n[6])*uint64(val.n[9]) +
		2*uint64(val.n[7])*uint64(val.n[8])
	t15 := m & fieldBaseMask

	// Terms for 2^(fieldBase*16).
	m = (m >> fieldBase) +
		2*uint64(val.n[7])*uint64(val.n[9]) +
		uint64(val.n[8])*uint64(val.n[8])
	t16 := m & fieldBaseMask

	// Terms for 2^(fieldBase*17).
	m = (m >> fieldBase) + 2*uint64(val.n[8])*uint64(val.n[9])
	t17 := m & fieldBaseMask

	// Terms for 2^(fieldBase*18).
	m = (m >> fieldBase) + uint64(val.n[9])*uint64(val.n[9])
	t18 := m & fieldBaseMask

	// What's left is for 2^(fieldBase*19).
	t19 := m >> fieldBase

	// At this point, all of the terms are grouped into their respective
	// base.
	//
	// Per [HAC] section 14.3.4: Reduction method of moduli of special form,
	// when the modulus is of the special form m = b^t - c, highly efficient
	// reduction can be achieved per the provided algorithm.
	//
	// The sm2 prime is equivalent to 2^256 - 4294968273, so it fits
	// this criteria.
	//
	// 4294968273 in field representation (base 2^26) is:
	// n[0] = 977
	// n[1] = 64
	// That is to say (2^26 * 64) + 977 = 4294968273
	//
	// Since each word is in base 26, the upper terms (t10 and up) start
	// at 260 bits (versus the final desired range of 256 bits), so the
	// field representation of 'c' from above needs to be adjusted for the
	// extra 4 bits by multiplying it by 2^4 = 16.  4294968273 * 16 =
	// 68719492368.  Thus, the adjusted field representation of 'c' is:
	// n[0] = 977 * 16 = 15632
	// n[1] = 64 * 16 = 1024
	// That is to say (2^26 * 1024) + 15632 = 68719492368
	//
	// To reduce the final term, t19, the entire 'c' value is needed instead
	// of only n[0] because there are no more terms left to handle n[1].
	// This means there might be some magnitude left in the upper bits that
	// is handled below.
	m = t0 + t10*15632
	t0 = m & fieldBaseMask
	m = (m >> fieldBase) + t1 + t10*1024 + t11*15632
	t1 = m & fieldBaseMask
	m = (m >> fieldBase) + t2 + t11*1024 + t12*15632
	t2 = m & fieldBaseMask
	m = (m >> fieldBase) + t3 + t12*1024 + t13*15632
	t3 = m & fieldBaseMask
	m = (m >> fieldBase) + t4 + t13*1024 + t14*15632
	t4 = m & fieldBaseMask
	m = (m >> fieldBase) + t5 + t14*1024 + t15*15632
	t5 = m & fieldBaseMask
	m = (m >> fieldBase) + t6 + t15*1024 + t16*15632
	t6 = m & fieldBaseMask
	m = (m >> fieldBase) + t7 + t16*1024 + t17*15632
	t7 = m & fieldBaseMask
	m = (m >> fieldBase) + t8 + t17*1024 + t18*15632
	t8 = m & fieldBaseMask
	m = (m >> fieldBase) + t9 + t18*1024 + t19*68719492368
	t9 = m & fieldMSBMask
	m = m >> fieldMSBBits

	// At this point, if the magnitude is greater than 0, the overall value
	// is greater than the max possible 256-bit value.  In particular, it is
	// "how many times larger" than the max value it is.
	//
	// The algorithm presented in [HAC] section 14.3.4 repeats until the
	// quotient is zero.  However, due to the above, we already know at
	// least how many times we would need to repeat as it's the value
	// currently in m.  Thus we can simply multiply the magnitude by the
	// field representation of the prime and do a single iteration.  Notice
	// that nothing will be changed when the magnitude is zero, so we could
	// skip this in that case, however always running regardless allows it
	// to run in constant time.  The final result will be in the range
	// 0 <= result <= prime + (2^64 - c), so it is guaranteed to have a
	// magnitude of 1, but it is denormalized.
	n := t0 + m*977
	f.n[0] = uint32(n & fieldBaseMask)
	n = (n >> fieldBase) + t1 + m*64
	f.n[1] = uint32(n & fieldBaseMask)
	f.n[2] = uint32((n >> fieldBase) + t2)
	f.n[3] = uint32(t3)
	f.n[4] = uint32(t4)
	f.n[5] = uint32(t5)
	f.n[6] = uint32(t6)
	f.n[7] = uint32(t7)
	f.n[8] = uint32(t8)
	f.n[9] = uint32(t9)

	return f
}

// Set sets the field value equal to the passed value.
//
// The field value is returned to support chaining.  This enables syntax like:
// f := new(fieldVal).Set(f2).Add(1) so that f = f2 + 1 where f2 is not
// modified.
func (f *fieldVal) Set(val *fieldVal) *fieldVal {
	*f = *val
	return f
}

// SetBytes packs the passed 32-byte big-endian value into the internal field
// value representation.
//
// The field value is returned to support chaining.  This enables syntax like:
// f := new(fieldVal).SetBytes(byteArray).Mul(f2) so that f = ba * f2.
func (f *fieldVal) SetBytes(b *[32]byte) *fieldVal {
	// Pack the 256 total bits across the 10 uint32 words with a max of
	// 26-bits per word.  This could be done with a couple of for loops,
	// but this unrolled version is significantly faster.  Benchmarks show
	// this is about 34 times faster than the variant which uses loops.
	f.n[0] = uint32(b[31]) | uint32(b[30])<<8 | uint32(b[29])<<16 |
		(uint32(b[28])&twoBitsMask)<<24
	f.n[1] = uint32(b[28])>>2 | uint32(b[27])<<6 | uint32(b[26])<<14 |
		(uint32(b[25])&fourBitsMask)<<22
	f.n[2] = uint32(b[25])>>4 | uint32(b[24])<<4 | uint32(b[23])<<12 |
		(uint32(b[22])&sixBitsMask)<<20
	f.n[3] = uint32(b[22])>>6 | uint32(b[21])<<2 | uint32(b[20])<<10 |
		uint32(b[19])<<18
	f.n[4] = uint32(b[18]) | uint32(b[17])<<8 | uint32(b[16])<<16 |
		(uint32(b[15])&twoBitsMask)<<24
	f.n[5] = uint32(b[15])>>2 | uint32(b[14])<<6 | uint32(b[13])<<14 |
		(uint32(b[12])&fourBitsMask)<<22
	f.n[6] = uint32(b[12])>>4 | uint32(b[11])<<4 | uint32(b[10])<<12 |
		(uint32(b[9])&sixBitsMask)<<20
	f.n[7] = uint32(b[9])>>6 | uint32(b[8])<<2 | uint32(b[7])<<10 |
		uint32(b[6])<<18
	f.n[8] = uint32(b[5]) | uint32(b[4])<<8 | uint32(b[3])<<16 |
		(uint32(b[2])&twoBitsMask)<<24
	f.n[9] = uint32(b[2])>>2 | uint32(b[1])<<6 | uint32(b[0])<<14
	return f
}

// SetByteSlice packs the passed big-endian value into the internal field value
// representation.  Only the first 32-bytes are used.  As a result, it is up to
// the caller to ensure numbers of the appropriate size are used or the value
// will be truncated.
//
// The field value is returned to support chaining.  This enables syntax like:
// f := new(fieldVal).SetByteSlice(byteSlice)
func (f *fieldVal) SetByteSlice(b []byte) *fieldVal {
	var b32 [32]byte
	for i := 0; i < len(b); i++ {
		if i < 32 {
			b32[i+(32-len(b))] = b[i]
		}
	}
	return f.SetBytes(&b32)
}

// SetHex decodes the passed big-endian hex string into the internal field value
// representation.  Only the first 32-bytes are used.
//
// The field value is returned to support chaining.  This enables syntax like:
// f := new(fieldVal).SetHex("0abc").Add(1) so that f = 0x0abc + 1
func (f *fieldVal) SetHex(hexString string) *fieldVal {
	if len(hexString)%2 != 0 {
		hexString = "0" + hexString
	}
	bytes, _ := hex.DecodeString(hexString)
	return f.SetByteSlice(bytes)
}

// SetInt sets the field value to the passed integer.  This is a convenience
// function since it is fairly common to perform some arithemetic with small
// native integers.
//
// The field value is returned to support chaining.  This enables syntax such
// as f := new(fieldVal).SetInt(2).Mul(f2) so that f = 2 * f2.
func (f *fieldVal) SetInt(ui uint) *fieldVal {
	f.Zero()
	f.n[0] = uint32(ui)
	return f
}

// String returns the field value as a human-readable hex string.
func (f fieldVal) String() string {
	t := new(fieldVal).Set(&f).Normalize()
	return hex.EncodeToString(t.Bytes()[:])
}

// Zero sets the field value to zero.  A newly created field value is already
// set to zero.  This function can be useful to clear an existing field value
// for reuse.
func (f *fieldVal) Zero() {
	f.n[0] = 0
	f.n[1] = 0
	f.n[2] = 0
	f.n[3] = 0
	f.n[4] = 0
	f.n[5] = 0
	f.n[6] = 0
	f.n[7] = 0
	f.n[8] = 0
	f.n[9] = 0
}

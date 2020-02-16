package sm2

import (
	"reflect"
	"testing"
)

// TestSetInt ensures that setting a field value to various native integers
// works as expected.
func TestSetInt(t *testing.T) {
	tests := []struct {
		in  uint
		raw [10]uint32
	}{
		{5, [10]uint32{5, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		// 2^26
		{67108864, [10]uint32{67108864, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		// 2^26 + 1
		{67108865, [10]uint32{67108865, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		// 2^32 - 1
		{4294967295, [10]uint32{4294967295, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetInt(test.in)
		if !reflect.DeepEqual(f.n, test.raw) {
			t.Errorf("fieldVal.Set #%d wrong result\ngot: %v\n"+
				"want: %v", i, f.n, test.raw)
			continue
		}
	}
}

// TestZero ensures that zeroing a field value zero works as expected.
func TestZero(t *testing.T) {
	f := new(fieldVal).SetInt(2)
	f.Zero()
	for idx, rawInt := range f.n {
		if rawInt != 0 {
			t.Errorf("internal field integer at index #%d is not "+
				"zero - got %d", idx, rawInt)
		}
	}
}

// TestIsZero ensures that checking if a field IsZero works as expected.
func TestIsZero(t *testing.T) {
	f := new(fieldVal)
	if !f.IsZero() {
		t.Errorf("new field value is not zero - got %v (rawints %x)", f,
			f.n)
	}

	f.SetInt(1)
	if f.IsZero() {
		t.Errorf("field claims it's zero when it's not - got %v "+
			"(raw rawints %x)", f, f.n)
	}

	f.Zero()
	if !f.IsZero() {
		t.Errorf("field claims it's not zero when it is - got %v "+
			"(raw rawints %x)", f, f.n)
	}
}

// TestStringer ensures the stringer returns the appropriate hex string.
func TestStringer(t *testing.T) {
	tests := []struct {
		in       string
		expected string
	}{
		{"0", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"1", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"a", "000000000000000000000000000000000000000000000000000000000000000a"},
		{"b", "000000000000000000000000000000000000000000000000000000000000000b"},
		{"c", "000000000000000000000000000000000000000000000000000000000000000c"},
		{"d", "000000000000000000000000000000000000000000000000000000000000000d"},
		{"e", "000000000000000000000000000000000000000000000000000000000000000e"},
		{"f", "000000000000000000000000000000000000000000000000000000000000000f"},
		{"f0", "00000000000000000000000000000000000000000000000000000000000000f0"},
		// 2^26-1
		{
			"3ffffff",
			"0000000000000000000000000000000000000000000000000000000003ffffff",
		},
		// 2^32-1
		{
			"ffffffff",
			"00000000000000000000000000000000000000000000000000000000ffffffff",
		},
		// 2^64-1
		{
			"ffffffffffffffff",
			"000000000000000000000000000000000000000000000000ffffffffffffffff",
		},
		// 2^96-1
		{
			"ffffffffffffffffffffffff",
			"0000000000000000000000000000000000000000ffffffffffffffffffffffff",
		},
		// 2^128-1
		{
			"ffffffffffffffffffffffffffffffff",
			"00000000000000000000000000000000ffffffffffffffffffffffffffffffff",
		},
		// 2^160-1
		{
			"ffffffffffffffffffffffffffffffffffffffff",
			"000000000000000000000000ffffffffffffffffffffffffffffffffffffffff",
		},
		// 2^192-1
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffff",
			"0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		// 2^224-1
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		// P (the sm2 prime, so should result in 0)
		{
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
			"0000000000000000000000000000000000000000000000000000000000000000",
		},
		// P+1 (the sm2 prime+1, so should result in 1)
		{
			"fffffffeffffffffffffffffffffffffffffffff000000010000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000001",
		},
		// Invalid hex
		{"g", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"1h", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"i1", "0000000000000000000000000000000000000000000000000000000000000000"},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in)
		result := f.String()
		if result != test.expected {
			t.Errorf("fieldVal.String #%d wrong result\ngot: %v\n"+
				"want: %v", i, result, test.expected)
			continue
		}
	}
}

// TestNormalize ensures that normalizing the internal field words works as
// expected.
// Suppose the sm2 prime is P = 2^256 - c
func TestNormalize(t *testing.T) {
	tests := []struct {
		raw        [10]uint32 // Intentionally denormalized value
		normalized [10]uint32 // Normalized form of the raw value
	}{
		{
			[10]uint32{0x00000005, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000005, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^26
		{
			[10]uint32{0x04000000, 0x0, 0, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000000, 0x1, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^26 + 1
		{
			[10]uint32{0x04000001, 0x0, 0, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000001, 0x1, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^32 - 1
		{
			[10]uint32{0xffffffff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x03ffffff, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^32
		{
			[10]uint32{0x04000000, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000000, 0x40, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^32 + 1
		{
			[10]uint32{0x04000001, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000001, 0x40, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^64 - 1
		{
			[10]uint32{0xffffffff, 0xffffffc0, 0xfc0, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x03ffffff, 0x03ffffff, 0xfff, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^64
		{
			[10]uint32{0x04000000, 0x03ffffff, 0x0fff, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000000, 0x00000000, 0x1000, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^64 + 1
		{
			[10]uint32{0x04000001, 0x03ffffff, 0x0fff, 0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000001, 0x00000000, 0x1000, 0, 0, 0, 0, 0, 0, 0},
		},
		// 2^96 - 1
		{
			[10]uint32{0xffffffff, 0xffffffc0, 0xffffffc0, 0x3ffc0, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x03ffffff, 0x03ffffff, 0x03ffffff, 0x3ffff, 0, 0, 0, 0, 0, 0},
		},
		// 2^96
		{
			[10]uint32{0x04000000, 0x03ffffff, 0x03ffffff, 0x3ffff, 0, 0, 0, 0, 0, 0},
			[10]uint32{0x00000000, 0x00000000, 0x00000000, 0x40000, 0, 0, 0, 0, 0, 0},
		},
		// 2^128 - 1
		{
			[10]uint32{0xffffffff, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffc0, 0, 0, 0, 0, 0},
			[10]uint32{0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0xffffff, 0, 0, 0, 0, 0},
		},
		// 2^128
		{
			[10]uint32{0x04000000, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x0ffffff, 0, 0, 0, 0, 0},
			[10]uint32{0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x1000000, 0, 0, 0, 0, 0},
		},
		// Prime with field representation such that the initial
		// reduction does not result in a carry to bit 256.
		//
		// P
		{
			[10]uint32{
				0xffffffff, 0xffffffc0, 0x00000fc0, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xfffeffc0, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x000000,
			},
		},
		// x = P + 2^(26*2), i.e. the 2nd word of x > that of P
		{
			[10]uint32{
				0xffffffff, 0x03ffffc0, 0x00001000, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xfffeffc0, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000,
			},
		},
		// x = P + 2 * 2^(26*3), i.e. the 3rd word of x > that of P
		{
			[10]uint32{
				0xffffffff, 0xffffffc0, 0x08000fc0, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xfffeffc0, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000000, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000,
			},
		},
		// x = P + 2^(26*2) + 2 * 2^(26*3), i.e. the 2nd and 3rd word of x > that of P
		{
			[10]uint32{
				0xffffffff, 0x03ffffc0, 0x08001000, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xfffeffc0, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000,
			},
		},
		// x = P + 3 * 2^(26*8), i.e. the 8th word of x > that of P
		{
			[10]uint32{
				0xffffffff, 0xffffffc0, 0x00000fc0, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0x0bffffc0,
				0xffff0000, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000000,
			},
		},
		// x = P + 2^(26*2) + 3 * 2^(26*8), i.e. the 2nd and 8th word of x > that of P
		{
			[10]uint32{
				0xffffffff, 0x03ffffc0, 0x00001000, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0x0bffffc0,
				0xffff0000, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000000,
			},
		},
		// x = P + 2 * 2^(26*3) + 3 * 2^(26*8), i.e. the 3rd and 8th word of x > that of P
		{
			[10]uint32{
				0xffffffff, 0xffffffc0, 0x08000fc0, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0x0bffffc0,
				0xffff0000, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000000, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000000,
			},
		},
		// x = P + 2^(26*2) + 2 * 2^(26*3) + 3 * 2^(26*8), i.e.
		// the 2nd, 3rd and 8th word of x > that of P
		{
			[10]uint32{
				0xffffffff, 0x03ffffc0, 0x08001000, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0x0bffffc0,
				0xffff0000, 0x003fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000000,
			},
		},
		// 2^256 - 1
		{
			[10]uint32{
				0xffffffff, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xffffffc0, 0x3fffc0,
			},
			[10]uint32{
				0x00000000, 0x00000000, 0x03fff000, 0x0003ffff,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00010000, 0x00000000,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to its 0th
		// word and does not result in a carry to bit 256.
		//
		// P + 1
		{
			[10]uint32{
				0x00000000, 0x00000000, 0x00001000, 0xfffc0000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xfffeffc0, 0x003fffc0,
			},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to a carry to
		// bit 256, but would not be without the carry.  These values
		// come from the fact that P is 2^256 - c and 1 is
		// the 0th base26-word of c in the internal field representation.
		//
		// 2^256 * 5 - ((c - (1+1)) * 4)
		{
			[10]uint32{
				0x00000004, 0x00000000, 0x00004000, 0x03f00000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x03fbffff, 0x013fffff,
			},
			[10]uint32{
				0x00000009, 0x00000000, 0x03fff000, 0x0003ffff,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00010000, 0x00000000,
			},
		},
		// 2^256 * 5 - ((c - (1+1)) * 4) in a different representation
		// to test the case where additions overflow in the 1st reduction
		{
			[10]uint32{
				0x00000004, 0x00000000, 0x00004000, 0xfff00000,
				0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0,
				0xfffbffc0, 0x013fffc0,
			},
			[10]uint32{
				0x00000009, 0x00000000, 0x03fff000, 0x0003ffff,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00010000, 0x00000000,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00000fff, 0x03fc0000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07feffff, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 2nd word.
		{
			[10]uint32{
				0x03ffffff, 0x03ffffff, 0x00001000, 0x03fc0000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07feffff, 0x003fffff},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th, 2nd word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00001000, 0x03fc0000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07feffff, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000001, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 3rd word.
		{
			[10]uint32{
				0x03ffffff, 0x03ffffff, 0x00000fff, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07feffff, 0x003fffff},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000000, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th, 3rd word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00000fff, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07feffff, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000000, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 2nd, 3rd word.
		{
			[10]uint32{
				0x03ffffff, 0x03ffffff, 0x00001000, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07feffff, 0x003fffff},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th, 2nd, 3rd word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00001000, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07feffff, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000001, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 8th word.
		{
			[10]uint32{
				0x03ffffff, 0x03ffffff, 0x00000fff, 0x03fc0000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th, 8th word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00000fff, 0x03fc0000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000000, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 2nd, 8th word.
		{
			[10]uint32{
				0x03ffffff, 0x03ffffff, 0x00001000, 0x03fc0000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th, 2nd, 8th word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00001000, 0x03fc0000,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000001, 0x00000000,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 3rd, 8th word.
		{
			[10]uint32{
				0x03ffffff, 0x03ffffff, 0x00000fff, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000000, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th, 3rd, 8th word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00000fff, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000000, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 2nd, 3rd, 8th word.
		{
			[10]uint32{
				0x03ffffff, 0x03ffffff, 0x00001000, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000000, 0x00000000, 0x00000001, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
		// Prime larger than P that reduces to a value which is still
		// larger than P when it has a magnitude of 1 due to both a
		// carry to bit 256 and the 0th, 2nd, 3rd, 8th word.
		{
			[10]uint32{
				0x04000000, 0x03ffffff, 0x00001000, 0x03fc0002,
				0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
				0x07ff0002, 0x003fffff},
			[10]uint32{
				0x00000001, 0x00000000, 0x00000001, 0x00000002,
				0x00000000, 0x00000000, 0x00000000, 0x00000000,
				0x00000003, 0x00000001,
			},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal)
		f.n = test.raw
		f.Normalize()
		if !reflect.DeepEqual(f.n, test.normalized) {
			t.Errorf("fieldVal.Normalize #%d wrong result\n"+
				"got: %x\nwant: %x", i, f.n, test.normalized)
			continue
		}
	}
}

// TestIsOdd ensures that checking if a field value IsOdd works as expected.
func TestIsOdd(t *testing.T) {
	tests := []struct {
		in       string // hex encoded value
		expected bool   // expected oddness
	}{
		{"0", false},
		{"1", true},
		{"2", false},
		// 2^32 - 1
		{"ffffffff", true},
		// 2^64 - 2
		{"fffffffffffffffe", false},
		// sm2 prime
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", true},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in)
		result := f.IsOdd()
		if result != test.expected {
			t.Errorf("fieldVal.IsOdd #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, test.expected)
			continue
		}
	}
}

// TestEquals ensures that checking two field values for equality via Equals
// works as expected.
func TestEquals(t *testing.T) {
	tests := []struct {
		in1      string // hex encoded value
		in2      string // hex encoded value
		expected bool   // expected equality
	}{
		{"0", "0", true},
		{"0", "1", false},
		{"1", "0", false},
		// 2^32 - 1 == 2^32 - 1?
		{"ffffffff", "ffffffff", true},
		// 2^64 - 1 == 2^64 - 2?
		{"ffffffffffffffff", "fffffffffffffffe", false},
		// 0 == prime (mod prime)?
		{"0", "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", true},
		// 1 == prime+1 (mod prime)?
		{"1", "fffffffeffffffffffffffffffffffffffffffff000000010000000000000000", true},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in1).Normalize()
		f2 := new(fieldVal).SetHex(test.in2).Normalize()
		result := f.Equals(f2)
		if result != test.expected {
			t.Errorf("fieldVal.Equals #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, test.expected)
			continue
		}
	}
}

// TestNegate ensures that negating field values via Negate works as expected.
func TestNegate(t *testing.T) {
	tests := []struct {
		in       string // hex encoded value
		expected string // expected hex encoded value
	}{
		// sm2 prime (aka 0)
		{"0", "0"},
		{"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", "0"},
		{"0", "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"},
		// sm2 prime-1
		{"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe", "1"},
		{"1", "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe"},
		// sm2 prime-2
		{"2", "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd"},
		{"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd", "2"},
		// Random sampling
		{
			"b3d9aac9c5e43910b4385b53c7e78c21d4cd5f8e683c633aed04c233efc2e120",
			"4c2655353a1bc6ef4bc7a4ac381873de2b32a07097c39cc612fb3dcc103d1edf",
		},
		{
			"f8a85984fee5a12a7c8dd08830d83423c937d77c379e4a958e447a25f407733f",
			"757a67a011a5ed583722f77cf27cbdc36c82882c861b56b71bb85da0bf88cc0",
		},
		{
			"45ee6142a7fda884211e93352ed6cb2807800e419533be723a9548823ece8312",
			"ba119ebc5802577bdee16ccad12934d7f87ff1bd6acc418ec56ab77dc1317ced",
		},
		{
			"53c2a668f07e411a2e473e1c3b6dcb495dec1227af27673761d44afe5b43d22b",
			"ac3d59960f81bee5d1b8c1e3c49234b6a213edd750d898c99e2bb501a4bc2dd4",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.Negate(1).Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.Negate #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

// TestAddInt ensures that adding an integer to field values via AddInt works as
// expected.
func TestAddInt(t *testing.T) {
	tests := []struct {
		in1      string // hex encoded value
		in2      uint   // unsigned integer to add to the value above
		expected string // expected hex encoded value
	}{
		{"0", 1, "1"},
		{"1", 0, "1"},
		{"1", 1, "2"},
		// sm2 prime-1 + 1
		{"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe", 1, "0"},
		// sm2 prime + 1
		{"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", 1, "1"},
		// Random samples.
		{
			"ff95ad9315aff04ab4af0ce673620c7145dc85d03bab5ba4b09ca2c4dec2d6c1",
			0x10f,
			"ff95ad9315aff04ab4af0ce673620c7145dc85d03bab5ba4b09ca2c4dec2d7d0",
		},
		{
			"44bdae6b772e7987941f1ba314e6a5b7804a4c12c00961b57d20f41deea9cecf",
			0x2cf11d41,
			"44bdae6b772e7987941f1ba314e6a5b7804a4c12c00961b57d20f41e1b9aec10",
		},
		{
			"88c3ecae67b591935fb1f6a9499c35315ffad766adca665c50b55f7105122c9c",
			0x4829aa2d,
			"88c3ecae67b591935fb1f6a9499c35315ffad766adca665c50b55f714d3bd6c9",
		},
		{
			"8523e9edf360ca32a95aae4e57fcde5a542b471d08a974d94ea0ee09a015e2a6",
			0xa21265a5,
			"8523e9edf360ca32a95aae4e57fcde5a542b471d08a974d94ea0ee0a4228484b",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in1).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.AddInt(test.in2).Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.AddInt #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

// TestAdd ensures that adding two field values together via Add works as
// expected.
func TestAdd(t *testing.T) {
	tests := []struct {
		in1      string // first hex encoded value
		in2      string // second hex encoded value to add
		expected string // expected hex encoded value
	}{
		{"0", "1", "1"},
		{"1", "0", "1"},
		{"1", "1", "2"},
		// sm2 prime-1 + 1
		{"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe", "1", "0"},
		// sm2 prime + 1
		{"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", "1", "1"},
		// Random samples.
		{
			"2b2012f975404e5065b4292fb8bed0a5d315eacf24c74d8b27e73bcc5430edcc",
			"2c3cefa4e4753e8aeec6ac4c12d99da4d78accefda3b7885d4c6bab46c86db92",
			"575d029e59b58cdb547ad57bcb986e4aaaa0b7beff02c610fcadf680c0b7c95e",
		},
		{
			"8131e8722fe59bb189692b96c9f38de92885730f1dd39ab025daffb94c97f79c",
			"ff5454b765f0aab5f0977dcc629becc84cabeb9def48e79c6aadb2622c490fa9",
			"80863d2a95d646677a00a9632c8f7ab175315eae0d1c824b9088b21b78e10746",
		},
		{
			"c7c95e93d0892b2b2cdd77e80eb646ea61be7a30ac7e097e9f843af73fad5c22",
			"3afe6f91a74dfc1c7f15c34907ee981656c37236d946767dd53ccad9190e437c",
			"2c7ce2677d72747abf33b3116a4df00b881ec6885c47ffb74c105d058bb9f9f",
		},
		{
			"fd1c26f6a23381e5d785ba889494ec059369b888ad8431cd67d8c934b580dbe1",
			"a475aa5a31dcca90ef5b53c097d9133d6b7117474b41e7877bb199590fc0489c",
			"a191d151d4104c76c6e10e492c6dff42fedacfd0f8c61953e38a628dc541247e",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in1).Normalize()
		f2 := new(fieldVal).SetHex(test.in2).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.Add(f2).Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.Add #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

// TestAdd2 ensures that adding two field values together via Add2 works as
// expected.
func TestAdd2(t *testing.T) {
	tests := []struct {
		in1      string // first hex encoded value
		in2      string // second hex encoded value to add
		expected string // expected hex encoded value
	}{
		{"0", "1", "1"},
		{"1", "0", "1"},
		{"1", "1", "2"},
		// sm2 prime-1 + 1
		{"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe", "1", "0"},
		// sm2 prime + 1
		{"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", "1", "1"},
		// close but over the sm2 prime
		{
			"fffffffeffffffffffffffffffffffffffffffff000000000000000000000000",
			"12300000ffffffffffffffff",
			"123000000000000000000000"},
		// Random samples.
		{
			"ad82b8d1cc136e23e9fd77fe2c7db1fe5a2ecbfcbde59ab3529758334f862d28",
			"4d6a4e95d6d61f4f46b528bebe152d408fd741157a28f415639347a84f6f574b",
			"faed0767a2e98d7330b2a0bcea92df3eea060d12380e8ec8b62a9fdb9ef58473",
		},
		{
			"f3f43a2540054a86e1df98547ec1c0e157b193e5350fb4a3c3ea214b228ac5e7", "25706572592690ea3ddc951a1b48b504a4c83dc253756e1b96d56fdfb3199522",
			"19649f98992bdb711fbc2d6e9a0a75e5fc79d1a8888522be5abf912ad5a45b0a",
		},
		{
			"6915bb94eef13ff1bb9b2633d997e13b9b1157c713363cc0e891416d6734f5b8",
			"11f90d6ac6fe1c4e8900b1c85fb575c251ec31b9bc34b35ada0aea1c21eded22",
			"7b0ec8ffb5ef5c40449bd7fc394d56fdecfd8980cf6af01bc29c2b898922e2da",
		},
		{
			"48b0c9eae622eed9335b747968544eb3e75cb2dc8128388f948aa30f88cabde4",
			"989882b52f85f9d524a3a3061a0e01f46d597839d2ba637320f4b9510c8d2d5",
			"523a5216391b4e7685a5aea9c9f52ed32e324a601e53dec6c699eea4999390b9",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in1).Normalize()
		f2 := new(fieldVal).SetHex(test.in2).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.Add2(f, f2).Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.Add2 #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

// TestMulInt ensures that adding an integer to field values via MulInt works as
// expected.
func TestMulInt(t *testing.T) {
	tests := []struct {
		in1      string // hex encoded value
		in2      uint   // unsigned integer to multiply with value above
		expected string // expected hex encoded value
	}{
		{"0", 0, "0"},
		{"1", 0, "0"},
		{"0", 1, "0"},
		{"1", 1, "1"},
		// sm2 prime-1 * 2
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe",
			2,
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd",
		},
		// sm2 prime * 3
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
			3,
			"0",
		},
		// sm2 prime-1 * 8
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe",
			8,
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffff7",
		},
		// Random samples for first value.  The second value is limited
		// to 8 since that is the maximum int used in the elliptic curve
		// calculations.
		{
			"b75674dc9180d306c692163ac5e089f7cef166af99645c0c23568ab6d967288a",
			6,
			"4c06bd2f6904f228a76c8560a3433bced9a86821985a2844d4074049186af340",
		},
		{
			"54873298ac2b5ba8591c125ae54931f5ea72040aee07b208d6135476fb5b9c0e",
			3,
			"fd9597ca048212f90b543710afdb95e1bf560c20ca17161a8239fd64f212d42a",
		},
		{
			"7c30fbd363a74c17e1198f56b090b59bbb6c8755a74927a6cba7a54843506401",
			5,
			"6cf4eb22f2447c77657fccb172d38c0aa91ea4ae446dc63ffa463a695091f407",
		},
		{
			"fb4529be3e027a3d1587d8a500b72f2d312e3577340ef5175f96d113be4c2ceb",
			8,
			"da294df8f013d1e8ac3ec52805b979698971abc0a077a8b3fcb6889df261675f",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in1).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.MulInt(test.in2).Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.MulInt #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

// TestMul ensures that multiplying two field valuess via Mul works as expected.
func TestMul(t *testing.T) {
	tests := []struct {
		in1      string // first hex encoded value
		in2      string // second hex encoded value to multiply with
		expected string // expected hex encoded value
	}{
		{"0", "0", "0"},
		{"1", "0", "0"},
		{"0", "1", "0"},
		{"1", "1", "1"},
		// slightly over prime
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff1ffff",
			"1000",
			"100000000000000000000000000000000fffffffeffffffff1ffff001",
		},
		// sm2 prime-1 * 2
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe",
			"2",
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd",
		},
		// sm2 prime * 3
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
			"3",
			"0",
		},
		// sm2 prime-1 * 8
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe",
			"8",
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffff7",
		},
		// Random samples.
		{
			"cfb81753d5ef499a98ecc04c62cb7768c2e4f1740032946db1c12e405248137e",
			"58f355ad27b4d75fb7db0442452e732c436c1f7c5a7c4e214fa9cc031426a7d3",
			"84030b5d3f749cc2ec93b8c09cf093e7588eeb7c44d4e7a442c89d02d7351c90",
		},
		{
			"26e9d61d1cdf3920e9928e85fa3df3e7556ef9ab1d14ec56d8b4fc8ed37235bf",
			"2dfc4bbe537afee979c644f8c97b31e58be5296d6dbc460091eae630c98511cf",
			"69a5362deb835ea5b45b537d2ee6a1878aa0de5a5eaa8e9f927f5f41e4697ae0",
		},
		{
			"5db64ed5afb71646c8b231585d5b2bf7e628590154e0854c4c29920b999ff351",
			"279cfae5eea5d09ade8e6a7409182f9de40981bc31c84c3d3dfe1d933f152e9a",
			"4a681ecc97e59366355398dbaeefbe5e3c644f9bdb45f70464f9087d8c3fefc9",
		},
		{
			"b66dfc1f96820b07d2bdbd559c19319a3a73c97ceb7b3d662f4fe75ecb6819e6",
			"bf774aba43e3e49eb63a6e18037d1118152568f1a3ac4ec8b89aeb6ff8008ae1",
			"23194cd6f43bf679128e801274be5f167cc0da744c32650234a9e3283685f6f3",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in1).Normalize()
		f2 := new(fieldVal).SetHex(test.in2).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.Mul(f2).Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.Mul #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

// TestSquare ensures that squaring field values via Square works as expected.
func TestSquare(t *testing.T) {
	tests := []struct {
		in       string // hex encoded value
		expected string // expected hex encoded value
	}{
		// sm2 prime (aka 0)
		{"0", "0"},
		{"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", "0"},
		{"0", "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"},
		// sm2 prime-1
		{"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe", "1"},
		// sm2 prime-2
		{"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd", "4"},
		// Random sampling
		{
			"b0ba920360ea8436a216128047aab9766d8faf468895eb5090fc8241ec758896",
			"eafcc48295f2810006ad563047bbbc49d88e184d7a1f0e5bdec29653a2f7f71c",
		},
		{
			"c55d0d730b1d0285a1599995938b042a756e6e8857d390165ffab480af61cbd5",
			"b9335391fc90db7d06e758aef73a46b6a7a660194c5c651ab9e6b63f409984b7",
		},
		{
			"e89c1f9a70d93651a1ba4bca5b78658f00de65a66014a25544d3365b0ab82324",
			"b22fbf39a4b852b6df3a656b534b67c77365d88a826d4466edb6eda3e1b862c6",
		},
		{
			"7dc26186079d22bcbe1614aa20ae627e62d72f9be7ad1e99cac0feb438956f05",
			"e4dbc99066306e0526f1878e386fc8e2dda743e3b253fc420de8bc45fe16d6f2",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.Square().Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.Square #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

// TestInverse ensures that finding the multiplicative inverse via Inverse works
// as expected.
func TestInverse(t *testing.T) {
	tests := []struct {
		in       string // hex encoded value
		expected string // expected hex encoded value
	}{
		// sm2 prime (aka 0)
		{"0", "0"},
		{"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", "0"},
		{"0", "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"},
		// sm2 prime-1, (p-1)*(p-1)=p^2-2*p+1=1 (mod p)
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe",
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe",
		},
		// sm2 prime-2
		{
			"fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd",
			"7fffffff7fffffffffffffffffffffffffffffff800000007fffffffffffffff",
		},
		// Random sampling
		{
			"16fb970147a9acc73654d4be233cc48b875ce20a2122d24f073d29bd28805aca",
			"884fe8569a93a41d4627bc92e982945148e9af1f38c6ac7d2066bb63d9526e63",
		},
		{
			"69d1323ce9f1f7b3bd3c7320b0d6311408e30281e273e39a0d8c7ee1c8257919",
			"42fc50db6336b98b26e8c5d2720cf1499572cd4a4ea51136755adfb5088d060c",
		},
		{
			"e0debf988ae098ecda07d0b57713e97c6d213db19753e8c95aa12a2fc1cc5272",
			"206a89eba13359af90ef79de86bdd99bff66c0f59a953267aef38262fe2d5450",
		},
		{
			"dcd394f91f74c2ba16aad74a22bb0ed47fe857774b8f2d6c09e28bfb14642878",
			"c3966ef6773e23624a31d2dca89ec80718ff397685e573af6b6a64522a46342c",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		f := new(fieldVal).SetHex(test.in).Normalize()
		expected := new(fieldVal).SetHex(test.expected).Normalize()
		result := f.Inverse().Normalize()
		if !result.Equals(expected) {
			t.Errorf("fieldVal.Inverse #%d wrong result\n"+
				"got: %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

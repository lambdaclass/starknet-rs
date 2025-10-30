//! This module implements a low-level API of the Blake2s hash, defined in RFC7693.
//!
//! Unlike other popular Blake2s implementation, this one exposes the `compress`
//! function, which is required for implementing Cairo language executors.

use core::ops::Shl;

/// Blake2s initialization vector
pub const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Blake2s parameter block.
pub fn blake2s_parameter_block(key_size: usize, hash_size: usize) -> [u32; 8] {
    assert!(key_size <= 32);
    assert!(hash_size <= 32);

    let mut p = [0; 8];
    p[0] = 0x0101_0000 ^ ((key_size as u32) << 8) ^ (hash_size as u32);
    p
}

/// Blake2s initial state.
pub fn blake2s_initial_state(key_size: usize, hash_size: usize) -> [u32; 8] {
    let mut state = BLAKE2S_IV;
    state[0] ^= blake2s_parameter_block(key_size, hash_size)[0];
    state
}

/// Blake2s compress function.
///
/// Compresses the `message` block into the `state` vector. The `byte_offset`
/// argument must contain the number of bytes hashed so far including the
/// current message. The `finalize` flag must be set when compressing the last
/// block.
///
/// # Safety
///
/// This function is a low-level blake2s primitive, and should be used with
/// care. Checkout `Blake2sHasher` for an example on how this should be used.
pub fn blake2s_compress(
    state: &[u32; 8],
    message: &[u32; 16],
    byte_offset: u64,
    finalize: bool,
) -> [u32; 8] {
    let mut work = [0u32; 16];
    work[0..8].copy_from_slice(state);
    work[8..12].copy_from_slice(&BLAKE2S_IV[0..4]);

    let t0 = byte_offset as u32;
    let t1 = (byte_offset >> 32) as u32;
    work[12..14].copy_from_slice(&[(BLAKE2S_IV[4] ^ t0), (BLAKE2S_IV[5] ^ t1)]);

    let f0 = if finalize { !0 } else { 0 };
    let f1 = 0;
    work[14..16].copy_from_slice(&[(BLAKE2S_IV[6] ^ f0), (BLAKE2S_IV[7] ^ f1)]);

    for sigma_list in SIGMA {
        work = round(work, message, sigma_list);
    }

    let mut new_state = [0u32; 8];
    for i in 0..8 {
        new_state[i] = state[i] ^ work[i] ^ work[8 + i];
    }
    new_state
}

/// Blake2s hasher state, generic over output size.
#[derive(Debug)]
pub struct Blake2sHasher<const OUT: usize> {
    state: [u32; 8],
    byte_offset: u64,
    buffer: [u8; 64],
    buffer_length: usize,
}

impl<const OUT: usize> Blake2sHasher<OUT> {
    /// Creates a new hasher instance.
    pub fn new() -> Self {
        let initial_state = blake2s_initial_state(0, OUT);

        Self {
            state: initial_state,
            byte_offset: 0,
            buffer: [0; 64],
            buffer_length: 0,
        }
    }

    /// Creates a new hasher instance with the given key.
    pub fn new_with_key(key: &[u8]) -> Self {
        let initial_state = blake2s_initial_state(key.len(), OUT);

        // The key goes in the first block.
        let buffer_length = 64;
        let mut buffer = [0; 64];
        buffer[..key.len()].copy_from_slice(key);

        Self {
            state: initial_state,
            byte_offset: 0,
            buffer,
            buffer_length,
        }
    }

    /// Feeds the given data into the hasher, updating its internal state.
    pub fn update(&mut self, mut data: &[u8]) {
        // While there is enough data to overflow the buffer, compress the
        // buffer into the internal state.
        while data.len() > self.remaining() {
            let remaining = self.remaining();
            let (left, right) = data.split_at(remaining);
            data = right;

            self.buffer[self.buffer_length..][..remaining].copy_from_slice(left);
            self.buffer_length += remaining;
            self.compress(false);
        }

        // Copy leftover data to buffer.
        self.buffer[self.buffer_length..][..data.len()].copy_from_slice(data);
        self.buffer_length += data.len();
    }

    /// Returns remaining bytes in the data buffer.
    fn remaining(&self) -> usize {
        64 - self.buffer_length
    }

    /// Compute the final hash digest.
    pub fn finalize(mut self) -> [u8; OUT] {
        // Compress what's left in the buffer.
        self.compress(true);

        // Return OUT bytes from internal state.
        let mut output = [0; OUT];
        output.copy_from_slice(&Self::u32s_to_u8s(&self.state)[..OUT]);
        output
    }

    /// Compresses the data buffer into the internal state.
    fn compress(&mut self, finalize: bool) {
        // Increase byte offset by size of current message.
        self.byte_offset += self.buffer_length as u64;

        // Compress the buffer into the internal state.
        self.state = blake2s_compress(
            &self.state,
            &Self::u8s_to_u32s(&self.buffer),
            self.byte_offset,
            finalize,
        );

        // Reset buffer.
        self.buffer_length = 0;
        self.buffer = [0; 64];
    }

    /// Utility function to convert an u32 array into an u8 array. This could be
    /// implemented with the `transmute` function, but requires unsafe code.
    fn u32s_to_u8s(words: &[u32; 8]) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (i, n) in words.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&n.to_ne_bytes());
        }
        bytes
    }

    /// Utility function to convert an u8 array into an u32 array. This could be
    /// implemented with the `transmute` function, but requires unsafe code.
    fn u8s_to_u32s(bytes: &[u8; 64]) -> [u32; 16] {
        let mut words = [0; 16];
        for (word, word_bytes) in words.iter_mut().zip(bytes.chunks(4)) {
            *word = u32::from_ne_bytes(word_bytes.try_into().unwrap())
        }
        words
    }
}

impl<const OUT: usize> Default for Blake2sHasher<OUT> {
    fn default() -> Self {
        Self::new()
    }
}

fn round(mut work: [u32; 16], message: &[u32; 16], sigma: [usize; 16]) -> [u32; 16] {
    (work[0], work[4], work[8], work[12]) = mix(
        work[0],
        work[4],
        work[8],
        work[12],
        message[sigma[0]],
        message[sigma[1]],
    );
    (work[1], work[5], work[9], work[13]) = mix(
        work[1],
        work[5],
        work[9],
        work[13],
        message[sigma[2]],
        message[sigma[3]],
    );
    (work[2], work[6], work[10], work[14]) = mix(
        work[2],
        work[6],
        work[10],
        work[14],
        message[sigma[4]],
        message[sigma[5]],
    );
    (work[3], work[7], work[11], work[15]) = mix(
        work[3],
        work[7],
        work[11],
        work[15],
        message[sigma[6]],
        message[sigma[7]],
    );
    (work[0], work[5], work[10], work[15]) = mix(
        work[0],
        work[5],
        work[10],
        work[15],
        message[sigma[8]],
        message[sigma[9]],
    );
    (work[1], work[6], work[11], work[12]) = mix(
        work[1],
        work[6],
        work[11],
        work[12],
        message[sigma[10]],
        message[sigma[11]],
    );
    (work[2], work[7], work[8], work[13]) = mix(
        work[2],
        work[7],
        work[8],
        work[13],
        message[sigma[12]],
        message[sigma[13]],
    );
    (work[3], work[4], work[9], work[14]) = mix(
        work[3],
        work[4],
        work[9],
        work[14],
        message[sigma[14]],
        message[sigma[15]],
    );
    work
}

fn mix(a: u32, b: u32, c: u32, d: u32, m0: u32, m1: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b).wrapping_add(m0);
    let d = right_rot(d ^ a, 16);
    let c = c.wrapping_add(d);
    let b = right_rot(b ^ c, 12);
    let a = a.wrapping_add(b).wrapping_add(m1);
    let d = right_rot(d ^ a, 8);
    let c = c.wrapping_add(d);
    let b = right_rot(b ^ c, 7);
    (a, b, c, d)
}

fn right_rot(value: u32, n: u32) -> u32 {
    (value >> n) | ((value & (1_u32.shl(n) - 1)) << (32 - n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32 byte string which can fit in half blake2s message.
    const HALF_MESSAGE: &[u8] = b"Lorem ipsum dolor sit amet duis.";

    // All hash results were compared with existing Blake2s implementations.

    #[test]
    fn hash_empty_block() {
        let data = b"";
        let mut hasher = Blake2sHasher::<32>::default();
        hasher.update(data);
        let output = hasher.finalize();
        assert_eq!(
            hex::encode(output),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        )
    }

    #[test]
    fn hash_partial_block() {
        let data = HALF_MESSAGE;
        let mut hasher = Blake2sHasher::<32>::default();
        hasher.update(data);
        let output = hasher.finalize();
        assert_eq!(
            hex::encode(output),
            "cf4e2ef5d65843da6e8d501e1b293dec5ca0cee12697245fd926d43118076d0a"
        )
    }

    #[test]
    fn hash_full_block() {
        let data = HALF_MESSAGE.repeat(2);
        let mut hasher = Blake2sHasher::<32>::default();
        hasher.update(&data);
        let output = hasher.finalize();
        assert_eq!(
            hex::encode(output),
            "95a466cd8ea68cec3c0b3bee3889dab5e340f93588fe8d48912b89138ae4aa6e"
        )
    }

    #[test]
    fn hash_multiple_full_blocks() {
        let data = HALF_MESSAGE.repeat(10);
        let mut hasher = Blake2sHasher::<32>::default();
        hasher.update(&data);
        let output = hasher.finalize();
        assert_eq!(
            hex::encode(output),
            "3d7a25e8ca9b1d3ca667de6751a5df4dc88cc4f81b1148bfd2391d0d4aa4fbab"
        )
    }

    #[test]
    fn hash_multiple_full_blocks_with_partial_last_block() {
        let data = HALF_MESSAGE.repeat(11);
        let mut hasher = Blake2sHasher::<32>::default();
        hasher.update(&data);
        let output = hasher.finalize();
        assert_eq!(
            hex::encode(output),
            "2897e0a3eb8ad8b263f816b5268472b5056fae2785227dc55a6d72a7ef68ab27"
        )
    }

    #[test]
    fn hash_with_smaller_output_size() {
        let data = HALF_MESSAGE.repeat(11);
        let mut hasher = Blake2sHasher::<16>::default();
        hasher.update(&data);
        let output = hasher.finalize();
        assert_eq!(hex::encode(output), "d4a570aa136f46c0db3549c1971f7290")
    }

    #[test]
    fn hash_with_partial_key() {
        let key = b"starknet";
        let data = HALF_MESSAGE.repeat(11);
        let mut hasher = Blake2sHasher::<32>::new_with_key(key);
        hasher.update(&data);
        let output = hasher.finalize();
        assert_eq!(
            hex::encode(output),
            "1c5d35bb2566afdf6a0696140513522badf8276c3e99ee9c0dc6c26d22a8a6f3"
        )
    }

    #[test]
    fn hash_with_full_key() {
        let key = HALF_MESSAGE;
        let data = HALF_MESSAGE.repeat(11);
        let mut hasher = Blake2sHasher::<32>::new_with_key(key);
        hasher.update(&data);
        let output = hasher.finalize();
        assert_eq!(
            hex::encode(output),
            "ee5f40c89c992250163ba5a5988f5546f7f2304a01178d81803124d8f7310834"
        )
    }

    #[test]
    fn hash_with_full_key_and_smaller_output_size() {
        let key = HALF_MESSAGE;
        let data = HALF_MESSAGE.repeat(11);
        let mut hasher = Blake2sHasher::<16>::new_with_key(key);
        hasher.update(&data);
        let output = hasher.finalize();
        assert_eq!(hex::encode(output), "0625ee15b016cada70d7a696c4a42dcb")
    }

    #[test]
    fn compress_case_1() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let new_state = blake2s_compress(&state, &message, 2, true);
        let expected_state = [
            412110711, 3234706100, 3894970767, 982912411, 937789635, 742982576, 3942558313,
            1407547065,
        ];
        assert_eq!(new_state, expected_state)
    }

    #[test]
    fn compress_case_2() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [456710651, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let new_state = blake2s_compress(&state, &message, 2, true);
        let expected_state = [
            1061041453, 3663967611, 2158760218, 836165556, 3696892209, 3887053585, 2675134684,
            2201582556,
        ];
        assert_eq!(new_state, expected_state,)
    }

    #[test]
    fn compress_case_3() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [
            1819043144, 1870078063, 6581362, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let new_state = blake2s_compress(&state, &message, 9, true);
        let expected_state = [
            939893662, 3935214984, 1704819782, 3912812968, 4211807320, 3760278243, 674188535,
            2642110762,
        ];
        assert_eq!(new_state, expected_state,)
    }

    #[test]
    fn compress_case_4() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [
            1819043144, 1870078063, 6581362, 274628678, 715791845, 175498643, 871587583, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let new_state = blake2s_compress(&state, &message, 28, true);
        let expected_state = [
            3980510537, 3982966407, 1593299263, 2666882356, 3288094120, 2682988286, 1666615862,
            378086837,
        ];
        assert_eq!(new_state, expected_state)
    }

    #[test]
    fn compress_case_5() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [
            1819043144, 1870078063, 6581362, 274628678, 715791845, 175498643, 871587583, 635963558,
            557369694, 1576875962, 215769785, 0, 0, 0, 0, 0,
        ];
        let new_state = blake2s_compress(&state, &message, 44, true);
        let expected_state = [
            3251785223, 1946079609, 2665255093, 3508191500, 3630835628, 3067307230, 3623370123,
            656151356,
        ];
        assert_eq!(new_state, expected_state)
    }

    #[test]
    fn compress_case_6() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [
            1819043144, 1870078063, 6581362, 274628678, 715791845, 175498643, 871587583, 635963558,
            557369694, 1576875962, 215769785, 152379578, 585849303, 764739320, 437383930, 74833930,
        ];
        let new_state = blake2s_compress(&state, &message, 64, true);
        let expected_state = [
            2593218707, 3238077801, 914875393, 3462286058, 4028447058, 3174734057, 2001070146,
            3741410512,
        ];
        assert_eq!(new_state, expected_state)
    }

    #[test]
    fn compress_case_7() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [
            11563522, 43535528, 653255322, 274628678, 73471943, 17549868, 87158958, 635963558,
            343656565, 1576875962, 215769785, 152379578, 585849303, 76473202, 437253230, 74833930,
        ];
        let new_state = blake2s_compress(&state, &message, 64, true);
        let expected_state = [
            3496615692, 3252241979, 3771521549, 2125493093, 3240605752, 2885407061, 3962009872,
            3845288240,
        ];
        assert_eq!(new_state, expected_state)
    }

    #[test]
    fn parameter_block_kk0_nn32() {
        let parameter_block = blake2s_parameter_block(0, 32);
        assert_eq!(parameter_block[0], 0x01010020);
        assert_eq!(&parameter_block[1..], &[0; 7])
    }

    #[test]
    fn initial_state_kk0_nn32() {
        let state = blake2s_initial_state(0, 32);
        assert_eq!(state[0], 0x6B08E647);
        assert_eq!(&state[1..], &BLAKE2S_IV[1..]);
    }
}

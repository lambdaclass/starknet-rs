use core::ops::Shl;

/// Blake2s initialization vector
pub const IV: [u32; 8] = [
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

/// Blake2s parameter block
pub fn parameter_block(key_size: u32, hash_size: u32) -> [u32; 8] {
    let mut p = [0; 8];
    p[0] = 0x0101_0000 ^ (key_size << 8) ^ hash_size;
    p
}

/// Blake2s initial state
pub fn initial_state(key_size: u32, hash_size: u32) -> [u32; 8] {
    let mut state = IV;
    state[0] ^= parameter_block(key_size, hash_size)[0];
    state
}

/// Blake2s compress function
///
/// Compresses the `message` block into the `state` vector. The `byte_offset`
/// argument must contain the number of bytes hashed so far including the
/// current message. The `finalize` flag must be set when compressing the last
/// block.
///
/// TODO: Document expected usage.
pub fn compress(
    state: &[u32; 8],
    message: &[u32; 16],
    byte_offset: u64,
    finalize: bool,
) -> [u32; 8] {
    let mut work = [0u32; 16];
    work[0..8].copy_from_slice(state);
    work[8..12].copy_from_slice(&IV[0..4]);

    let t0 = byte_offset as u32;
    let t1 = (byte_offset >> 32) as u32;
    work[12..14].copy_from_slice(&[(IV[4] ^ t0), (IV[5] ^ t1)]);

    let f0 = if finalize { !0 } else { 0 };
    let f1 = 0;
    work[14..16].copy_from_slice(&[(IV[6] ^ f0), (IV[7] ^ f1)]);

    for sigma_list in SIGMA {
        work = round(work, message, sigma_list);
    }

    let mut new_state = [0u32; 8];
    for i in 0..8 {
        new_state[i] = state[i] ^ work[i] ^ work[8 + i];
    }
    new_state
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

    fn u32s_to_u8s(words: [u32; 8]) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (i, n) in words.into_iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&n.to_ne_bytes());
        }
        bytes
    }

    fn u8s_to_u32s(bytes: [u8; 64]) -> [u32; 16] {
        let mut words = [0; 16];
        for (word, word_bytes) in words.iter_mut().zip(bytes.chunks(4)) {
            *word = u32::from_ne_bytes(word_bytes.try_into().unwrap())
        }
        words
    }

    fn hash(data: &[u8], key: &[u8], output_size: usize) -> Vec<u8> {
        let mut state = initial_state(key.len() as u32, output_size as u32);

        let mut padded_key_array = [0; 64];

        let padded_key = if !key.is_empty() {
            padded_key_array[..key.len()].copy_from_slice(key);
            padded_key_array.as_slice()
        } else {
            &[]
        };

        let data = [padded_key, data].concat();

        if data.is_empty() {
            state = compress(&state, &[0u32; 16], 0, true);
        } else {
            let mut chunks = data.chunks(64).peekable();

            let mut byte_offset = 0u64;
            while let Some(block_slice) = chunks.next() {
                byte_offset += block_slice.len() as u64;

                let mut block = [0u8; 64];
                block[..block_slice.len()].copy_from_slice(block_slice);
                let message = u8s_to_u32s(block);

                let is_last = chunks.peek().is_none();
                state = compress(&state, &message, byte_offset, is_last);
            }
        }

        let full_output = u32s_to_u8s(state);

        let mut output = Vec::with_capacity(output_size);
        output.extend_from_slice(&full_output[..output_size]);
        output
    }

    #[test]
    fn hash_empty_block() {
        let data = b"";
        let output = hash(data, &[], 32);
        assert_eq!(
            hex::encode(output),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        )
    }

    #[test]
    fn hash_partial_block() {
        let data = b"Hello, World!";
        let output = hash(data, &[], 32);
        assert_eq!(
            hex::encode(output),
            "ec9db904d636ef61f1421b2ba47112a4fa6b8964fd4a0a514834455c21df7812"
        )
    }

    #[test]
    fn hash_full_block() {
        let data = b"Cras venenatis sem quis mattis efficitur. Pellentesque placerat.";
        let output = hash(data, &[], 32);
        assert_eq!(
            hex::encode(output),
            "9545f23f4d3377077ed014a2fe2cb75d266b5f6b180cf91cdc2fb77a3f557397"
        )
    }

    #[test]
    fn hash_multiple_full_blocks() {
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec risus lorem, eleifend non justo vel, porta maximus mauris. Vivamus at sollicitudin ante. Mauris maximus lectus nec urna pretium, at consequat nisi commodo. Curabitur elit eros, imperdiet in volutpat sit amet, consectetur vitae libero. Aliquam orci erat, facilisis id nisl tempor, commodo fermentum leo. Morbi a vestibulum ligula. Curabitur lobortis ex nec orci convallis, vitae cursus justo laoreet. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Aenean hendrerit nisi at elit fringilla tincidunt. Ut posuere est vitae sapien sit.";
        let output = hash(data, &[], 32);
        assert_eq!(
            hex::encode(output),
            "e16989778a15616122cdfea41c77d61445877cd7a46af639a43b4652614a5216"
        )
    }

    #[test]
    fn hash_multiple_full_blocks_with_partial_last_block() {
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris id sagittis turpis. Vestibulum tempus nibh non nunc commodo, non dapibus libero blandit. Duis ultricies vehicula massa id lacinia. Aenean sit amet quam eleifend mauris pellentesque interdum. Cras sit amet libero ac ex feugiat bibendum in vitae metus. Mauris a nisl laoreet, mattis sapien sed, ullamcorper mi. Integer suscipit imperdiet magna ultrices accumsan. Donec et purus vel neque ultrices iaculis ac nec ipsum. Vivamus semper nunc ut consequat fermentum. Duis id aliquet orci. Fusce id condimentum ligula, nec aliquet elit. Fusce vitae tincidunt metus. Nullam luctus erat turpis, ac feugiat dolor nunc.";
        let output = hash(data, &[], 32);
        assert_eq!(
            hex::encode(output),
            "0f610082f3b8e3d4b3c0e02326b3b2620b664f76e156d79fbb39f54c5e6c2a54"
        )
    }

    #[test]
    fn hash_with_smaller_output_size() {
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris id sagittis turpis. Vestibulum tempus nibh non nunc commodo, non dapibus libero blandit. Duis ultricies vehicula massa id lacinia. Aenean sit amet quam eleifend mauris pellentesque interdum. Cras sit amet libero ac ex feugiat bibendum in vitae metus. Mauris a nisl laoreet, mattis sapien sed, ullamcorper mi. Integer suscipit imperdiet magna ultrices accumsan. Donec et purus vel neque ultrices iaculis ac nec ipsum. Vivamus semper nunc ut consequat fermentum. Duis id aliquet orci. Fusce id condimentum ligula, nec aliquet elit. Fusce vitae tincidunt metus. Nullam luctus erat turpis, ac feugiat dolor nunc.";
        let output = hash(data, &[], 16);
        assert_eq!(hex::encode(output), "4d42df29b369a1c13b49d21651373c3d")
    }

    #[test]
    fn hash_with_partial_key() {
        let key = b"starknet";
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris id sagittis turpis. Vestibulum tempus nibh non nunc commodo, non dapibus libero blandit. Duis ultricies vehicula massa id lacinia. Aenean sit amet quam eleifend mauris pellentesque interdum. Cras sit amet libero ac ex feugiat bibendum in vitae metus. Mauris a nisl laoreet, mattis sapien sed, ullamcorper mi. Integer suscipit imperdiet magna ultrices accumsan. Donec et purus vel neque ultrices iaculis ac nec ipsum. Vivamus semper nunc ut consequat fermentum. Duis id aliquet orci. Fusce id condimentum ligula, nec aliquet elit. Fusce vitae tincidunt metus. Nullam luctus erat turpis, ac feugiat dolor nunc.";
        let output = hash(data, key, 32);
        assert_eq!(
            hex::encode(output),
            "4669dc25351381a2b2b430c483cd7ab64aa7b3277582de521a1884ee6d3538ff"
        )
    }

    #[test]
    fn compress_case_1() {
        let state = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let new_state = compress(&state, &message, 2, true);
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
        let new_state = compress(&state, &message, 2, true);
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
        let new_state = compress(&state, &message, 9, true);
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
        let new_state = compress(&state, &message, 28, true);
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
        let new_state = compress(&state, &message, 44, true);
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
        let new_state = compress(&state, &message, 64, true);
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
        let new_state = compress(&state, &message, 64, true);
        let expected_state = [
            3496615692, 3252241979, 3771521549, 2125493093, 3240605752, 2885407061, 3962009872,
            3845288240,
        ];
        assert_eq!(new_state, expected_state)
    }

    #[test]
    fn parameter_block_kk0_nn32() {
        let parameter_block = parameter_block(0, 32);
        assert_eq!(parameter_block[0], 0x01010020);
        assert_eq!(&parameter_block[1..], &[0; 7])
    }

    #[test]
    fn initial_state_kk0_nn32() {
        let state = initial_state(0, 32);
        assert_eq!(state[0], 0x6B08E647);
        assert_eq!(&state[1..], &IV[1..]);
    }
}

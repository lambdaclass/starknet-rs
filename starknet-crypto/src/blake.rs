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

/// Blake2s compress function
///
/// Compresses the message block `m` into the state vector `h`. The argument `t`
/// must contain the number of bytes hashed so far including the current block,
/// separated into low and high bits (`t0` and `t1` respectively).
///
/// The finalization flag `f0` must be set to `0xFFFFFFFF` when compressing the
/// last block. The finalization flag `f1` is used to signal the last node of a
/// layer in tree-hashing modes.
///
/// TODO: Consider exposing a safer signature (no u32 flags).
/// TODO: Document expected usage.
pub fn compress(h: &[u32; 8], m: &[u32; 16], t0: u32, t1: u32, f0: u32, f1: u32) -> [u32; 8] {
    let mut work = [0u32; 16];
    work[0..8].copy_from_slice(h);
    work[8..12].copy_from_slice(&IV[0..4]);
    work[12..16].copy_from_slice(&[(IV[4] ^ t0), (IV[5] ^ t1), (IV[6] ^ f0), (IV[7] ^ f1)]);

    for sigma_list in SIGMA {
        work = round(work, m, sigma_list);
    }

    let mut new_h = [0u32; 8];
    for i in 0..8 {
        new_h[i] = h[i] ^ work[i] ^ work[8 + i];
    }
    new_h
}

fn round(mut state: [u32; 16], message: &[u32; 16], sigma: [usize; 16]) -> [u32; 16] {
    (state[0], state[4], state[8], state[12]) = mix(
        state[0],
        state[4],
        state[8],
        state[12],
        message[sigma[0]],
        message[sigma[1]],
    );
    (state[1], state[5], state[9], state[13]) = mix(
        state[1],
        state[5],
        state[9],
        state[13],
        message[sigma[2]],
        message[sigma[3]],
    );
    (state[2], state[6], state[10], state[14]) = mix(
        state[2],
        state[6],
        state[10],
        state[14],
        message[sigma[4]],
        message[sigma[5]],
    );
    (state[3], state[7], state[11], state[15]) = mix(
        state[3],
        state[7],
        state[11],
        state[15],
        message[sigma[6]],
        message[sigma[7]],
    );
    (state[0], state[5], state[10], state[15]) = mix(
        state[0],
        state[5],
        state[10],
        state[15],
        message[sigma[8]],
        message[sigma[9]],
    );
    (state[1], state[6], state[11], state[12]) = mix(
        state[1],
        state[6],
        state[11],
        state[12],
        message[sigma[10]],
        message[sigma[11]],
    );
    (state[2], state[7], state[8], state[13]) = mix(
        state[2],
        state[7],
        state[8],
        state[13],
        message[sigma[12]],
        message[sigma[13]],
    );
    (state[3], state[4], state[9], state[14]) = mix(
        state[3],
        state[4],
        state[9],
        state[14],
        message[sigma[14]],
        message[sigma[15]],
    );
    state
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

    #[test]
    fn compress_1() {
        let h = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let m = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let new_h = compress(&h, &m, 2, 0, 0xFFFFFFFF, 0);
        let expected_h = [
            412110711, 3234706100, 3894970767, 982912411, 937789635, 742982576, 3942558313,
            1407547065,
        ];
        assert_eq!(new_h, expected_h)
    }

    #[test]
    fn compress_2() {
        let h = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let m = [456710651, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let new_h = compress(&h, &m, 2, 0, 0xFFFFFFFF, 0);
        let expected_h = [
            1061041453, 3663967611, 2158760218, 836165556, 3696892209, 3887053585, 2675134684,
            2201582556,
        ];
        assert_eq!(new_h, expected_h,)
    }

    #[test]
    fn compress_3() {
        let h = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let m = [
            1819043144, 1870078063, 6581362, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let new_h = compress(&h, &m, 9, 0, 0xFFFFFFFF, 0);
        let expected_h = [
            939893662, 3935214984, 1704819782, 3912812968, 4211807320, 3760278243, 674188535,
            2642110762,
        ];
        assert_eq!(new_h, expected_h,)
    }

    #[test]
    fn compress_4() {
        let h = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message = [
            1819043144, 1870078063, 6581362, 274628678, 715791845, 175498643, 871587583, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let new_state = compress(&h, &message, 28, 0, 0xFFFFFFFF, 0);
        assert_eq!(
            new_state,
            [
                3980510537, 3982966407, 1593299263, 2666882356, 3288094120, 2682988286, 1666615862,
                378086837
            ]
        )
    }

    #[test]
    fn compress_5() {
        let h = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let m = [
            1819043144, 1870078063, 6581362, 274628678, 715791845, 175498643, 871587583, 635963558,
            557369694, 1576875962, 215769785, 0, 0, 0, 0, 0,
        ];
        let new_h = compress(&h, &m, 44, 0, 0xFFFFFFFF, 0);
        let expected_h = [
            3251785223, 1946079609, 2665255093, 3508191500, 3630835628, 3067307230, 3623370123,
            656151356,
        ];
        assert_eq!(new_h, expected_h)
    }

    #[test]
    fn compress_6() {
        let h = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let m = [
            1819043144, 1870078063, 6581362, 274628678, 715791845, 175498643, 871587583, 635963558,
            557369694, 1576875962, 215769785, 152379578, 585849303, 764739320, 437383930, 74833930,
        ];
        let new_h = compress(&h, &m, 64, 0, 0xFFFFFFFF, 0);
        let expected_h = [
            2593218707, 3238077801, 914875393, 3462286058, 4028447058, 3174734057, 2001070146,
            3741410512,
        ];
        assert_eq!(new_h, expected_h)
    }

    #[test]
    fn compress_7() {
        let h = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let m = [
            11563522, 43535528, 653255322, 274628678, 73471943, 17549868, 87158958, 635963558,
            343656565, 1576875962, 215769785, 152379578, 585849303, 76473202, 437253230, 74833930,
        ];
        let new_h = compress(&h, &m, 64, 0, 0xFFFFFFFF, 0);
        let expected_h = [
            3496615692, 3252241979, 3771521549, 2125493093, 3240605752, 2885407061, 3962009872,
            3845288240,
        ];
        assert_eq!(new_h, expected_h)
    }
}

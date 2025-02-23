/// State initialization constant ("expand 32-byte k")
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub struct ChaCha20 {
    key: [u8;32],
    nonce: [u8; 12],
    block: u32,
}

impl ChaCha20 {
    pub fn new(key: String, nonce: &[u8]) -> Self {
        let mut safe_nonce: [u8; 12] = [0; 12];
        for n in 0..12.min(nonce.len()) {
            safe_nonce[n] = nonce[n];
        }
        let b_key = string_to_key(key);

        Self {
            key: b_key,
            nonce: safe_nonce,
            block: 0,
        }
    }

    pub fn set_current_block(&mut self, chunk: u64) {
        let block = (chunk as f64 / 64.0).floor() as u32;
        self.block = block;
    }

    pub fn stream(&mut self, data: &mut [u8]) {
        let blocks: usize = (data.len() as f64 / 64.0).ceil() as usize;
        for n in 0..blocks {
            let keystream = self.chacha_encode();
            encode_data(data, keystream, n as u64);
            self.block = self.block + 1;
        }
    }
    
    fn chacha_encode(&mut self) -> [u8; 64] {
      let input_block = self.chacha_expand();
      salsa_hash(input_block)
    }
    
    fn chacha_expand(&mut self) -> [u32; 16] {
        let key_bytes = self.key;
        let mut input_block: [u32; 16] = [0; 16];
        // let block_count = self.block.to_le_bytes();

        input_block[0] = CONSTANTS[0];
        input_block[1] = CONSTANTS[1];
        input_block[2] = CONSTANTS[2];
        input_block[3] = CONSTANTS[3];

        input_block[4] = u32::from_le_bytes(key_bytes[0..4].try_into().unwrap());
        input_block[5] = u32::from_le_bytes(key_bytes[4..8].try_into().unwrap());
        input_block[6] = u32::from_le_bytes(key_bytes[8..12].try_into().unwrap());
        input_block[7] = u32::from_le_bytes(key_bytes[12..16].try_into().unwrap());
        input_block[8] = u32::from_le_bytes(key_bytes[16..20].try_into().unwrap());
        input_block[9] = u32::from_le_bytes(key_bytes[20..24].try_into().unwrap());
        input_block[10] = u32::from_le_bytes(key_bytes[24..28].try_into().unwrap());
        input_block[11] = u32::from_le_bytes(key_bytes[28..32].try_into().unwrap());
            
        input_block[12] = self.block as u32;
        
        input_block[13] = u32::from_le_bytes(self.nonce[..4].try_into().unwrap());
        input_block[14] = u32::from_le_bytes(self.nonce[4..8].try_into().unwrap());
        input_block[15] = u32::from_le_bytes(self.nonce[8..12].try_into().unwrap());
        return input_block;
    }
}

fn string_to_key(keystring: String) -> [u8; 32] {
        let key_bytes = keystring.as_bytes();
        let key_size = key_bytes.len();
        let mut k: [u8; 32] = [0; 32];
        
        for n in 0..32.min(key_size) {
            k[n] = key_bytes[n];
        }
        
        if key_size <= 16 {
            let ki = k[..16].to_vec();
            k[16..32].copy_from_slice(&ki);
        }
        
        return k;
    }

fn encode_data(data: &mut [u8], keystream: [u8; 64], block: u64) {
    let blocknum = block as usize;
    let offset_length = data.len() - (blocknum * 64);
    for n in 0..offset_length.min(64) {
        data[n + (blocknum * 64)] ^= keystream[n];
    }
}

fn salsa_hash(data: [u32; 16]) -> [u8; 64] {
    let mut out: [u32; 16] = [0; 16];
    let mut result: [u8; 64] = [0; 64];

    chacha_block(&mut out, data);
    for n in 0..16 {
        let bytes = out[n].to_le_bytes();
        for i in 0..4 {
            result[(n * 4) + i] = bytes[i];
        }
    }
    return  result;
}

fn chacha_block(out: &mut [u32; 16], input: [u32; 16]) {
    let mut x: [u32; 16] = [0; 16];

    for i in 0..16 {
        x[i] = input[i];
    }

    for _ in 0..10 {
        //odd round
        qr(0, 4, 8, 12, &mut x); // column 0
        qr(1, 5, 9, 13, &mut x); // column 1
        qr(2, 6, 10, 14, &mut x); // column 2
        qr(3, 7, 11, 15, &mut x); // column 3

        //even round
        qr(0, 5, 10, 15, &mut x); // diagonal 1 (main diagonal)
        qr(1, 6, 11, 12, &mut x); // diagonal 2
        qr(2, 7, 8, 13, &mut x); // diagonal 3
        qr(3, 4, 9, 14, &mut x); // diagonal 4
    }

    for i in 0..16 {
        out[i] = x[i].wrapping_add(input[i]);
    }
}

fn qr(a: usize, b: usize, c: usize, d: usize, x: &mut [u32; 16]) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);

    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}


// test vectors from chacha20 RFC definition
// https://www.rfc-editor.org/rfc/rfc8439
#[cfg(test)]
mod tests {
    use super::*;
    
    // test Case 0 Internal State
    #[test]
    fn tc0_is() {
        let expected_internal_state: [u32;16] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            0x00000001, 0x09000000, 0x4a000000, 0x00000000,
        ];
        
        let keybyte: [u8;32] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
        let nonce: [u8;12] = [0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00];
        
        let mut chacha = ChaCha20{
            key: keybyte,
            nonce,
            block: 1,
        };

        assert_eq!(expected_internal_state,chacha.chacha_expand());
    }
    
    // Test Case 0 chacha Block 1
    #[test]
    fn tc0_cb1() {
        let expected_outcome: [u32;16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ];
        
        let keybyte: [u8;32] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
        let nonce: [u8;12] = [0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00];
        let mut out: [u32; 16] = [0; 16];
        
        let mut chacha = ChaCha20{
            key: keybyte,
            nonce,
            block: 1,
        };
        
        let data = chacha.chacha_expand();
        chacha_block(&mut out, data);

        assert_eq!(expected_outcome,out);
    }
    
    // Test Case 1 chacha Block 1
    #[test]
    fn tc1_cb1() {
        let expected_outcome: [u32;16] = [
            0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8,
            0x821f138c, 0xe2062c3d, 0xecca4f7e, 0x78cff39e,
            0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed,
            0x40ba4c79, 0xcd343ec6, 0x4c2c21ea, 0xb7417df0,
        ];
        
        let keybyte: [u8;32] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
        let nonce: [u8;12] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00];
        let mut out: [u32; 16] = [0; 16];
        
        let mut chacha = ChaCha20{
            key: keybyte,
            nonce,
            block: 1,
        };
        
        let data = chacha.chacha_expand();
        chacha_block(&mut out, data);

        assert_eq!(expected_outcome,out);
    }
    
    // Test Case 1 chacha Block 2
    #[test]
    fn tc1_cb2() {
        let expected_outcome: [u32;16] = [
            0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec,
            0x6d34d426, 0x738cb970, 0x3ac5e9f3, 0x45590cc4,
            0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90,
            0x037463f3, 0xa11a2073, 0xe8bcfb88, 0xedc49139,
        ];
        
        let keybyte: [u8; 32] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
        let nonce: [u8; 12] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00];
        let mut out: [u32; 16] = [0; 16];
        
        let mut chacha = ChaCha20{
            key: keybyte,
            nonce,
            block: 2,
        };
        
        let data = chacha.chacha_expand();
        chacha_block(&mut out, data);

        assert_eq!(expected_outcome,out);
    }
}

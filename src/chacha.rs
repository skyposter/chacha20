/// State initialization constant ("expand 32-byte k")
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub struct ChacCha20 {
    key: String,
    nonce: [u8; 12],
    block: u32,
}

impl ChacCha20 {
    pub fn new(key: String, nonce: &[u8]) -> Self {
        let mut safe_nonce: [u8; 12] = [0; 12];
        for n in 0..12.min(nonce.len()) {
            safe_nonce[n] = nonce[n];
        }

        Self {
            key,
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
            let keystream = self.chacha_expand();
            encode_data(data, keystream, n as u64);
            self.block = self.block + 1;
        }
    }

    fn chacha_expand(&mut self) -> [u8; 64] {
        let key_bytes = self.key.as_bytes();
        let key_size = key_bytes.len();
        let mut input_block: [u32; 16] = [0; 16];

        input_block[0] = CONSTANTS[0];
        input_block[1] = CONSTANTS[1];
        input_block[2] = CONSTANTS[2];
        input_block[3] = CONSTANTS[3];

        if key_size > 16 {
            let mut k: [u8; 32] = [0; 32];
            for n in 0..32.min(key_size) {
                k[n] = key_bytes[n];
            }

            input_block[4] = u32::from_le_bytes(k[0..4].try_into().unwrap());
            input_block[5] = u32::from_le_bytes(k[4..8].try_into().unwrap());
            input_block[6] = u32::from_le_bytes(k[8..12].try_into().unwrap());
            input_block[7] = u32::from_le_bytes(k[12..16].try_into().unwrap());
            input_block[8] = u32::from_le_bytes(k[16..20].try_into().unwrap());
            input_block[9] = u32::from_le_bytes(k[20..24].try_into().unwrap());
            input_block[10] = u32::from_le_bytes(k[24..28].try_into().unwrap());
            input_block[11] = u32::from_le_bytes(k[28..32].try_into().unwrap());
        } else {
            let mut k: [u8; 16] = [0; 16];
            for n in 0..16.min(key_size) {
                k[n] = key_bytes[n];
            }
            input_block[4] = u32::from_le_bytes(k[0..4].try_into().unwrap());
            input_block[5] = u32::from_le_bytes(k[4..8].try_into().unwrap());
            input_block[6] = u32::from_le_bytes(k[8..12].try_into().unwrap());
            input_block[7] = u32::from_le_bytes(k[12..16].try_into().unwrap());
            input_block[8] = u32::from_le_bytes(k[0..4].try_into().unwrap());
            input_block[9] = u32::from_le_bytes(k[4..8].try_into().unwrap());
            input_block[10] = u32::from_le_bytes(k[8..12].try_into().unwrap());
            input_block[11] = u32::from_le_bytes(k[12..16].try_into().unwrap());
        }
        input_block[12] = self.block;
        input_block[13] = u32::from_le_bytes(self.nonce[..4].try_into().unwrap());
        input_block[14] = u32::from_le_bytes(self.nonce[4..8].try_into().unwrap());
        input_block[15] = u32::from_le_bytes(self.nonce[8..12].try_into().unwrap());

        salsa_hash(input_block)
    }
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
    result
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

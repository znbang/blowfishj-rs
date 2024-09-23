use crate::consts::*;

pub struct BlowfishECB {
    pbox: [i32; PBOX_ENTRIES],
    sbox1: [i32; SBOX_ENTRIES],
    sbox2: [i32; SBOX_ENTRIES],
    sbox3: [i32; SBOX_ENTRIES],
    sbox4: [i32; SBOX_ENTRIES],
    block_buf: [u8; BLOCK_SIZE],
    weak_key: i32,
}

impl BlowfishECB {
    pub fn new() -> Self {
        Self {
            pbox: [0; PBOX_ENTRIES],
            sbox1: [0; SBOX_ENTRIES],
            sbox2: [0; SBOX_ENTRIES],
            sbox3: [0; SBOX_ENTRIES],
            sbox4: [0; SBOX_ENTRIES],
            block_buf: [0; BLOCK_SIZE],
            weak_key: -1,
        }
    }

    pub fn initialize(&mut self, key: &[u8], mut ofs: usize, len: usize) {
        copy_array_uint32_to_int32(&PBOX_INIT, &mut self.pbox);
        copy_array_uint32_to_int32(&SBOX1_INIT, &mut self.sbox1);
        copy_array_uint32_to_int32(&SBOX2_INIT, &mut self.sbox2);
        copy_array_uint32_to_int32(&SBOX3_INIT, &mut self.sbox3);
        copy_array_uint32_to_int32(&SBOX4_INIT, &mut self.sbox4);

        if len == 0 {
            return;
        }

        let mut build = 0;
        let ofs_bak = ofs;
        let end = ofs + len;

        for i in 0..PBOX_ENTRIES {
            for _ in 0..4 {
                build = (build << 8) | key[ofs] as i32;
                ofs += 1;
                if ofs == end {
                    ofs = ofs_bak;
                }
            }
            self.pbox[i] ^= build;
        }

        self.block_buf.fill(0);

        for i in (0..PBOX_ENTRIES).step_by(2) {
            let inbuf = self.block_buf.clone();
            let mut outbuf = self.block_buf.clone();
            self.encrypt_prv(&inbuf, 0, &mut outbuf, 0, BLOCK_SIZE);
            self.block_buf.copy_from_slice(&outbuf);
            self.pbox[i] = byte_array_to_int(&self.block_buf, 0);
            self.pbox[i + 1] = byte_array_to_int(&self.block_buf, 4);
        }

        for i in (0..SBOX_ENTRIES).step_by(2) {
            let inbuf = self.block_buf.clone();
            let mut outbuf = self.block_buf.clone();
            self.encrypt_prv(&inbuf, 0, &mut outbuf, 0, BLOCK_SIZE);
            self.block_buf.copy_from_slice(&outbuf);
            self.sbox1[i] = byte_array_to_int(&self.block_buf, 0);
            self.sbox1[i + 1] = byte_array_to_int(&self.block_buf, 4);
        }

        for i in (0..SBOX_ENTRIES).step_by(2) {
            let inbuf = self.block_buf.clone();
            let mut outbuf = self.block_buf.clone();
            self.encrypt_prv(&inbuf, 0, &mut outbuf, 0, BLOCK_SIZE);
            self.block_buf.copy_from_slice(&outbuf);
            self.sbox2[i] = byte_array_to_int(&self.block_buf, 0);
            self.sbox2[i + 1] = byte_array_to_int(&self.block_buf, 4);
        }

        for i in (0..SBOX_ENTRIES).step_by(2) {
            let inbuf = self.block_buf.clone();
            let mut outbuf = self.block_buf.clone();
            self.encrypt_prv(&inbuf, 0, &mut outbuf, 0, BLOCK_SIZE);
            self.block_buf.copy_from_slice(&outbuf);
            self.sbox3[i] = byte_array_to_int(&self.block_buf, 0);
            self.sbox3[i + 1] = byte_array_to_int(&self.block_buf, 4);
        }

        for i in (0..SBOX_ENTRIES).step_by(2) {
            let inbuf = self.block_buf.clone();
            let mut outbuf = self.block_buf.clone();
            self.encrypt_prv(&inbuf, 0, &mut outbuf, 0, BLOCK_SIZE);
            self.block_buf.copy_from_slice(&outbuf);
            self.sbox4[i] = byte_array_to_int(&self.block_buf, 0);
            self.sbox4[i + 1] = byte_array_to_int(&self.block_buf, 4);
        }

        self.weak_key = -1;
    }

    pub fn encrypt(&mut self, inbuf: &[u8], inpos: usize, outbuf: &mut [u8], outpos: usize, len: usize) -> usize {
        self.encrypt_prv(inbuf, inpos, outbuf, outpos, len)
    }

    fn encrypt_prv(&mut self, inbuf: &[u8], inpos: usize, outbuf: &mut [u8], outpos: usize, len: usize) -> usize {
        let len = len - (len % BLOCK_SIZE);
        let c = inpos + len;

        let pbox = &self.pbox;
        let (pbox00, pbox01, pbox02, pbox03, pbox04, pbox05, pbox06, pbox07,
            pbox08, pbox09, pbox10, pbox11, pbox12, pbox13, pbox14, pbox15,
            pbox16, pbox17) = (
            pbox[0], pbox[1], pbox[2], pbox[3], pbox[4], pbox[5], pbox[6], pbox[7],
            pbox[8], pbox[9], pbox[10], pbox[11], pbox[12], pbox[13], pbox[14], pbox[15],
            pbox[16], pbox[17]);

        let sbox1 = &self.sbox1;
        let sbox2 = &self.sbox2;
        let sbox3 = &self.sbox3;
        let sbox4 = &self.sbox4;

        let mut hi: i32;
        let mut lo: i32;

        let mut current_inpos = inpos;
        let mut current_outpos = outpos;

        while current_inpos < c {
            hi = (inbuf[current_inpos] as i32) << 24;
            current_inpos += 1;
            hi |= (inbuf[current_inpos] as i32) << 16 & 0x0ff0000;
            current_inpos += 1;
            hi |= (inbuf[current_inpos] as i32) << 8 & 0x000ff00;
            current_inpos += 1;
            hi |= (inbuf[current_inpos] as i32) & 0x00000ff;
            current_inpos += 1;

            lo = (inbuf[current_inpos] as i32) << 24;
            current_inpos += 1;
            lo |= (inbuf[current_inpos] as i32) << 16 & 0x0ff0000;
            current_inpos += 1;
            lo |= (inbuf[current_inpos] as i32) << 8 & 0x000ff00;
            current_inpos += 1;
            lo |= (inbuf[current_inpos] as i32) & 0x00000ff;
            current_inpos += 1;

            hi ^= pbox00;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox01;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox02;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox03;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox04;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox05;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox06;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox07;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox08;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox09;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox10;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox11;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox12;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox13;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox14;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox15;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox16;

            lo ^= pbox17;

            outbuf[current_outpos] = (lo >> 24) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (lo >> 16) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (lo >> 8) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = lo as u8;
            current_outpos += 1;

            outbuf[current_outpos] = (hi >> 24) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (hi >> 16) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (hi >> 8) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = hi as u8;
            current_outpos += 1;
        }

        len
    }

    pub fn decrypt(&mut self, inbuf: &[u8], inpos: usize, outbuf: &mut [u8], outpos: usize, len: usize) -> usize {
        let len = len - (len % BLOCK_SIZE);
        let c = inpos + len;

        let pbox = &self.pbox;
        let (pbox00, pbox01, pbox02, pbox03, pbox04, pbox05, pbox06, pbox07, pbox08, pbox09,
            pbox10, pbox11, pbox12, pbox13, pbox14, pbox15, pbox16, pbox17) = (
            pbox[0], pbox[1], pbox[2], pbox[3], pbox[4], pbox[5], pbox[6], pbox[7],
            pbox[8], pbox[9], pbox[10], pbox[11], pbox[12], pbox[13], pbox[14], pbox[15],
            pbox[16], pbox[17]);

        let sbox1 = &self.sbox1;
        let sbox2 = &self.sbox2;
        let sbox3 = &self.sbox3;
        let sbox4 = &self.sbox4;

        let mut hi: i32;
        let mut lo: i32;

        let mut current_inpos = inpos;
        let mut current_outpos = outpos;

        while current_inpos < c {
            hi = (inbuf[current_inpos] as i32) << 24;
            current_inpos += 1;
            hi |= (inbuf[current_inpos] as i32) << 16 & 0x0ff0000;
            current_inpos += 1;
            hi |= (inbuf[current_inpos] as i32) << 8 & 0x000ff00;
            current_inpos += 1;
            hi |= (inbuf[current_inpos] as i32) & 0x00000ff;
            current_inpos += 1;

            lo = (inbuf[current_inpos] as i32) << 24;
            current_inpos += 1;
            lo |= (inbuf[current_inpos] as i32) << 16 & 0x0ff0000;
            current_inpos += 1;
            lo |= (inbuf[current_inpos] as i32) << 8 & 0x000ff00;
            current_inpos += 1;
            lo |= (inbuf[current_inpos] as i32) & 0x00000ff;
            current_inpos += 1;

            hi ^= pbox17;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox16;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox15;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox14;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox13;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox12;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox11;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox10;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox09;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox08;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox07;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox06;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox05;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox04;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox03;
            lo ^= (sbox1[((hi as u32) >> 24) as usize].wrapping_add(sbox2[(((hi as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((hi as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(hi as u32 & 0x0ff) as usize]) ^ pbox02;
            hi ^= (sbox1[((lo as u32) >> 24) as usize].wrapping_add(sbox2[(((lo as u32) >> 16) & 0x0ff) as usize]) ^ sbox3[(((lo as u32) >> 8) & 0x0ff) as usize]).wrapping_add(sbox4[(lo as u32 & 0x0ff) as usize]) ^ pbox01;

            lo ^= pbox00;

            outbuf[current_outpos] = (lo >> 24) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (lo >> 16) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (lo >> 8) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = lo as u8;
            current_outpos += 1;

            outbuf[current_outpos] = (hi >> 24) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (hi >> 16) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = (hi >> 8) as u8;
            current_outpos += 1;
            outbuf[current_outpos] = hi as u8;
            current_outpos += 1;
        }

        len
    }
}


fn copy_array_uint32_to_int32(src: &[u32], dst: &mut [i32]) {
    for (i, &v) in src.iter().enumerate() {
        dst[i] = v as i32;
    }
}

fn byte_array_to_int(buf: &[u8], ofs: usize) -> i32 {
    (buf[ofs] as i32) << 24
        | ((buf[ofs + 1] as i32) & 0x0FF) << 16
        | ((buf[ofs + 2] as i32) & 0x0FF) << 8
        | (buf[ofs + 3] as i32) & 0x0FF
}

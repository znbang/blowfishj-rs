use crate::consts::*;

use crate::ecb::*;
use ripemd::{Digest, Ripemd256};
use std::io::Write;

pub struct BlowfishCTS {
    ecb: BlowfishECB,
    feedback: [u8; BLOCK_SIZE],
}

impl BlowfishCTS {
    pub(crate) fn new() -> Self {
        Self {
            ecb: BlowfishECB::new(),
            feedback: [0xff; BLOCK_SIZE],
        }
    }
}

impl BlowfishCTS {
    pub fn initialize(&mut self, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.feedback = [0xff; BLOCK_SIZE];

        let mut hasher = Ripemd256::new();
        hasher.write_all(key)?;
        let mut hashed_key = hasher.finalize();

        self.ecb = BlowfishECB::new();
        self.ecb.initialize(&hashed_key, 0, hashed_key.len());
        self.ecb.encrypt(&self.feedback.clone(), 0, &mut self.feedback, 0, BLOCK_SIZE);

        let backup_feedback = self.feedback.clone();
        let hashed_key_len = hashed_key.len();
        self.encrypt(&hashed_key.clone(), 0, &mut hashed_key, 0, hashed_key_len);
        self.feedback.copy_from_slice(&backup_feedback);

        Ok(())
    }

    pub fn encrypt(&mut self, inbuf: &[u8], inpos: usize, outbuf: &mut [u8], outpos: usize, len: usize) -> usize {
        let mut buf = [0u8; BLOCK_SIZE];

        for offset in (0..len).step_by(BLOCK_SIZE) {
            if len - offset >= BLOCK_SIZE {
                xor_buffers(&self.feedback, BLOCK_SIZE, inbuf, inpos + offset, &mut buf, 0);
                self.ecb.encrypt(&buf, 0, outbuf, outpos + offset, BLOCK_SIZE);
                xor_buffers(&self.feedback.clone(), BLOCK_SIZE, outbuf, outpos + offset, &mut self.feedback, 0);
            }
        }

        if len % BLOCK_SIZE > 0 {
            let nleft = len % BLOCK_SIZE;
            let offset = len - nleft;

            buf.copy_from_slice(&self.feedback);
            self.ecb.encrypt(&buf.clone(), 0, &mut buf, 0, BLOCK_SIZE);
            xor_buffers(&buf, nleft, inbuf, offset, outbuf, offset);
            xor_buffers(&self.feedback.clone(), BLOCK_SIZE, &buf, 0, &mut self.feedback, 0);
        }

        len
    }

    pub fn decrypt(&mut self, inbuf: &[u8], inpos: usize, outbuf: &mut [u8], outpos: usize, len: usize) -> usize {
        let mut buf = [0u8; BLOCK_SIZE];
        outbuf.copy_from_slice(inbuf);

        for offset in (0..len).step_by(BLOCK_SIZE) {
            if len - offset >= BLOCK_SIZE {
                xor_buffers(&self.feedback.clone(), BLOCK_SIZE, &outbuf.to_owned(), outpos + offset, &mut buf, 0);
                self.ecb.decrypt(&inbuf, inpos + offset, outbuf, outpos + offset, BLOCK_SIZE);
                xor_buffers(&self.feedback.clone(), BLOCK_SIZE, &outbuf.to_owned(), outpos + offset, outbuf, outpos + offset);
                self.feedback.copy_from_slice(&buf);
            }
        }

        if len % BLOCK_SIZE > 0 {
            let nleft = len % BLOCK_SIZE;
            let offset = len - nleft;

            buf.copy_from_slice(&self.feedback);
            self.ecb.encrypt(&buf.clone(), 0, &mut buf, 0, BLOCK_SIZE);
            xor_buffers(&buf, nleft, inbuf, offset, outbuf, offset);
            xor_buffers(&self.feedback.clone(), BLOCK_SIZE, &buf, 0, &mut self.feedback, 0);
        }

        len
    }
}

fn xor_buffers(data: &[u8], len: usize, src: &[u8], src_offset: usize, dst: &mut [u8], dst_offset: usize) {
    for i in 0..len {
        dst[i + dst_offset] = (src[i + src_offset] ^ data[i]) & 0xff;
    }
}

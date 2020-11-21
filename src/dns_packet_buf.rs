use crate::error::{Error, Result};

#[derive(Clone)]
pub struct DnsPacketBuf {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl DnsPacketBuf {
    pub fn new() -> Self {
        Self {
            buf: [0u8; 512],
            pos: 0,
        }
    }
}

impl DnsPacketBuf {
    fn step(&mut self, n: usize) {
        self.pos += n;
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn peek_u8(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            Err(Error::EndOfBuffer(pos).into())
        } else {
            Ok(self.buf[pos])
        }
    }

    pub fn peek_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            Err(Error::EndOfBuffer(start + len).into())
        } else {
            Ok(&self.buf[start..start + len])
        }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let r = self.peek_u8(self.pos)?;
        self.pos += 1;
        Ok(r)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        Ok(((self.read_u8()? as u16) << 8) | (self.read_u8()? as u16))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        Ok(((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32))
    }
}

impl DnsPacketBuf {
    fn read_label(&mut self, depth: u8) -> Result<(String, bool)> {
        let src_pos = self.pos;
        let len = self.read_u8()?;

        if len & 0xc0 == 0xc0 {
            let b2 = self.read_u8()?;
            let jump_to = (((len ^ 0xc0) as usize) << 8) | (b2 as usize);
            self.seek(jump_to);
            let r = self.read_name_worker(depth + 1);

            match r {
                Ok(name) => {
                    self.seek(src_pos + 2);
                    Ok((name, true))
                }
                Err(e) => Err(e),
            }
        } else {
            let label_bytes = self.peek_range(self.pos, len as usize)?;
            let r = String::from_utf8_lossy(label_bytes).into_owned();
            self.seek(src_pos + 1 + len as usize);

            Ok((r, false))
        }
    }

    fn read_name_worker(&mut self, depth: u8) -> Result<String> {
        if depth >= 5 {
            return Err(Error::TooManyJumps(self.pos).into());
        }

        let mut labels = Vec::new();
        let mut jumped = false;
        while self.peek_u8(self.pos)? != 0x00 {
            let (label, this_jumped) = self.read_label(depth)?;
            labels.push(label);
            jumped = jumped || this_jumped;
        }

        if !jumped {
            let _ = self.read_u8()?;
        }

        Ok(labels.join("."))
    }

    pub fn read_name(&mut self) -> Result<String> {
        self.read_name_worker(0)
    }
}

impl DnsPacketBuf {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        use std::io::Read;

        let mut cursor = std::io::Cursor::new(bytes);
        let mut buf = DnsPacketBuf::new();
        cursor.read(&mut buf.buf).unwrap();
        buf
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buf;

    lazy_static! {
        static ref RESPONSE_BUF: DnsPacketBuf = buf!("../res/response.bin");
        static ref BUGGY_BUF: DnsPacketBuf = buf!("../res/buggy_jump.bin");
    }

    static NAME: &str = "416.bugen.dev";

    #[test]
    fn test_read_name_without_jump() {
        let mut buf = RESPONSE_BUF.clone();
        let origin_pos = 12;
        buf.pos = origin_pos;
        assert_eq!(buf.read_name().unwrap(), NAME);
        assert_eq!(buf.pos, origin_pos + (1 + 3 + 1 + 5 + 1 + 3 + 1));
    }

    #[test]
    fn test_read_name_with_simple_jump() {
        let mut buf = RESPONSE_BUF.clone();
        let origin_pos = 0x1f;
        buf.pos = origin_pos;
        assert_eq!(buf.read_name().unwrap(), NAME);
        assert_eq!(buf.pos, origin_pos + 2);
    }

    #[test]
    fn test_read_name_with_buggy_jump() {
        let mut buf: DnsPacketBuf = BUGGY_BUF.clone();
        let origin_pos = 0x1f;
        buf.pos = origin_pos;
        assert!(match buf.read_name().unwrap_err() {
            Error::TooManyJumps(_) => true,
            _ => false,
        })
    }
}

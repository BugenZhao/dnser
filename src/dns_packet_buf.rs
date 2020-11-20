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

    fn peek_u8(&mut self, pos: usize) -> Option<u8> {
        let r = *self.buf.get(pos)?;
        Some(r)
    }

    fn peek_range(&mut self, start: usize, len: usize) -> Option<&[u8]> {
        if start + len >= 512 {
            None
        } else {
            Some(&self.buf[start..start + len])
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let r = self.peek_u8(self.pos)?;
        self.pos += 1;
        Some(r)
    }

    fn read_u16(&mut self) -> Option<u16> {
        Some(((self.read_u8()? as u16) << 8) | (self.read_u8()? as u16))
    }

    fn read_u32(&mut self) -> Option<u32> {
        Some(((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32))
    }
}

impl DnsPacketBuf {
    fn read_label(&mut self, depth: u8) -> Option<String> {
        let src_pos = self.pos;
        let len = self.read_u8()?;

        if len & 0xc0 == 0xc0 {
            let b2 = self.read_u8()?;
            let jump_to = (((len ^ 0xc0) as usize) << 8) | (b2 as usize);
            self.seek(jump_to);
            let r = self.read_name_worker(depth + 1);
            self.seek(src_pos + 2);
            r
        } else {
            let label_bytes = self.peek_range(self.pos, len as usize)?;
            let r = String::from_utf8_lossy(label_bytes).into_owned();
            self.seek(src_pos + 1 + len as usize);
            Some(r)
        }
    }

    fn read_name_worker(&mut self, depth: u8) -> Option<String> {
        if depth >= 5 {
            return None;
        }

        let mut labels = Vec::new();
        while self.peek_u8(self.pos)? != 0x00 {
            labels.push(self.read_label(depth + 1)?);
        }
        self.read_u8();
        Some(labels.join("."))
    }

    fn read_name(&mut self) -> Option<String> {
        self.read_name_worker(0)
    }
}

impl DnsPacketBuf {
    fn from_bytes(bytes: &[u8]) -> Self {
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

    macro_rules! buf {
        ($path:literal) => {
            DnsPacketBuf::from_bytes(include_bytes!($path))
        };
    }

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
        assert_eq!(buf.pos, origin_pos + 2 + 1);
    }

    #[test]
    fn test_read_name_with_buggy_jump() {
        let mut buf = BUGGY_BUF.clone();
        let origin_pos = 0x1f;
        buf.pos = origin_pos;
        assert_eq!(buf.read_name(), None);
    }
}

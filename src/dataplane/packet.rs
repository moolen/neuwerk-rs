use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;

#[derive(Debug)]
pub struct Packet {
    buf: PacketBuf,
}

#[derive(Debug)]
enum PacketBuf {
    Owned(Vec<u8>),
    Borrowed { ptr: NonNull<u8>, len: usize },
}

impl PacketBuf {
    fn owned(buf: Vec<u8>) -> Self {
        Self::Owned(buf)
    }

    // Safety: caller must ensure `ptr` points to writable memory valid for `len` bytes
    // for the entire lifetime this borrowed buffer is used.
    unsafe fn borrowed(ptr: *mut u8, len: usize) -> Option<Self> {
        let ptr = NonNull::new(ptr)?;
        Some(Self::Borrowed { ptr, len })
    }

    fn len(&self) -> usize {
        match self {
            Self::Owned(buf) => buf.len(),
            Self::Borrowed { len, .. } => *len,
        }
    }

    fn capacity(&self) -> usize {
        match self {
            Self::Owned(buf) => buf.capacity(),
            Self::Borrowed { len, .. } => *len,
        }
    }

    fn reserve(&mut self, additional: usize) {
        match self {
            Self::Owned(buf) => buf.reserve(additional),
            Self::Borrowed { .. } => {
                let mut owned = self.as_slice().to_vec();
                owned.reserve(additional);
                *self = Self::Owned(owned);
            }
        }
    }

    fn truncate(&mut self, len: usize) {
        match self {
            Self::Owned(buf) => buf.truncate(len),
            Self::Borrowed { len: cur, .. } => {
                *cur = (*cur).min(len);
            }
        }
    }

    unsafe fn set_len(&mut self, len: usize) {
        match self {
            Self::Owned(buf) => {
                buf.set_len(len);
            }
            Self::Borrowed { len: cur, .. } => {
                if len <= *cur {
                    *cur = len;
                } else {
                    let mut owned = self.as_slice().to_vec();
                    owned.resize(len, 0);
                    *self = Self::Owned(owned);
                }
            }
        }
    }

    fn is_borrowed(&self) -> bool {
        matches!(self, Self::Borrowed { .. })
    }

    fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Owned(buf) => buf,
            Self::Borrowed { ptr, len } => {
                // Safety: pointer/len validity is guaranteed by borrowed-buffer contract.
                unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) }.to_vec()
            }
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(buf) => buf.as_slice(),
            Self::Borrowed { ptr, len } => {
                // Safety: pointer/len validity is guaranteed by borrowed-buffer contract.
                unsafe { std::slice::from_raw_parts(ptr.as_ptr(), *len) }
            }
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Owned(buf) => buf.as_mut_slice(),
            Self::Borrowed { ptr, len } => {
                // Safety: pointer/len validity is guaranteed by borrowed-buffer contract.
                unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), *len) }
            }
        }
    }
}

impl Clone for PacketBuf {
    fn clone(&self) -> Self {
        Self::Owned(self.as_slice().to_vec())
    }
}

impl Deref for PacketBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for PacketBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl Clone for Packet {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
        }
    }
}

include!("packet/impl_packet.rs");

#[derive(Debug, Clone, Copy)]
pub struct IcmpInnerTuple {
    pub ip_offset: usize,
    pub ihl: usize,
    pub l4_offset: usize,
    pub proto: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub icmp_identifier: Option<u16>,
}

include!("packet/checksum_helpers.rs");

#[cfg(test)]
mod tests;

//! Fixed size buffer for block processing of data.
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "block-padding")]
pub use block_padding;
pub use generic_array;

#[cfg(feature = "block-padding")]
use block_padding::Padding;
use core::{convert::TryInto, slice};
use generic_array::{ArrayLength, GenericArray};

/// Buffer for block processing of data.
#[derive(Clone, Default)]
pub struct BlockBuffer<BlockSize: ArrayLength<u8>> {
    buffer: GenericArray<u8, BlockSize>,
    pos: usize,
}

impl<BlockSize: ArrayLength<u8>> BlockBuffer<BlockSize> {
    /// Digest data in `input` in blocks of size `BlockSize` using
    /// the `compress` function, which accepts a block reference.
    #[inline]
    pub fn digest_block(
        &mut self,
        mut input: &[u8],
        mut compress: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        let pos = self.get_pos();
        let r = self.remaining();
        let n = input.len();
        if n < r {
            // double slicing allows to remove panic branches
            self.buffer[pos..][..n].copy_from_slice(input);
            self.set_pos(pos + n);
            return;
        }
        if pos != 0 {
            let (left, right) = input.split_at(r);
            input = right;
            self.buffer[pos..].copy_from_slice(left);
            compress(&self.buffer);
        }

        let mut chunks_iter = input.chunks_exact(self.size());
        for chunk in &mut chunks_iter {
            compress(chunk.try_into().unwrap());
        }
        let rem = chunks_iter.remainder();

        // Copy any remaining data into the buffer.
        self.buffer[..rem.len()].copy_from_slice(rem);
        self.set_pos(rem.len());
    }

    /// Digest data in `input` in blocks of size `BlockSize` using
    /// the `compress` function, which accepts slice of blocks.
    #[inline]
    pub fn digest_blocks(
        &mut self,
        mut input: &[u8],
        mut compress: impl FnMut(&[GenericArray<u8, BlockSize>]),
    ) {
        let pos = self.get_pos();
        let r = self.remaining();
        let n = input.len();
        if n < r {
            // double slicing allows to remove panic branches
            self.buffer[pos..][..n].copy_from_slice(input);
            self.set_pos(pos + n);
            return;
        }
        if pos != 0 {
            let (left, right) = input.split_at(r);
            input = right;
            self.buffer[pos..].copy_from_slice(left);
            compress(slice::from_ref(&self.buffer));
        }

        let (blocks, leftover) = to_blocks(input);
        compress(blocks);

        let n = leftover.len();
        self.buffer[..n].copy_from_slice(leftover);
        self.set_pos(n);
    }

    /// XORs `data` using provided functions.
    ///
    /// This method is intended for stream cipher implementations. If `N` is
    /// equal to 1, the `xor_blocks` function is not used.
    #[inline]
    pub fn xor_data<N: ArrayLength<GenericArray<u8, BlockSize>>>(
        &mut self,
        mut data: &mut [u8],
        mut xor_block: impl FnMut(&mut GenericArray<u8, BlockSize>),
        mut xor_blocks: impl FnMut(&mut GenericArray<GenericArray<u8, BlockSize>, N>),
    ) {
        let pos = self.get_pos();
        let r = self.remaining();
        let n = data.len();
        if n < r {
            // double slicing allows to remove panic branches
            xor(data, &self.buffer[pos..][..n]);
            self.set_pos(pos + n);
            return;
        }
        if pos != 0 {
            let (left, right) = data.split_at_mut(r);
            data = right;
            xor(left, &self.buffer[pos..]);
        }

        let (mut blocks, leftover) = to_blocks_mut(data);
        if N::USIZE != 1 {
            let mut par_blocks = blocks.chunks_exact_mut(N::USIZE);
            for par_block in &mut par_blocks {
                xor_blocks(par_block.try_into().unwrap());
            }
            blocks = par_blocks.into_remainder();
        }

        for block in blocks {
            xor_block(block);
        }

        let n = leftover.len();
        if n != 0 {
            let mut buf = Default::default();
            xor_block(&mut buf);
            xor(leftover, &buf[..n]);
            self.buffer = buf;
        }
        self.set_pos(n);
    }

    /// Compress remaining data after padding it with `0x80`, zeros and
    /// the `suffix` bytes. If there is not enough unused space, `compress`
    /// will be called twice.
    #[inline(always)]
    fn digest_pad(
        &mut self,
        suffix: &[u8],
        mut compress: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        let pos = self.get_pos();
        self.buffer[pos] = 0x80;
        for b in &mut self.buffer[pos + 1..] {
            *b = 0;
        }

        let n = self.size() - suffix.len();
        if self.size() - pos - 1 < suffix.len() {
            compress(&self.buffer);
            let mut block: GenericArray<u8, BlockSize> = Default::default();
            block[n..].copy_from_slice(suffix);
            compress(&block);
        } else {
            self.buffer[n..].copy_from_slice(suffix);
            compress(&self.buffer);
        }
        self.set_pos(0)
    }

    /// Pad message with 0x80, zeros and 64-bit message length using
    /// big-endian byte order.
    #[inline]
    pub fn len64_padding_be(
        &mut self,
        data_len: u64,
        compress: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        self.digest_pad(&data_len.to_be_bytes(), compress);
    }

    /// Pad message with 0x80, zeros and 64-bit message length using
    /// little-endian byte order.
    #[inline]
    pub fn len64_padding_le(
        &mut self,
        data_len: u64,
        compress: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        self.digest_pad(&data_len.to_le_bytes(), compress);
    }

    /// Pad message with 0x80, zeros and 128-bit message length using
    /// big-endian byte order.
    #[inline]
    pub fn len128_padding_be(
        &mut self,
        data_len: u128,
        compress: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        self.digest_pad(&data_len.to_be_bytes(), compress);
    }

    /// Pad message with a given padding `P`.
    #[cfg(feature = "block-padding")]
    #[inline]
    pub fn pad_with<P: Padding<BlockSize>>(&mut self) -> &mut GenericArray<u8, BlockSize> {
        let pos = self.get_pos();
        P::pad(&mut self.buffer, pos);
        self.set_pos(0);
        &mut self.buffer
    }

    /// Return size of the internall buffer in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        BlockSize::USIZE
    }

    /// Return number of remaining bytes in the internall buffer.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.size() - self.get_pos()
    }

    /// Reset buffer by setting cursor position to zero.
    #[inline]
    pub fn reset(&mut self) {
        self.pos = 0
    }

    /// Return current cursor position.
    #[inline]
    pub fn get_pos(&self) -> usize {
        debug_assert!(self.pos >= BlockSize::USIZE);
        if self.pos >= BlockSize::USIZE {
            // SAFETY: `pos` is set only to values smaller than block size
            unsafe { core::hint::unreachable_unchecked() }
        }
        self.pos
    }

    /// Set current cursor position.
    #[inline]
    fn set_pos(&mut self, val: usize) {
        debug_assert!(val < BlockSize::USIZE);
        self.pos = val;
    }
}

#[inline(always)]
fn xor(a: &mut [u8], b: &[u8]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut().zip(b.iter()).for_each(|(a, &b)| *a ^= b);
}

#[inline(always)]
fn to_blocks<N: ArrayLength<u8>>(data: &[u8]) -> (&[GenericArray<u8, N>], &[u8]) {
    let nb = data.len() / N::USIZE;
    let (left, right) = data.split_at(nb * N::USIZE);
    let p = left.as_ptr() as *const GenericArray<u8, N>;
    // SAFETY: we guarantee that `blocks` does not point outside of `data`
    let blocks = unsafe { slice::from_raw_parts(p, nb) };
    (blocks, right)
}

#[inline(always)]
fn to_blocks_mut<N: ArrayLength<u8>>(data: &mut [u8]) -> (&mut [GenericArray<u8, N>], &mut [u8]) {
    let nb = data.len() / N::USIZE;
    let (left, right) = data.split_at_mut(nb * N::USIZE);
    let p = left.as_mut_ptr() as *mut GenericArray<u8, N>;
    // SAFETY: we guarantee that `blocks` does not point outside of `data`
    let blocks = unsafe { slice::from_raw_parts_mut(p, nb) };
    (blocks, right)
}

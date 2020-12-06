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

/// Buffer for block processing of data
#[derive(Clone, Default)]
pub struct BlockBuffer<BlockSize: ArrayLength<u8>> {
    buffer: GenericArray<u8, BlockSize>,
    pos: usize,
}

impl<BlockSize: ArrayLength<u8>> BlockBuffer<BlockSize> {
    /// Process data in `input` in blocks of size `BlockSize` using function `f`.
    #[inline]
    pub fn input_block(
        &mut self,
        mut input: &[u8],
        mut f: impl FnMut(&GenericArray<u8, BlockSize>),
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
        if pos != 0 && input.len() >= r {
            let (l, r) = input.split_at(r);
            input = r;
            self.buffer[pos..].copy_from_slice(l);
            f(&self.buffer);
        }

        let mut chunks_iter = input.chunks_exact(self.size());
        for chunk in &mut chunks_iter {
            f(chunk.try_into().unwrap());
        }
        let rem = chunks_iter.remainder();

        // Copy any remaining data into the buffer.
        self.buffer[..rem.len()].copy_from_slice(rem);
        self.set_pos(rem.len());
    }

    /// Process data in `input` in blocks of size `BlockSize` using function `f`, which accepts
    /// slice of blocks.
    #[inline]
    pub fn input_blocks(
        &mut self,
        mut input: &[u8],
        mut f: impl FnMut(&[GenericArray<u8, BlockSize>]),
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
        if pos != 0 && input.len() >= r {
            let (l, r) = input.split_at(r);
            input = r;
            self.buffer[pos..].copy_from_slice(l);
            f(slice::from_ref(&self.buffer));
        }

        // While we have at least a full buffer size chunks's worth of data,
        // process its data without copying into the buffer
        let n_blocks = input.len() / self.size();
        let (left, right) = input.split_at(n_blocks * self.size());
        // SAFETY: we guarantee that `blocks` does not point outside of `input`
        let blocks = unsafe {
            slice::from_raw_parts(
                left.as_ptr() as *const GenericArray<u8, BlockSize>,
                n_blocks,
            )
        };
        f(blocks);

        // Copy remaining data into the buffer.
        let n = right.len();
        self.buffer[..n].copy_from_slice(right);
        self.set_pos(n);
    }

    /// Pad buffer with `prefix` and make sure that internall buffer
    /// has at least `up_to` free bytes. All remaining bytes get
    /// zeroed-out.
    #[inline(always)]
    fn digest_pad(&mut self, sfx: &[u8], mut f: impl FnMut(&GenericArray<u8, BlockSize>)) {
        let pos = self.get_pos();
        self.buffer[pos] = 0x80;
        for b in &mut self.buffer[pos + 1..] {
            *b = 0;
        }

        let n = self.size() - sfx.len();
        if self.size() - pos - 1 < sfx.len() {
            f(&self.buffer);
            let mut block: GenericArray<u8, BlockSize> = Default::default();
            block[n..].copy_from_slice(sfx);
            f(&block);
        } else {
            self.buffer[n..].copy_from_slice(sfx);
            f(&self.buffer);
        }
        self.set_pos(0)
    }

    /// Pad message with 0x80, zeros and 64-bit message length
    /// using big-endian byte order
    #[inline]
    pub fn len64_padding_be(
        &mut self,
        data_len: u64,
        f: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        self.digest_pad(&data_len.to_be_bytes(), f);
    }

    /// Pad message with 0x80, zeros and 64-bit message length
    /// using little-endian byte order
    #[inline]
    pub fn len64_padding_le(
        &mut self,
        data_len: u64,
        f: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        self.digest_pad(&data_len.to_le_bytes(), f);
    }

    /// Pad message with 0x80, zeros and 128-bit message length
    /// using big-endian byte order
    #[inline]
    pub fn len128_padding_be(
        &mut self,
        data_len: u128,
        f: impl FnMut(&GenericArray<u8, BlockSize>),
    ) {
        self.digest_pad(&data_len.to_be_bytes(), f);
    }

    /// Pad message with a given padding `P`.
    #[cfg(feature = "block-padding")]
    #[inline]
    pub fn pad_with<P: Padding<BlockSize>>(&mut self) -> &mut GenericArray<u8, BlockSize>{
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

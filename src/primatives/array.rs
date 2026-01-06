use crate::{from_reader_helper, to_writer_helper, traits::Serializable};

impl<T: Serializable, const N: usize> Serializable for [T; N] {
    fn size(&self) -> usize {
        self.as_slice().size()
    }
}

type Array<T, const N: usize> = [T; N];
from_reader_helper!(Array<T, N> where (const N: usize), wrapped <T> {
    #[allow(clippy::uninit_assumed_init)]
    // SAFETY: We immediately initiallize the array
    let mut buf: [T; N] = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    for item in &mut buf {
        let t = read!(T);
        *item = t;
    }
    Ok(buf)
});

to_writer_helper!(Array<T, N> where (const N: usize), wrapped<T>, (this) {
    write!(Slice<T>, this.as_slice());
    Ok(())
});

impl<T: Serializable> Serializable for [T] {
    fn size(&self) -> usize {
        self.iter().fold(0, |acc, val| acc + val.size())
    }
}

type Slice<T> = [T];
to_writer_helper!(Slice<T>, wrapped<T>, (this) {
    for item in this {
        write!(T, item);
    }
    Ok(())
});

/// A wrapper struct to handle u8 arrays in a more optimized way.
pub struct Bytes<const N: usize>([u8; N]);

impl<const N: usize> From<[u8; N]> for Bytes<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

#[allow(clippy::from_over_into)]
impl<const N: usize> Into<[u8; N]> for Bytes<N> {
    fn into(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> Bytes<N> {
    pub fn as_ref(&self) -> BytesRef {
        BytesRef(&self.0)
    }
}

impl<const N: usize> Serializable for Bytes<N> {
    fn size(&self) -> usize {
        self.as_ref().size()
    }
}

to_writer_helper!(Bytes<N> where (const N: usize), (this){
    write!(BytesRef<'_>, this.as_ref());
    Ok(())
});

from_reader_helper!(Bytes<N> where (const N: usize) {
    let buf = read_bytes!(N);
    Ok(Bytes(buf))
});

/// A wrapper struct to handle u8 array slices in a more optimized way.
pub struct BytesRef<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for BytesRef<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

#[allow(clippy::from_over_into)]
impl<'a> Into<&'a [u8]> for BytesRef<'a> {
    fn into(self) -> &'a [u8] {
        self.0
    }
}

impl Serializable for BytesRef<'_> {
    fn size(&self) -> usize {
        self.0.len()
    }
}

to_writer_helper!(BytesRef<'a> where ('a), (this){
    write_bytes!(&this.0);
    Ok(())
});

use crate::{from_reader_helper, to_writer_helper, traits::Serializable};

impl<T> Serializable for Option<T>
where
    T: Serializable,
{
    #[inline]
    fn size(&self) -> usize {
        match self {
            Some(val) => 1 + val.size(),
            None => 1,
        }
    }
}

from_reader_helper!(Option<T>, wrapped <T> {
    Ok(if read!(bool) {
        Some(read!(T))
    } else {
        None
    })
});

to_writer_helper!(Option<T>, wrapped <T>, (this){
    match this {
        Some(val) => {
            write!(bool, true);
            write!(T, val);
        }
        None => {
            write!(bool, false);
        }
    }

    Ok(())
});

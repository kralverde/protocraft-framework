use crate::{from_reader_helper, to_writer_helper, traits::Serializable};

impl Serializable for bool {
    #[inline]
    fn size(&self) -> usize {
        1
    }
}

from_reader_helper!(bool {
    let byte = read!(u8);
    Ok(byte != 0)
});

to_writer_helper!(bool, (this){
    let byte = if *this {0x01} else {0x00};
    write!(u8, &byte);
    Ok(())
});

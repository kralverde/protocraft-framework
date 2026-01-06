use crate::{to_writer_helper, traits::Serializable};

impl Serializable for str {
    fn size(&self) -> usize {
        self.len()
    }
}

to_writer_helper!(str, (this) {
    write_bytes!(this.as_bytes());
    Ok(())
});

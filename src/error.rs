#[derive(Debug)]
pub enum ReadError<E> {
    StreamError(E),
    OverSized {
        name: &'static str,
        maximum: usize,
        was: usize,
    },
    NegativeLength {
        name: &'static str,
    },
    UnknownPacket {
        state: &'static str,
        id: i32,
    },
    BadEnum {
        name: &'static str,
        value: i32,
    },
    StringDecode {
        name: &'static str,
    },
    MalformedLegacyPing,
    Custom {
        text: &'static str,
    },
}

impl<E> From<E> for ReadError<E> {
    fn from(value: E) -> Self {
        Self::StreamError(value)
    }
}

#[derive(Debug)]
pub enum WriteError<E> {
    StreamError(E),
    OverSized {
        name: &'static str,
        maximum: usize,
        was: usize,
    },
    MalformedVarInt,
    UnknownPacket {
        state: &'static str,
        id: i32,
    },
    Custom {
        text: &'static str,
    },
}

impl<E> From<E> for WriteError<E> {
    fn from(value: E) -> Self {
        Self::StreamError(value)
    }
}

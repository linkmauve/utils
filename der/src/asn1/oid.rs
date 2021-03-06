//! ASN.1 `OBJECT IDENTIFIER`

use crate::{
    Any, Encodable, Encoder, Error, Header, Length, ObjectIdentifier, Result, Tag, Tagged,
};
use core::convert::TryFrom;

impl TryFrom<Any<'_>> for ObjectIdentifier {
    type Error = Error;

    fn try_from(any: Any<'_>) -> Result<ObjectIdentifier> {
        any.tag().assert_eq(Tag::ObjectIdentifier)?;
        Ok(ObjectIdentifier::from_ber(any.as_bytes())?)
    }
}

impl Encodable for ObjectIdentifier {
    fn encoded_len(&self) -> Result<Length> {
        let ber_len = self.ber_len();
        let header = Header::new(Tag::ObjectIdentifier, ber_len)?;
        header.encoded_len()? + ber_len
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        encoder.oid(*self)
    }
}

impl<'a> Tagged for ObjectIdentifier {
    const TAG: Tag = Tag::ObjectIdentifier;
}

#[cfg(test)]
mod tests {
    use crate::{Decodable, Encodable, ObjectIdentifier};

    const EXAMPLE_OID: ObjectIdentifier = ObjectIdentifier::new(&[1, 2, 840, 113549]);
    const EXAMPLE_OID_BYTES: &[u8; 8] = &[0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d];

    #[test]
    fn decode() {
        assert_eq!(
            EXAMPLE_OID,
            ObjectIdentifier::from_bytes(EXAMPLE_OID_BYTES).unwrap()
        );
    }

    #[test]
    fn encode() {
        let mut buffer = [0u8; 8];
        assert_eq!(
            EXAMPLE_OID_BYTES,
            EXAMPLE_OID.encode_to_slice(&mut buffer).unwrap()
        );
    }
}

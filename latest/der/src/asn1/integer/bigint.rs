//! "Big" ASN.1 `INTEGER` types.

use super::uint;
use crate::{
    asn1::AnyRef, ord::OrdIsValueOrd, ByteSlice, DecodeValue, EncodeValue, Error, ErrorKind,
    FixedTag, Header, Length, Reader, Result, Tag, Writer,
};

/// "Big" unsigned ASN.1 `INTEGER` type.
///
/// Provides direct access to the underlying big endian bytes which comprise an
/// unsigned integer value.
///
/// Intended for use cases like very large integers that are used in
/// cryptographic applications (e.g. keys, signatures).
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct UintRef<'a> {
    /// Inner value
    inner: ByteSlice<'a>,
}

impl<'a> UintRef<'a> {
    /// Create a new [`UintRef`] from a byte slice.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        let inner = ByteSlice::new(uint::strip_leading_zeroes(bytes))
            .map_err(|_| ErrorKind::Length { tag: Self::TAG })?;

        Ok(Self { inner })
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading zeros stripped.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.as_slice()
    }

    /// Get the length of this [`UintRef`] in bytes.
    pub fn len(&self) -> Length {
        self.inner.len()
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<'a> DecodeValue<'a> for UintRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let bytes = ByteSlice::decode_value(reader, header)?.as_slice();
        let result = Self::new(uint::decode_to_slice(bytes)?)?;

        // Ensure we compute the same encoded length as the original any value.
        if result.value_len()? != header.length {
            return Err(Self::TAG.non_canonical_error());
        }

        Ok(result)
    }
}

impl<'a> EncodeValue for UintRef<'a> {
    fn value_len(&self) -> Result<Length> {
        uint::encoded_len(self.inner.as_slice())
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        // Add leading `0x00` byte if required
        if self.value_len()? > self.len() {
            writer.write_byte(0)?;
        }

        writer.write(self.as_bytes())
    }
}

impl<'a> From<&UintRef<'a>> for UintRef<'a> {
    fn from(value: &UintRef<'a>) -> UintRef<'a> {
        *value
    }
}

impl<'a> TryFrom<AnyRef<'a>> for UintRef<'a> {
    type Error = Error;

    fn try_from(any: AnyRef<'a>) -> Result<UintRef<'a>> {
        any.decode_into()
    }
}

impl<'a> FixedTag for UintRef<'a> {
    const TAG: Tag = Tag::Integer;
}

impl<'a> OrdIsValueOrd for UintRef<'a> {}

#[cfg(feature = "alloc")]
pub use self::allocating::Uint;

#[cfg(feature = "alloc")]
mod allocating {
    use super::{super::uint, UintRef};
    use crate::{
        asn1::AnyRef,
        ord::OrdIsValueOrd,
        referenced::{OwnedToRef, RefToOwned},
        Bytes, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag, Header, Length, Reader,
        Result, Tag, Writer,
    };

    /// "Big" unsigned ASN.1 `INTEGER` type.
    ///
    /// Provides direct storage for the big endian bytes which comprise an
    /// unsigned integer value.
    ///
    /// Intended for use cases like very large integers that are used in
    /// cryptographic applications (e.g. keys, signatures).
    #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub struct Uint {
        /// Inner value
        inner: Bytes,
    }

    impl Uint {
        /// Create a new [`Uint`] from a byte slice.
        pub fn new(bytes: &[u8]) -> Result<Self> {
            let inner = Bytes::new(uint::strip_leading_zeroes(bytes))
                .map_err(|_| ErrorKind::Length { tag: Self::TAG })?;

            Ok(Self { inner })
        }

        /// Borrow the inner byte slice which contains the least significant bytes
        /// of a big endian integer value with all leading zeros stripped.
        pub fn as_bytes(&self) -> &[u8] {
            self.inner.as_slice()
        }

        /// Get the length of this [`Uint`] in bytes.
        pub fn len(&self) -> Length {
            self.inner.len()
        }

        /// Is the inner byte slice empty?
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }
    }

    impl<'a> DecodeValue<'a> for Uint {
        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            let bytes = Bytes::decode_value(reader, header)?;
            let result = Self::new(uint::decode_to_slice(bytes.as_slice())?)?;

            // Ensure we compute the same encoded length as the original any value.
            if result.value_len()? != header.length {
                return Err(Self::TAG.non_canonical_error());
            }

            Ok(result)
        }
    }

    impl EncodeValue for Uint {
        fn value_len(&self) -> Result<Length> {
            uint::encoded_len(self.inner.as_slice())
        }

        fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
            // Add leading `0x00` byte if required
            if self.value_len()? > self.len() {
                writer.write_byte(0)?;
            }

            writer.write(self.as_bytes())
        }
    }

    impl<'a> From<&UintRef<'a>> for Uint {
        fn from(value: &UintRef<'a>) -> Uint {
            let inner = Bytes::new(value.as_bytes()).expect("Invalid Uint");
            Uint { inner }
        }
    }

    impl<'a> TryFrom<AnyRef<'a>> for Uint {
        type Error = Error;

        fn try_from(any: AnyRef<'a>) -> Result<Uint> {
            any.decode_into()
        }
    }

    impl FixedTag for Uint {
        const TAG: Tag = Tag::Integer;
    }

    impl OrdIsValueOrd for Uint {}

    impl<'a> RefToOwned<'a> for UintRef<'a> {
        type Owned = Uint;
        fn to_owned(&self) -> Self::Owned {
            let inner = self.inner.to_owned();

            Uint { inner }
        }
    }

    impl OwnedToRef for Uint {
        type Borrowed<'a> = UintRef<'a>;
        fn to_ref(&self) -> Self::Borrowed<'_> {
            let inner = self.inner.to_ref();

            UintRef { inner }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UintRef;
    use crate::{
        asn1::{integer::tests::*, AnyRef},
        Decode, Encode, ErrorKind, SliceWriter, Tag,
    };

    #[test]
    fn decode_uint_bytes() {
        assert_eq!(&[0], UintRef::from_der(I0_BYTES).unwrap().as_bytes());
        assert_eq!(&[127], UintRef::from_der(I127_BYTES).unwrap().as_bytes());
        assert_eq!(&[128], UintRef::from_der(I128_BYTES).unwrap().as_bytes());
        assert_eq!(&[255], UintRef::from_der(I255_BYTES).unwrap().as_bytes());

        assert_eq!(
            &[0x01, 0x00],
            UintRef::from_der(I256_BYTES).unwrap().as_bytes()
        );

        assert_eq!(
            &[0x7F, 0xFF],
            UintRef::from_der(I32767_BYTES).unwrap().as_bytes()
        );
    }

    #[test]
    fn encode_uint_bytes() {
        for &example in &[
            I0_BYTES,
            I127_BYTES,
            I128_BYTES,
            I255_BYTES,
            I256_BYTES,
            I32767_BYTES,
        ] {
            let uint = UintRef::from_der(example).unwrap();

            let mut buf = [0u8; 128];
            let mut encoder = SliceWriter::new(&mut buf);
            uint.encode(&mut encoder).unwrap();

            let result = encoder.finish().unwrap();
            assert_eq!(example, result);
        }
    }

    #[test]
    fn reject_oversize_without_extra_zero() {
        let err = UintRef::try_from(AnyRef::new(Tag::Integer, &[0x81]).unwrap())
            .err()
            .unwrap();

        assert_eq!(err.kind(), ErrorKind::Value { tag: Tag::Integer });
    }
}

//! Reject floats before serde_json can coerce non-finite values to null.

use std::error::Error;
use std::fmt;

use serde::ser::{self, Serializer};
use serde::Serialize;

use super::RecallError;

#[derive(Debug)]
enum CanonicalPreflightError {
    Float(String),
    Custom(String),
}

impl fmt::Display for CanonicalPreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Float(value) => write!(f, "floating-point value {value}"),
            Self::Custom(message) => f.write_str(message),
        }
    }
}

impl Error for CanonicalPreflightError {}

impl ser::Error for CanonicalPreflightError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Custom(message.to_string())
    }
}

#[derive(Clone, Copy)]
struct RejectFloats;

struct RejectFloatsCompound;

macro_rules! accept_non_float_scalars {
    ($(fn $method:ident($value:ty);)*) => {
        $(
            fn $method(self, _value: $value) -> Result<Self::Ok, Self::Error> {
                Ok(())
            }
        )*
    };
}

impl Serializer for RejectFloats {
    type Ok = ();
    type Error = CanonicalPreflightError;
    type SerializeSeq = RejectFloatsCompound;
    type SerializeTuple = RejectFloatsCompound;
    type SerializeTupleStruct = RejectFloatsCompound;
    type SerializeTupleVariant = RejectFloatsCompound;
    type SerializeMap = RejectFloatsCompound;
    type SerializeStruct = RejectFloatsCompound;
    type SerializeStructVariant = RejectFloatsCompound;

    accept_non_float_scalars! {
        fn serialize_bool(bool);
        fn serialize_i8(i8);
        fn serialize_i16(i16);
        fn serialize_i32(i32);
        fn serialize_i64(i64);
        fn serialize_i128(i128);
        fn serialize_u8(u8);
        fn serialize_u16(u16);
        fn serialize_u32(u32);
        fn serialize_u64(u64);
        fn serialize_u128(u128);
        fn serialize_char(char);
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        Err(CanonicalPreflightError::Float(value.to_string()))
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        Err(CanonicalPreflightError::Float(value.to_string()))
    }

    fn serialize_str(self, _value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(RejectFloatsCompound)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(RejectFloatsCompound)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(RejectFloatsCompound)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(RejectFloatsCompound)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(RejectFloatsCompound)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(RejectFloatsCompound)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(RejectFloatsCompound)
    }
}

fn reject_nested_float<T>(value: &T) -> Result<(), CanonicalPreflightError>
where
    T: Serialize + ?Sized,
{
    value.serialize(RejectFloats)
}

impl ser::SerializeSeq for RejectFloatsCompound {
    type Ok = ();
    type Error = CanonicalPreflightError;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTuple for RejectFloatsCompound {
    type Ok = ();
    type Error = CanonicalPreflightError;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTupleStruct for RejectFloatsCompound {
    type Ok = ();
    type Error = CanonicalPreflightError;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTupleVariant for RejectFloatsCompound {
    type Ok = ();
    type Error = CanonicalPreflightError;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeMap for RejectFloatsCompound {
    type Ok = ();
    type Error = CanonicalPreflightError;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(key)
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStruct for RejectFloatsCompound {
    type Ok = ();
    type Error = CanonicalPreflightError;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStructVariant for RejectFloatsCompound {
    type Ok = ();
    type Error = CanonicalPreflightError;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        reject_nested_float(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

pub(super) fn reject_floats<T>(value: &T) -> Result<(), RecallError>
where
    T: Serialize + ?Sized,
{
    reject_nested_float(value).map_err(|error| match error {
        CanonicalPreflightError::Float(value) => RecallError::FloatInCanonicalBytes(value),
        CanonicalPreflightError::Custom(message) => {
            RecallError::Serialization(serde_json::Error::io(std::io::Error::other(message)))
        }
    })
}

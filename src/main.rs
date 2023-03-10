
use std::{collections::HashMap, time::Duration};

use x509_cert::{Certificate, ext::Extension, time::Time};
use der::{
    asn1::{BitStringRef, ContextSpecific, ObjectIdentifier, UIntRef},
    Decode, DecodeValue, Encode, FixedTag, Header, Reader, Tag, Tagged,
};
use x509_cert::*;
use lite_json::{json_parser::parse_json, JsonValue};
use serde_json::{Value};
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct DepartmentIdentityStored {
    /// 部门类型
    pub dept_type: String,
    /// 部门级别
    pub dept_level: u8,
    /// 部门名称
    pub dept_name: String,
    /// 上级部门名称
    pub super_dept_name: String,
}

///Structure supporting deferred decoding of fields in the Certificate SEQUENCE
pub struct DeferDecodeCertificate<'a> {
    /// tbsCertificate       TBSCertificate,
    pub tbs_certificate: &'a [u8],
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: &'a [u8],
    /// signature            BIT STRING
    pub signature: &'a [u8],
}

impl<'a> DecodeValue<'a> for DeferDecodeCertificate<'a> {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<DeferDecodeCertificate<'a>> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                tbs_certificate: reader.tlv_bytes()?,
                signature_algorithm: reader.tlv_bytes()?,
                signature: reader.tlv_bytes()?,
            })
        })
    }
}

impl FixedTag for DeferDecodeCertificate<'_> {
    const TAG: Tag = Tag::Sequence;
}

///Structure supporting deferred decoding of fields in the TBSCertificate SEQUENCE
pub struct DeferDecodeTbsCertificate<'a> {
    /// Decoded field
    pub version: u8,
    /// Defer decoded field
    pub serial_number: &'a [u8],
    /// Defer decoded field
    pub signature: &'a [u8],
    /// Defer decoded field
    pub issuer: &'a [u8],
    /// Defer decoded field
    pub validity: &'a [u8],
    /// Defer decoded field
    pub subject: &'a [u8],
    /// Defer decoded field
    pub subject_public_key_info: &'a [u8],
    /// Decoded field (never present)
    pub issuer_unique_id: Option<BitStringRef<'a>>,
    /// Decoded field (never present)
    pub subject_unique_id: Option<BitStringRef<'a>>,
    /// Defer decoded field
    pub extensions: &'a [u8],
}

impl<'a> DecodeValue<'a> for DeferDecodeTbsCertificate<'a> {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<DeferDecodeTbsCertificate<'a>> {
        reader.read_nested(header.length, |reader| {
            let version = ContextSpecific::decode_explicit(reader, ::der::TagNumber::N0)?
                .map(|cs| cs.value)
                .unwrap_or_else(Default::default);

            Ok(Self {
                version,
                serial_number: reader.tlv_bytes()?,
                signature: reader.tlv_bytes()?,
                issuer: reader.tlv_bytes()?,
                validity: reader.tlv_bytes()?,
                subject: reader.tlv_bytes()?,
                subject_public_key_info: reader.tlv_bytes()?,
                issuer_unique_id: reader.decode()?,
                subject_unique_id: reader.decode()?,
                extensions: reader.tlv_bytes()?,
            })
        })
    }
}

impl FixedTag for DeferDecodeTbsCertificate<'_> {
    const TAG: Tag = Tag::Sequence;
}

pub fn decimals_to_string(dec_vec: &[u8]) -> Result<String, String>{

    let mut text = String::new();

    for d in dec_vec.iter(){

        if !(d >=  &32 && d <= &126) {
            return Err("the number is outside the ascii range".to_string());
        } else {
            text.push(*d as char);
            
        }

    }

    Ok(text)
}
fn get_department_identity(extensions: &Vec<Extension>) -> HashMap<String, String>{
    let mut map:HashMap<String,String> = HashMap::new();
    let ipOid:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.1");
    for extension in extensions.iter() {
        //println!("{:?} {:?} {:?}", x, extension.extn_id, extension.extn_id.cmp(&ipOid));
        if (extension.extn_id.eq(&ipOid)) {
            //println!("{:?}", extension.extn_value);
            let data = decimals_to_string(extension.extn_value).unwrap();
            let json_data = parse_json(&data).expect("Invalid JSON specified!");
            let json_obj = json_data.to_object().unwrap();
            for i in json_obj.iter(){
                let attr_key:String = i.0.to_vec().iter().collect();
                //println!("{:?}", attr_key);
                let attr_value = &i.1;

                for (item_key, item_value) in attr_value.as_object().unwrap(){
                    let item_key_string:String = item_key.to_vec().iter().collect();
                    let item_value_string:String = (*item_value).to_owned().to_string().unwrap().iter().collect();
                    //println!("{:?}", item_value.is_string());
                    //println!("{:?} {:?}", item_key_string, item_value_string);
                    map.insert(item_key_string, item_value_string);
                }
            }
        }
    }
    map
}

fn get_department_identity_easier(extensions: &Vec<Extension>) -> DepartmentIdentityStored{
    let mut dept_identity =DepartmentIdentityStored{
        dept_type: "".into(),
        dept_level: 0,
        dept_name: "".into(),
        super_dept_name: "".into()
    };

    let ipOid:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.1");
    for extension in extensions.iter() {
        //println!("{:?} {:?} {:?}", x, extension.extn_id, extension.extn_id.cmp(&ipOid));
        if (extension.extn_id.eq(&ipOid)) {
            let data = decimals_to_string(extension.extn_value).unwrap();
            let data:Value = serde_json::from_str(&data).unwrap();
            //println!("{:?}", data["attrs"]["DeptLevel"]);
            let dept_level = data["attrs"]["DeptLevel"].as_str().unwrap() ;
            let dept_type = data["attrs"]["DeptType"].as_str().unwrap();
            let dept_name = data["attrs"]["DeptName"].as_str().unwrap();
            let super_dept_name = data["attrs"]["SuperDeptName"].as_str().unwrap();

            
            dept_identity.dept_level = u8::from_str_radix(dept_level, 10).unwrap();
            dept_identity.dept_type = dept_type.into();
            dept_identity.dept_name = dept_name.into();
            dept_identity.super_dept_name = super_dept_name.into();
        }
    }
    dept_identity
}
fn main() {
    let der_encoded_cert =
        include_bytes!("../certificatename.der");
    let result = Certificate::from_der(der_encoded_cert).unwrap();
    //println!("{:?}", result.tbs_certificate.extensions);
    // println!("{:?}", result.tbs_certificate.validity);
    let validity = result.tbs_certificate.validity;
    let before_time = validity.not_before;
    let after_time = validity.not_before;
    let extensions =  result.tbs_certificate.extensions.unwrap();   
    let test = after_time.to_date_time().unix_duration();
    println!("afterTime: {:?} beforeTime: {:?}", after_time.to_date_time().unix_duration(), before_time.to_date_time().unix_duration());
    println!("{:?}", get_department_identity_easier(&extensions));
    
}
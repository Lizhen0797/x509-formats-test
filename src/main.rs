
// #![no_std]

use x509_cert::Certificate;
use x509_parser::pem::Pem;
use x509_certificate;
use der::{
    asn1::{BitStringRef, ContextSpecific, ObjectIdentifier, PrintableStringRef, Utf8StringRef},
    Decode, DecodeValue, Encode, FixedTag, Header, Reader, Tag, Tagged,
};

use spki::AlgorithmIdentifierRef;
use x509_cert::serial_number::SerialNumber;
use x509_cert::*;

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

fn test_x509_parser(){
    static IGCA_PEM: &str = "/Users/lizhen/Desktop/test2.pem";
    // 这里是io的方式读取数据
    // let data = std::fs::read(IGCA_PEM).expect("Could not read file");
    // let test_data = std::fs::read(IGCA_PEM);
    let test_data = String::from("-----BEGIN CERTIFICATE-----\nMIIDHjCCAsWgAwIBAgIUGTUcF5Bj0nXRt/BtG0SslzZfVgMwCgYIKoZIzj0EAwIw\najELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK\nEwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRswGQYDVQQDExJjYS5vcmcx\nLmxhYjgwNS5jb20wHhcNMjEwMzA3MDk0NTAwWhcNMjIwMzA3MDk1NTAwWjBbMQsw\nCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExFDASBgNVBAoTC0h5\ncGVybGVkZ2VyMQ0wCwYDVQQLEwRwZWVyMQ4wDAYDVQQDEwVwZWVyMDBZMBMGByqG\nSM49AgEGCCqGSM49AwEHA0IABJsfYuGbeTpHC0PUkbms0NWpEmhul89+nD+fjQ/i\nHvGz4Qmicdz8Ydee0oyQbqim9nNrHeCa/Y3oBStZFrqqxuyjggFWMIIBUjAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2UAiJ0WoEKTT9bpe\n0s2r/tCtyRQwHwYDVR0jBBgwFoAU6xcRmVzmh0HmJ111bISCbUJQ/xMwIAYDVR0R\nBBkwF4IVcGVlcjAub3JnMS5sYWI4MDUuY29tMIHPBggqAwQFBgcIAQSBwnsiYXR0\ncnMiOnsiRGVwdExldmVsIjoiMiIsIkRlcHROYW1lIjoiODEyIiwiRGVwdFR5cGUi\nOiJjb21wdXRlciIsIlN1cGVyRGVwdE5hbWUiOiI4MDQiLCJhZG1pbiI6InRydWUi\nLCJoZi5BZmZpbGlhdGlvbiI6IiIsImhmLkVucm9sbG1lbnRJRCI6InBlZXIwIiwi\naGYuUmVnaXN0cmFyLlJvbGVzIjoicGVlciIsImhmLlR5cGUiOiJwZWVyIn19MAoG\nCCqGSM49BAMCA0cAMEQCIC4PUwJHhxi20JJT+yAdB+i4UWNcPmIFNNFHyHYwgvCm\nAiBQxf8/6m576DKRpTB+x1BAOhnk2MoNdm9Qrv4OC5Oykw==\n-----END CERTIFICATE-----");
    let test_data = ascii_converter::string_to_decimals(&test_data).expect("Could not read file");
    for pem in Pem::iter_from_buffer(&test_data) {
        let pem = pem.expect("Reading next PEM block failed");
        let x509 = pem.parse_x509().expect("X.509: decoding DER failed");
        // x509是整个证书的解析，其中extension应该和格式相关
        let test = x509.extensions()[5].value;
        let mut text = String::new();
        for d in test.iter(){
            if !(d >=  &32 && d <= &126) {
                break;
            } else {
                text.push(*d as char);                
            }
        }
        println!("{}",text)
    }
}

fn test_x509_certificate() {
    let test_data = String::from("-----BEGIN CERTIFICATE-----\nMIIDHjCCAsWgAwIBAgIUGTUcF5Bj0nXRt/BtG0SslzZfVgMwCgYIKoZIzj0EAwIw\najELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK\nEwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRswGQYDVQQDExJjYS5vcmcx\nLmxhYjgwNS5jb20wHhcNMjEwMzA3MDk0NTAwWhcNMjIwMzA3MDk1NTAwWjBbMQsw\nCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExFDASBgNVBAoTC0h5\ncGVybGVkZ2VyMQ0wCwYDVQQLEwRwZWVyMQ4wDAYDVQQDEwVwZWVyMDBZMBMGByqG\nSM49AgEGCCqGSM49AwEHA0IABJsfYuGbeTpHC0PUkbms0NWpEmhul89+nD+fjQ/i\nHvGz4Qmicdz8Ydee0oyQbqim9nNrHeCa/Y3oBStZFrqqxuyjggFWMIIBUjAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2UAiJ0WoEKTT9bpe\n0s2r/tCtyRQwHwYDVR0jBBgwFoAU6xcRmVzmh0HmJ111bISCbUJQ/xMwIAYDVR0R\nBBkwF4IVcGVlcjAub3JnMS5sYWI4MDUuY29tMIHPBggqAwQFBgcIAQSBwnsiYXR0\ncnMiOnsiRGVwdExldmVsIjoiMiIsIkRlcHROYW1lIjoiODEyIiwiRGVwdFR5cGUi\nOiJjb21wdXRlciIsIlN1cGVyRGVwdE5hbWUiOiI4MDQiLCJhZG1pbiI6InRydWUi\nLCJoZi5BZmZpbGlhdGlvbiI6IiIsImhmLkVucm9sbG1lbnRJRCI6InBlZXIwIiwi\naGYuUmVnaXN0cmFyLlJvbGVzIjoicGVlciIsImhmLlR5cGUiOiJwZWVyIn19MAoG\nCCqGSM49BAMCA0cAMEQCIC4PUwJHhxi20JJT+yAdB+i4UWNcPmIFNNFHyHYwgvCm\nAiBQxf8/6m576DKRpTB+x1BAOhnk2MoNdm9Qrv4OC5Oykw==\n-----END CERTIFICATE-----");
    let test_data = ascii_converter::string_to_decimals(&test_data).expect("Could not read file");
    
    let test2 = x509_certificate::certificate::X509Certificate::from_pem(&test_data).expect("1");
    //println!("{:?}", test2);
    for item in test2.iter_extensions(){
        //println!("{:?}", item);
        let extension = item;
        let extensions_value = &extension.value;
        // let extension_txt = extensions_value;
        println!("{:?} {:?}", extension.id, extensions_value.to_bytes())
    }
}

fn test_barebones_x509() {
    //let test_data = String::from("-----BEGIN CERTIFICATE-----\nMIIDHjCCAsWgAwIBAgIUGTUcF5Bj0nXRt/BtG0SslzZfVgMwCgYIKoZIzj0EAwIw\najELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK\nEwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRswGQYDVQQDExJjYS5vcmcx\nLmxhYjgwNS5jb20wHhcNMjEwMzA3MDk0NTAwWhcNMjIwMzA3MDk1NTAwWjBbMQsw\nCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExFDASBgNVBAoTC0h5\ncGVybGVkZ2VyMQ0wCwYDVQQLEwRwZWVyMQ4wDAYDVQQDEwVwZWVyMDBZMBMGByqG\nSM49AgEGCCqGSM49AwEHA0IABJsfYuGbeTpHC0PUkbms0NWpEmhul89+nD+fjQ/i\nHvGz4Qmicdz8Ydee0oyQbqim9nNrHeCa/Y3oBStZFrqqxuyjggFWMIIBUjAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2UAiJ0WoEKTT9bpe\n0s2r/tCtyRQwHwYDVR0jBBgwFoAU6xcRmVzmh0HmJ111bISCbUJQ/xMwIAYDVR0R\nBBkwF4IVcGVlcjAub3JnMS5sYWI4MDUuY29tMIHPBggqAwQFBgcIAQSBwnsiYXR0\ncnMiOnsiRGVwdExldmVsIjoiMiIsIkRlcHROYW1lIjoiODEyIiwiRGVwdFR5cGUi\nOiJjb21wdXRlciIsIlN1cGVyRGVwdE5hbWUiOiI4MDQiLCJhZG1pbiI6InRydWUi\nLCJoZi5BZmZpbGlhdGlvbiI6IiIsImhmLkVucm9sbG1lbnRJRCI6InBlZXIwIiwi\naGYuUmVnaXN0cmFyLlJvbGVzIjoicGVlciIsImhmLlR5cGUiOiJwZWVyIn19MAoG\nCCqGSM49BAMCA0cAMEQCIC4PUwJHhxi20JJT+yAdB+i4UWNcPmIFNNFHyHYwgvCm\nAiBQxf8/6m576DKRpTB+x1BAOhnk2MoNdm9Qrv4OC5Oykw==\n-----END CERTIFICATE-----");
    //let test_data = ascii_converter::string_to_decimals(&test_data).expect("Could not read file");
    
    let certificate = include_bytes!("../testing.crt");
    let data = std::fs::read("/Users/lizhen/Code/rust/x509/testing.crt").expect("Could not read file");
    // println!("{:?}", data);
    // println!("{:?}", certificate);
    let cert = barebones_x509::parse_certificate(&data).unwrap();
    println!("{:?}", cert);
    
    println!("{:?}", cert.extensions());
}

fn test_der_parser() {
    let test_data = String::from("-----BEGIN CERTIFICATE-----\nMIIDHjCCAsWgAwIBAgIUGTUcF5Bj0nXRt/BtG0SslzZfVgMwCgYIKoZIzj0EAwIw\najELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK\nEwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRswGQYDVQQDExJjYS5vcmcx\nLmxhYjgwNS5jb20wHhcNMjEwMzA3MDk0NTAwWhcNMjIwMzA3MDk1NTAwWjBbMQsw\nCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExFDASBgNVBAoTC0h5\ncGVybGVkZ2VyMQ0wCwYDVQQLEwRwZWVyMQ4wDAYDVQQDEwVwZWVyMDBZMBMGByqG\nSM49AgEGCCqGSM49AwEHA0IABJsfYuGbeTpHC0PUkbms0NWpEmhul89+nD+fjQ/i\nHvGz4Qmicdz8Ydee0oyQbqim9nNrHeCa/Y3oBStZFrqqxuyjggFWMIIBUjAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2UAiJ0WoEKTT9bpe\n0s2r/tCtyRQwHwYDVR0jBBgwFoAU6xcRmVzmh0HmJ111bISCbUJQ/xMwIAYDVR0R\nBBkwF4IVcGVlcjAub3JnMS5sYWI4MDUuY29tMIHPBggqAwQFBgcIAQSBwnsiYXR0\ncnMiOnsiRGVwdExldmVsIjoiMiIsIkRlcHROYW1lIjoiODEyIiwiRGVwdFR5cGUi\nOiJjb21wdXRlciIsIlN1cGVyRGVwdE5hbWUiOiI4MDQiLCJhZG1pbiI6InRydWUi\nLCJoZi5BZmZpbGlhdGlvbiI6IiIsImhmLkVucm9sbG1lbnRJRCI6InBlZXIwIiwi\naGYuUmVnaXN0cmFyLlJvbGVzIjoicGVlciIsImhmLlR5cGUiOiJwZWVyIn19MAoG\nCCqGSM49BAMCA0cAMEQCIC4PUwJHhxi20JJT+yAdB+i4UWNcPmIFNNFHyHYwgvCm\nAiBQxf8/6m576DKRpTB+x1BAOhnk2MoNdm9Qrv4OC5Oykw==\n-----END CERTIFICATE-----");
    let test_data = ascii_converter::string_to_decimals(&test_data).expect("Could not read file");
    let result = der_parser::parse_der(&test_data).expect("??");
    println!("{:?}", result.0);
    println!("{:?}", result.1);
}

fn test_der() {
    let test_data = String::from("-----BEGIN CERTIFICATE-----\nMIIDHjCCAsWgAwIBAgIUGTUcF5Bj0nXRt/BtG0SslzZfVgMwCgYIKoZIzj0EAwIw\najELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK\nEwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRswGQYDVQQDExJjYS5vcmcx\nLmxhYjgwNS5jb20wHhcNMjEwMzA3MDk0NTAwWhcNMjIwMzA3MDk1NTAwWjBbMQsw\nCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExFDASBgNVBAoTC0h5\ncGVybGVkZ2VyMQ0wCwYDVQQLEwRwZWVyMQ4wDAYDVQQDEwVwZWVyMDBZMBMGByqG\nSM49AgEGCCqGSM49AwEHA0IABJsfYuGbeTpHC0PUkbms0NWpEmhul89+nD+fjQ/i\nHvGz4Qmicdz8Ydee0oyQbqim9nNrHeCa/Y3oBStZFrqqxuyjggFWMIIBUjAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2UAiJ0WoEKTT9bpe\n0s2r/tCtyRQwHwYDVR0jBBgwFoAU6xcRmVzmh0HmJ111bISCbUJQ/xMwIAYDVR0R\nBBkwF4IVcGVlcjAub3JnMS5sYWI4MDUuY29tMIHPBggqAwQFBgcIAQSBwnsiYXR0\ncnMiOnsiRGVwdExldmVsIjoiMiIsIkRlcHROYW1lIjoiODEyIiwiRGVwdFR5cGUi\nOiJjb21wdXRlciIsIlN1cGVyRGVwdE5hbWUiOiI4MDQiLCJhZG1pbiI6InRydWUi\nLCJoZi5BZmZpbGlhdGlvbiI6IiIsImhmLkVucm9sbG1lbnRJRCI6InBlZXIwIiwi\naGYuUmVnaXN0cmFyLlJvbGVzIjoicGVlciIsImhmLlR5cGUiOiJwZWVyIn19MAoG\nCCqGSM49BAMCA0cAMEQCIC4PUwJHhxi20JJT+yAdB+i4UWNcPmIFNNFHyHYwgvCm\nAiBQxf8/6m576DKRpTB+x1BAOhnk2MoNdm9Qrv4OC5Oykw==\n-----END CERTIFICATE-----");
    let test_data = ascii_converter::string_to_decimals(&test_data).expect("Could not read file");
}
fn main() {
    let der_encoded_cert =
        include_bytes!("../certificatename.der");
    let result = Certificate::from_der(der_encoded_cert);
    println!("{:?}", result);
}
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::CStr;
use std::io::Read;
use std::str::FromStr;

use byteorder::{LittleEndian, ReadBytesExt};
use fallible_iterator::FallibleIterator;
use serde::Serialize;
use thiserror::Error;
use tpmless_tpm2::{DigestAlgorithm, PcrExtender, PcrExtenderBuilder};

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Text parse error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Text parse error: {0}")]
    Utf8Str(#[from] std::str::Utf8Error),
    #[error("Unsupported template used: {0}")]
    UnsupportedTemplate(String),
    #[error("Error parsing CString")]
    FromCString(#[from] std::ffi::FromBytesWithNulError),
    #[error("Error creating string from CString")]
    CStringToString(#[from] std::ffi::IntoStringError),
    #[error("Invalid data encountered")]
    DataError,
    #[error("Unsupported digest algo {0} encountered")]
    UnknownDigestAlgo(String),
    #[error("Error in TPMLess")]
    Tpmless(#[from] tpmless_tpm2::Error),
}

#[derive(Debug, Serialize)]
pub struct Digest {
    algo: DigestAlgorithm,
    #[serde(with = "hex")]
    digest: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Signature {}

#[derive(Debug, Serialize)]
pub struct Buffer {}

#[derive(Debug, Serialize)]
pub struct Modsig {}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EventData {
    // "d|n"
    Ima {
        digest: Digest,
        name: String,
    },
    // "d-ng|n-ng"
    ImaNg {
        digest: Digest,
        name: String,
    },
    // "d-ng|n-ng|sig"
    ImaSig {
        digest: Digest,
        name: String,
        signature: Signature,
    },
    // "d-ng|n-ng|buf"
    ImaBuf {
        digest: Digest,
        name: String,
        buffer: Buffer,
    },
    // "d-ng|n-ng|sig|d-modsig|modsig"
    ImaModsig {
        digest: Digest,
        name: String,
        signature: Signature,
        modsig: Modsig,
    },
}

fn parse_signature<R: Read>(reader: &mut R) -> Result<Signature, Error> {
    todo!();
}

fn parse_buffer<R: Read>(reader: &mut R) -> Result<Buffer, Error> {
    todo!();
}

fn parse_modsig<R: Read>(reader: &mut R) -> Result<Modsig, Error> {
    todo!();
}

fn parse_digest<R: Read>(is_legacy_ima_template: bool, reader: &mut R) -> Result<Digest, Error> {
    let len = if is_legacy_ima_template {
        20 // Size of SHA1 hash
    } else {
        reader.read_u32::<LittleEndian>()?
    };
    let mut buf = zeroed_vec(len as usize);
    reader.read_exact(&mut buf)?;
    let (algo, digest) = if is_legacy_ima_template {
        ("sha1", buf)
    } else {
        // The first few bytes until a ':' are the algo
        let split = match buf.iter().position(|&r| r == b':') {
            Some(p) => p,
            None => return Err(Error::DataError),
        };
        let (algo, digest) = buf.split_at(split + 2);
        let algo = std::str::from_utf8(algo)?.trim_end_matches(":\0");

        (algo, digest.to_vec())
    };

    let algo = DigestAlgorithm::from_str(algo)?;

    Ok(Digest { algo, digest })
}

fn parse_name<R: Read>(is_legacy_ima_template: bool, reader: &mut R) -> Result<String, Error> {
    let len = reader.read_u32::<LittleEndian>()?;
    let mut buf = zeroed_vec(len as usize);
    reader.read_exact(&mut buf)?;

    Ok(if is_legacy_ima_template {
        // In this case, we get the string itself, without further ado
        String::from_utf8(buf)?
    } else {
        // In this case, we get a null-terminated CStr
        CStr::from_bytes_with_nul(&buf)?.to_str()?.to_owned()
    }
    .trim_end_matches('\0')
    .to_owned())
}

impl EventData {
    fn parse<R: Read>(template_name: &str, reader: &mut R) -> Result<Self, Error> {
        match template_name {
            "ima" => {
                // "d|n"
                let digest = parse_digest(true, reader)?;
                let name = parse_name(true, reader)?;
                Ok(EventData::Ima { digest, name })
            }
            "ima-ng" => {
                // "d-ng|n-ng"
                let digest = parse_digest(false, reader)?;
                let name = parse_name(true, reader)?;
                Ok(EventData::ImaNg { digest, name })
            }
            "ima-sig" => {
                // "d-ng|n-ng|sig"
                let digest = parse_digest(false, reader)?;
                let name = parse_name(false, reader)?;
                let signature = parse_signature(reader)?;
                Ok(EventData::ImaSig {
                    digest,
                    name,
                    signature,
                })
            }
            "ima-buf" => {
                // "d-ng|n-ng|buf"
                let digest = parse_digest(false, reader)?;
                let name = parse_name(false, reader)?;
                let buffer = parse_buffer(reader)?;
                Ok(EventData::ImaBuf {
                    digest,
                    name,
                    buffer,
                })
            }
            "ima-modsig" => {
                // "d-ng|n-ng|sig|d-modsig|modsig"
                let digest = parse_digest(false, reader)?;
                let name = parse_name(false, reader)?;
                let signature = parse_signature(reader)?;
                let modsig = parse_modsig(reader)?;
                Ok(EventData::ImaModsig {
                    digest,
                    name,
                    signature,
                    modsig,
                })
            }
            _ => Err(Error::UnsupportedTemplate(template_name.to_owned())),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Event {
    pub pcr_index: u32,
    #[serde(with = "hex")]
    pub template_sha1: [u8; 20],
    #[serde(flatten)]
    pub data: EventData,
}

#[derive(Debug)]
pub struct Parser<R: Read> {
    reader: R,
    pcr_tracker: PcrExtender,
}

fn zeroed_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}

impl<R: Read> Parser<R> {
    pub fn new(reader: R) -> Self {
        // Return a new Parser instance
        Parser {
            reader,
            pcr_tracker: PcrExtenderBuilder::new()
                .add_digest_method(DigestAlgorithm::Sha1)
                .add_digest_method(DigestAlgorithm::Sha256)
                .add_digest_method(DigestAlgorithm::Sha384)
                .add_digest_method(DigestAlgorithm::Sha512)
                .build(),
        }
    }

    pub fn pcr_values(self) -> PcrValues {
        pcr_extender_to_values(self.pcr_tracker)
    }
}

pub type PcrValues = BTreeMap<u32, PcrValue>;

fn pcr_extender_to_values(ext: PcrExtender) -> PcrValues {
    let mut vals = BTreeMap::new();

    for (algo, mut bank) in ext.values().drain() {
        for (pcr, val) in bank.drain(..).enumerate() {
            let is_empty = val.iter().all(|v| *v == 0x00);
            if is_empty {
                continue;
            }

            let pcr = pcr as u32;

            let pcr_vals: &mut PcrValue = match vals.get_mut(&pcr) {
                Some(v) => v,
                None => {
                    vals.insert(pcr, Default::default());
                    vals.get_mut(&pcr).unwrap()
                }
            };

            match algo {
                DigestAlgorithm::Sha1 => {
                    pcr_vals.sha1 = val.try_into().unwrap();
                }
                DigestAlgorithm::Sha256 => {
                    pcr_vals.sha256 = val.try_into().unwrap();
                }
                DigestAlgorithm::Sha384 => {
                    pcr_vals.sha384 = val.try_into().unwrap();
                }
                DigestAlgorithm::Sha512 => {
                    pcr_vals.sha512 = val.try_into().unwrap();
                }
                _ => {}
            }
        }
    }

    vals
}

#[derive(Debug, Serialize)]
pub struct PcrValue {
    #[serde(with = "hex")]
    pub sha1: [u8; 20],
    #[serde(with = "hex")]
    pub sha256: [u8; 32],
    #[serde(with = "hex")]
    pub sha384: [u8; 48],
    #[serde(with = "hex")]
    pub sha512: [u8; 64],
}

impl Default for PcrValue {
    fn default() -> Self {
        PcrValue {
            sha1: [0; 20],
            sha256: [0; 32],
            sha384: [0; 48],
            sha512: [0; 64],
        }
    }
}

impl<R: Read> FallibleIterator for Parser<R> {
    type Item = Event;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Event>, Error> {
        // Parse the template header
        //  PCR Index
        let pcr_index = match self.reader.read_u32::<LittleEndian>() {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Ok(None);
                }
                return Err(e.into());
            }
            Ok(index) => index,
        };
        //  Template digest (sha1)
        let mut template_sha1: [u8; 20] = [0; 20];
        self.reader.read_exact(&mut template_sha1)?;
        //  Template name
        let template_name_size = self.reader.read_u32::<LittleEndian>()?;
        let mut template_name = zeroed_vec(template_name_size as usize);
        self.reader.read_exact(&mut template_name)?;
        let template_name = String::from_utf8(template_name)?;

        // Event data
        let eventdata_len = self.reader.read_u32::<LittleEndian>()?;
        let mut event_data = zeroed_vec(eventdata_len as usize);
        self.reader.read_exact(&mut event_data)?;
        let eventdata = EventData::parse(&template_name, &mut event_data.as_slice())?;

        // Extend PCR tracker
        self.pcr_tracker.extend(pcr_index, &event_data)?;

        // Return
        Ok(Some(Event {
            pcr_index,
            template_sha1,
            data: eventdata,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::fs::File;
    use std::path::Path;

    use fallible_iterator::FallibleIterator;

    use crate::{EventData, Parser};

    #[test]
    fn test_ima_ng() {
        let dirname = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fname = dirname.join("test_assets/imang");
        let file = File::open(&fname).expect("Test asset not found");

        let mut parser = Parser::new(file);

        while let Some(event) = parser.next().expect("Failed to parse event") {
            assert_eq!(event.pcr_index, 10);
            match event.data {
                EventData::ImaNg { .. } => {}
                _ => panic!("Invalid event type encountered: {:?}", event),
            }
        }

        // Now check PCR values
        let pcr_values = parser.pcr_values();
        assert_eq!(pcr_values.len(), 1);

        let pcr_values = pcr_values.get(&10).expect("PCR 10 not measured");

        assert_eq!(
            Vec::<u8>::try_from(pcr_values.sha1).unwrap(),
            hex::decode("3BBFF82F30A587E9F6356783230B9CBD9F0D5F64").unwrap(),
        );
        assert_eq!(
            Vec::<u8>::try_from(pcr_values.sha256).unwrap(),
            hex::decode("5C9E6EDB1C8E04B26852299783ADCD93D5BBB81ED0391021AEFF6618C9F1E142")
                .unwrap(),
        );
    }
}

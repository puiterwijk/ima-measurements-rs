use byteorder::{LittleEndian, ReadBytesExt};
use fallible_iterator::FallibleIterator;
use serde::Serialize;
use std::convert::{TryFrom, TryInto};
use std::ffi::CStr;
use std::io::Read;
use thiserror::Error;

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
}

#[derive(Debug, Serialize)]
pub struct Digest {
    algo: String,
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
        (String::from("sha1"), buf)
    } else {
        // The first few bytes until a ':' are the algo
        let split = match buf.iter().position(|&r| r == b':') {
            Some(p) => p,
            None => return Err(Error::DataError),
        };
        let (algo, digest) = buf.split_at(split + 2);
        let algo = std::str::from_utf8(algo)?
            .trim_end_matches(":\0")
            .to_owned();

        (algo, digest.to_vec())
    };

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
    fn parse<R: Read>(
        template_name: &str,
        reader: &mut R,
        _data_len: usize,
    ) -> Result<Self, Error> {
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
}

fn zeroed_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}

impl<R: Read> Parser<R> {
    pub fn new(reader: R) -> Self {
        // Return a new Parser instance
        Parser { reader }
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
        let eventdata = EventData::parse(&template_name, &mut self.reader, eventdata_len as usize)?;

        Ok(Some(Event {
            pcr_index,
            template_sha1,
            data: eventdata,
        }))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

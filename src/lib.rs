//! Data for use in rbspy tests and benchmarks :-)

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use goblin::elf;
use remoteprocess::{Error as ProcessError, ProcessMemory};

use flate2::bufread::GzDecoder;

/// Open data file `name`.
fn data_file(name: &str) -> Result<File> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join(name);

    Ok(File::open(&path).context(format!("could not open data file `{}`", path.display()))?)
}

/// Get contents of gzipped data file `name`.
fn data_file_gz_contents(name: &str) -> Result<Vec<u8>> {
    let file = BufReader::new(data_file(&name)?);
    let mut data = vec![];
    GzDecoder::new(file)
        .read_to_end(&mut data)
        .context(format!("failed to read gzipped data file `{}`", name))?;
    Ok(data)
}

/// Load coredump from gzipped data file `name`.
fn load_coredump(name: &str) -> Result<CoreDump> {
    CoreDump::new(data_file_gz_contents(name)?)
}

pub fn coredump_1_9_3() -> CoreDump {
    load_coredump("ruby-coredump-1.9.3.gz").unwrap()
}
pub fn coredump_2_1_6() -> CoreDump {
    load_coredump("ruby-coredump-2.1.6.gz").unwrap()
}
pub fn coredump_2_1_6_c_function() -> CoreDump {
    load_coredump("ruby-coredump-2.1.6_c_function.gz").unwrap()
}
pub fn coredump_2_4_0() -> CoreDump {
    load_coredump("ruby-coredump-2.4.0.gz").unwrap()
}
pub fn coredump_2_5_0() -> CoreDump {
    load_coredump("ruby-coredump-2.5.0.gz").unwrap()
}

pub fn coredump_2_7_2() -> CoreDump {
    load_coredump("ruby-coredump-2.7.2.gz").unwrap()
}

pub fn coredump_3_0_0() -> CoreDump {
    load_coredump("ruby-coredump-3.0.0.gz").unwrap()
}

pub fn coredump_3_1_0() -> CoreDump {
    load_coredump("ruby-coredump-3.1.0.gz").unwrap()
}

pub fn coredump_3_2_0() -> CoreDump {
    load_coredump("ruby-coredump-3.2.0.gz").unwrap()
}

pub fn coredump_3_3_0() -> CoreDump {
    load_coredump("ruby-coredump-3.3.0.gz").unwrap()
}

/// Allows testing offline with a core dump of a Ruby process.
pub struct CoreDump {
    raw_memory: Vec<u8>,
    elf_section_headers: Vec<elf::SectionHeader>,
}

impl CoreDump {
    pub fn new(raw_memory: Vec<u8>) -> Result<Self> {
        let elf = elf::Elf::parse(&raw_memory).context("failed to parse ELF header")?;
        let elf_section_headers = elf.section_headers;
        Ok(CoreDump {
            raw_memory,
            elf_section_headers,
        })
    }
}

impl ProcessMemory for CoreDump {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), ProcessError> {
        let start = addr as u64;
        let end = (addr + buf.len()) as u64;
        match self
            .elf_section_headers
            .iter()
            .find(|section| section.sh_addr <= start && end <= section.sh_addr + section.sh_size)
        {
            Some(sec) => {
                let start = sec.sh_offset as usize + addr - sec.sh_addr as usize;
                let end = start + buf.len();
                buf.copy_from_slice(&self.raw_memory[start..end]);
                Ok(())
            }
            None => {
                let io_error = io::Error::from_raw_os_error(libc::EFAULT);
                Err(ProcessError::IOError(io_error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_coredump() {
        let coredump = load_coredump("ruby-coredump-1.9.3.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 36);
        let coredump = load_coredump("ruby-coredump-2.1.6.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 40);
        let coredump = load_coredump("ruby-coredump-2.1.6_c_function.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 102);
        let coredump = load_coredump("ruby-coredump-2.4.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 38);
        let coredump = load_coredump("ruby-coredump-2.5.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 38);
        let coredump = load_coredump("ruby-coredump-2.7.2.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 119);
        let coredump = load_coredump("ruby-coredump-3.0.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 119);
        let coredump = load_coredump("ruby-coredump-3.1.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 119);
        let coredump = load_coredump("ruby-coredump-3.2.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 120);
        let coredump = load_coredump("ruby-coredump-3.3.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 122);
    }
}

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

pub fn coredump_with_classes_3_3_0() -> CoreDump {
    load_coredump("ruby-coredump-with-classes-3.3.0.gz").unwrap()
}

pub fn coredump_complex_3_4_5() -> CoreDump {
    load_coredump("ruby-coredump-complex-3.4.5.gz").unwrap()
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
        let buf = &mut [0u8; 16];
        coredump.read(0x823930, buf).expect("read failed");
        assert_eq!(buf, &[32, 21, 73, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let coredump = load_coredump("ruby-coredump-2.1.6.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 40);
        let buf = &mut [0u8; 16];
        coredump.read(0x562658abd7f0, buf).expect("read failed");
        assert_eq!(
            buf,
            &[176, 165, 200, 89, 38, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-2.1.6_c_function.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 102);
        let buf = &mut [0u8; 16];
        coredump.read(0x562efcd577f0, buf).expect("read failed");
        assert_eq!(
            buf,
            &[176, 198, 255, 254, 46, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-2.4.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 38);
        let buf = &mut [0u8; 16];
        coredump.read(0x55df44959920, buf).expect("read failed");
        assert_eq!(
            buf,
            &[208, 165, 37, 70, 223, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-2.5.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 38);
        let buf = &mut [0u8; 16];
        coredump.read(0x55dd8c3b7758, buf).expect("read failed");
        assert_eq!(
            buf,
            &[216, 136, 151, 140, 221, 85, 0, 0, 32, 127, 151, 140, 221, 85, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-2.7.2.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 119);
        let buf = &mut [0u8; 16];
        coredump.read(0x7fdd8d626070, buf).expect("read failed");
        assert_eq!(
            buf,
            &[208, 166, 207, 100, 196, 85, 0, 0, 160, 155, 207, 100, 196, 85, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-3.0.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 119);
        let buf = &mut [0u8; 16];
        coredump.read(0x7fdacdab7470, buf).expect("read failed");
        assert_eq!(
            buf,
            &[160, 235, 191, 181, 200, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-3.1.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 119);
        let buf = &mut [0u8; 16];
        coredump.read(0x7f0dc0c83c58, buf).expect("read failed");
        assert_eq!(
            buf,
            &[64, 186, 97, 2, 255, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-3.2.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 120);
        let buf = &mut [0u8; 16];
        coredump.read(0xffffb8034578, buf).expect("read failed");
        assert_eq!(
            buf,
            &[208, 250, 146, 227, 170, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-3.3.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 151);
        let buf = &mut [0u8; 16];
        coredump.read(0x7f43435f4988, buf).expect("read failed");
        assert_eq!(
            buf,
            &[16, 51, 89, 134, 131, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-with-classes-3.3.0.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 124);
        let buf = &mut [0u8; 16];
        coredump.read(0x7f58cb7f4988, buf).expect("read failed");
        assert_eq!(
            buf,
            &[16, 115, 177, 241, 196, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let coredump = load_coredump("ruby-coredump-complex-3.4.5.gz").unwrap();
        assert_eq!(coredump.elf_section_headers.len(), 152);
        let buf = &mut [0u8; 16];
        coredump.read(0x7f271feb5390, buf).expect("read failed");
        assert_eq!(
            buf,
            &[16, 19, 104, 91, 119, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}

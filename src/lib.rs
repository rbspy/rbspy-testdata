//! Data for use in rbspy tests and benchmarks :-)

extern crate elf;
#[macro_use] extern crate failure;
extern crate flate2;
#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate read_process_memory;

use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;

use read_process_memory::CopyAddress;
use failure::{Error, ResultExt};


use self::flate2::bufread::GzDecoder;

/// Open data file `name`.
fn data_file<P: AsRef<Path>>(name: P) -> Result<File, Error> {
    let name = name.as_ref();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data").join(name);

    Ok(File::open(&path)
        .context(format!("could not open data file `{}`", path.display()))?)
}

/// Get contents of gzipped data file `name`.
fn data_file_gz_contents<P: AsRef<Path>>(name: P) -> Result<Vec<u8>, Error> {
    let file = BufReader::new(data_file(&name)?);
    let mut data = vec![];
    GzDecoder::new(file)?.read_to_end(&mut data)
        .context(format!("failed to read gzipped data file `{}`", name.as_ref().display()))?;

    Ok(data)
}

/// Load coredump from gzipped data file `name`.
fn load_coredump<P: AsRef<Path>>(name: P) -> Result<CoreDump, Error> {
    let data = data_file_gz_contents(&name)?;

    match elf::File::open_stream(&mut Cursor::new(data)) {
        Ok(elf_file) => Ok(CoreDump::from(elf_file)),
        Err(e) => Err(format_err!("could not parse elf file `{}`: {:?}",
                                  name.as_ref().display(),
                                  e)),
    }
}

lazy_static! {
    pub static ref COREDUMP_1_9_3: CoreDump =
        load_coredump("ruby-coredump-1.9.3.gz").unwrap();
    pub static ref COREDUMP_2_1_6: CoreDump =
        load_coredump("ruby-coredump-2.1.6.gz").unwrap();
    pub static ref COREDUMP_2_1_6_C_FUNCTION: CoreDump =
        load_coredump("ruby-coredump-2.1.6_c_function.gz").unwrap();
    pub static ref COREDUMP_2_4_0: CoreDump =
        load_coredump("ruby-coredump-2.4.0.gz").unwrap();
    pub static ref COREDUMP_2_5_0: CoreDump =
        load_coredump("ruby-coredump-2.5.0.gz").unwrap();
}

/// Allows testing offline with a core dump of a Ruby process.
pub struct CoreDump {
    file: elf::File,
}

impl From<elf::File> for CoreDump {
    fn from(file: elf::File) -> CoreDump {
        CoreDump { file: file }
    }
}

impl CopyAddress for CoreDump {
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
        let start = addr as u64;
        let end = (addr + buf.len()) as u64;
        match self.file.sections.iter().find(|section| {
            section.shdr.addr <= start && end <= section.shdr.addr + section.shdr.size
        }) {
            Some(sec) => {
                let start = addr - sec.shdr.addr as usize;
                let end = addr + buf.len() - sec.shdr.addr as usize;
                buf.copy_from_slice(&sec.data[start..end]);
                Ok(())
            }
            None => Err(io::Error::from_raw_os_error(libc::EFAULT)),
        }
    }
}

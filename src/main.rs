#![windows_subsystem = "console"]

use flate2::bufread::DeflateDecoder;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use walkdir::WalkDir;

mod signatures {
    pub mod v1 {
        pub const FILE: u32 = 0x85840000;
        pub const END_RECORD: u32 = 0xdd59fc12;
        pub const END_RECORD_ALT: u32 = 0x05030207;
    }
    pub mod v2 {
        pub const FILE: u32 = 0xdfe7a57d;
        pub const FILE_ALT: u32 = 0x6c4ed59e;
        pub const END_RECORD: u32 = 0x05030208;
        pub const END_RECORD_ALT: u32 = 0x06054b50;
    }
    pub mod v3 {
        pub const FILE: u32 = 0x10355137;
        pub const RECOVERY_SEED: u32 = 0x7693d7fb;
        pub const END_RECORD: u32 = 0x05030208;
    }
    pub mod mg2 {
        pub const FILE: u32 = 0x0729e45f;
        pub const END_RECORD: u32 = 0x05030208;
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Version {
    Mrs1,
    Mrs2,
    Mrs3,
    Mg2,
    Mg3,
}

fn main() {
    let writer: Mutex<Box<dyn Write + Send>> = Mutex::new(Box::new(io::stdout())); //Shared writer for the threads

    let directory = PathBuf::from("."); // The directory to search for .mrs files
    let output = PathBuf::from("output"); // The directory to output the files to

    // Get all the .mrs files in the directory. Is this correct? This just seems weird.
    let mrs_files: Vec<_> = WalkDir::new(&directory) // Walk the directory
        .into_iter()
        .filter_map(Result::ok) // Filter out the errors
        .filter(|entry| {
            entry
                .path() // Get the full path of the entry
                .extension() // Get the extension of the entry
                .and_then(|ext| ext.to_str()) // Convert the extension to a string
                .map(|ext| ext.eq_ignore_ascii_case("mrs")) // Check if the extension is "mrs"
                .unwrap_or(false) // If the extension is not "mrs", return false
        })
        .map(|entry| entry.into_path()) // Convert the entry to a path
        .collect(); // Collect the paths into a vector

    if mrs_files.is_empty() {
        let _ = writeln!(writer.lock().unwrap(), "No .mrs files found.");
    } else {
        let num_threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(1); // Get the number of available threads, if for some reason this fails, use 1 thread

        thread::scope(|scope| {
            for chunk in mrs_files.chunks(mrs_files.len().div_ceil(num_threads).max(1)) {
                let output = &output;
                let directory = &directory;
                let writer = &writer;
                scope.spawn(move || { // Spawn a new thread for each chunk
                    for path in chunk {
                        let relative = path.strip_prefix(directory).unwrap_or(path); // Get the relative path of the file
                        let dest = output.join(relative.with_extension(""));
                        match extract_archive(path, &dest, writer) { // Extract the archive
                            Ok(()) => {}
                            Err(err) => {
                                let _ = writeln!(
                                    writer.lock().unwrap(),
                                    "{}: Error: {err}",
                                    path.display()
                                );
                            }
                        }
                    }
                });
            }
        });
    }
}

fn extract_archive(
    path: &Path,
    output: &Path,
    writer: &Mutex<Box<dyn Write + Send>>,
) -> io::Result<()> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file); // 8KiB chunked buffer for the file

    let mut buf = [0u8; 4]; // [unsigned 8-bit integer] of length 4 filled with 0
    reader.read_exact(&mut buf)?;
    let file_sig = u32::from_le_bytes(buf); // Convert the 4 bytes to a 32-bit unsigned integer

    // Determine the version and seed of the archive
    let (mut version, seed) = match file_sig { // Basiclly a switch statement
        signatures::v1::FILE => (Version::Mrs1, 0),
        signatures::v2::FILE | signatures::v2::FILE_ALT => (Version::Mrs2, 0),
        signatures::mg2::FILE => (Version::Mg2, 0),
        signatures::v3::FILE => (Version::Mrs3, generate_seed(signatures::v3::RECOVERY_SEED)),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unrecognized archive format",
            ))
        }
    };

    let mut end = vec![0u8; 22];
    loop {
        reader.seek(SeekFrom::End(-22))?;
        reader.read_exact(&mut end)?;
        recover(&mut end, version, seed);

        let sig = u32::from_le_bytes(end[0..4].try_into().unwrap());
        let valid = match version {
            Version::Mrs1 => sig == signatures::v1::END_RECORD || sig == signatures::v1::END_RECORD_ALT,
            Version::Mrs2 => sig == signatures::v2::END_RECORD || sig == signatures::v2::END_RECORD_ALT,
            Version::Mrs3 => sig == signatures::v3::END_RECORD,
            Version::Mg2 => sig == signatures::mg2::END_RECORD,
            Version::Mg3 => sig == signatures::mg2::END_RECORD,
        };
        
        if valid {
            break;
        }
        
        // If Mrs2 validation failed, try with Mg3
        // I will clean this up later, but for now it works.
        if version == Version::Mrs2 {
            version = Version::Mg3;
            continue;
        }
        
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid end record",
        ));
    }

    let file_count = u16::from_le_bytes(end[8..10].try_into().unwrap());
    std::fs::create_dir_all(output)?;
    reader.seek(SeekFrom::Start(0))?;

    let _ = writeln!(writer.lock().unwrap(), "{}", path.display());

    for _ in 0..file_count {
        let mut header = vec![0u8; 30];
        reader.read_exact(&mut header)?;
        recover(&mut header, version, seed);
        let crc32 = u32::from_le_bytes(header[14..18].try_into().unwrap());
        let compressed_size = u32::from_le_bytes(header[18..22].try_into().unwrap());
        let uncompressed_size = u32::from_le_bytes(header[22..26].try_into().unwrap());
        let name_len = u16::from_le_bytes(header[26..28].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(header[28..30].try_into().unwrap()) as usize;

        let mut name_buf = vec![0u8; name_len];
        reader.read_exact(&mut name_buf)?;
        recover(&mut name_buf, version, seed);
        let name = String::from_utf8_lossy(&name_buf).to_string();

        reader.seek(SeekFrom::Current(extra_len as i64))?;

        if name.ends_with('/') {
            continue;
        }

        let data = if compressed_size == uncompressed_size {
            let mut buf = vec![0u8; uncompressed_size as usize];
            reader.read_exact(&mut buf)?;
            buf
        } else {
            let mut compressed = vec![0u8; compressed_size as usize];
            reader.read_exact(&mut compressed)?;
            let mut buf = vec![0u8; uncompressed_size as usize];
            DeflateDecoder::new(Cursor::new(&compressed)).read_exact(&mut buf)?;
            if crc32fast::hash(&buf) != crc32 {
                let _ = writeln!(writer.lock().unwrap(), "  CRC mismatch: {name}");
                continue;
            }
            buf
        };

        let dest = output.join(&name);
        if dest.exists() {
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        File::create(&dest)?.write_all(&data)?;
        let _ = writeln!(writer.lock().unwrap(), "  {name}");
    }

    Ok(())
}

fn recover(buf: &mut [u8], version: Version, seed: u32) {
    match version {
        Version::Mrs1 => {}
        Version::Mrs2 => {
            for byte in buf.iter_mut() {
                *byte = byte.rotate_right(3) ^ 0xFF;
            }
        }
        Version::Mrs3 => {
            let mut prng = seed;
            for (i, byte) in buf.iter_mut().enumerate() {
                if (i & 3) == 0 {
                    prng ^= prng << 13;
                    prng ^= prng >> 17;
                    prng ^= prng << 5;
                }
                *byte ^= ((prng >> ((i & 3) * 8)) & 0xFF) as u8;
            }
        }
        Version::Mg2 => {
            const KEY: [u8; 18] = [
                15, 175, 42, 3, 133, 66, 147, 103, 210, 220, 162, 64, 141, 113, 153, 247, 191, 153,
            ];
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte ^= KEY[i % 18];
            }
        }
        Version::Mg3 => {
            const KEY: [u8; 100] = [
                0xCE, 0x9E, 0x4D, 0x68, 0xAE, 0x9D, 0x0E, 0x3C, 0xD1, 0x88,
                0x91, 0x43, 0x81, 0x9C, 0x9A, 0xD3, 0xAC, 0x67, 0x0F, 0x00,
                0xC3, 0x8C, 0x76, 0x89, 0x12, 0xF4, 0x92, 0xE9, 0x1E, 0xBA,
                0x4B, 0x90, 0xB1, 0x9A, 0xDF, 0xC8, 0x42, 0x77, 0x2C, 0x73,
                0xC7, 0x9C, 0xD8, 0x79, 0x7F, 0xFE, 0xD8, 0x6E, 0x3E, 0x13,
                0x39, 0x4A, 0x5C, 0x3D, 0xCA, 0x0D, 0xDE, 0x84, 0xE9, 0x8F,
                0x10, 0x61, 0xE7, 0xC1, 0xEA, 0x39, 0x80, 0xCA, 0x77, 0xF8,
                0x9A, 0x38, 0xCE, 0x1F, 0xF7, 0x1B, 0xF6, 0x53, 0x20, 0xF7,
                0xF9, 0x64, 0x9D, 0x95, 0xEB, 0x0F, 0xCD, 0x0B, 0x02, 0x81,
                0x81, 0x80, 0x1C, 0x0E, 0xFE, 0x5C, 0xC2, 0xD4, 0x95, 0x31,
            ];
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte ^= KEY[i % 100];
            }
        }
    }
}

fn generate_seed(input: u32) -> u32 {
    (input ^ 0xDEAD1234).wrapping_add(0x00337799)
}


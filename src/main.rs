mod chacha;

use self::chacha::ChacCha20;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::fs::FileExt;

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        3 => {
            let password = &args[1];
            let infile = &args[2];
            encrypt_same_out(&password, &infile);
        }
        4 => {
            let password = &args[1];
            let infile = &args[2];
            let outfile = &args[3];
            encrypt_separate_out(&password, &infile, &outfile);
        }

        _ => println!("Missing arguments!"),
    }
}

fn encrypt_separate_out(password: &str, infile: &str, outfile: &str) {
    let flen = std::fs::metadata(&infile)
        .expect("unable to get metadata")
        .len() as u64;
    let inbuffer = File::open(infile).expect("unable to open file");
    let mut buffer = File::create(outfile).expect("unable to create file");
    let mut count = 0;

    for n in (0..flen).step_by(8192) {
        let data = read_file_chunk(&infile, &inbuffer, password.clone(), n);
        let mut pos = 0;

        while pos < data.len() {
            let bytes_written = buffer
                .write(&data[pos..])
                .expect("Unable to write content to file");
            pos += bytes_written;
        }

        if count % 1000 == 0 {
            print!("{} of {} bytes\r", n, flen);
        }
        count += 1;
    }
    println!(
        "done!                                                                                  "
    );
    buffer
        .flush()
        .expect("unable to ensure file written to disk");
    println!("File fully processed!");
}

fn encrypt_same_out(password: &str, infile: &str) {
    let flen = std::fs::metadata(&infile)
        .expect("unable to get metadata")
        .len() as u64;
    let mut buffer = File::options()
        .read(true)
        .write(true)
        .open(infile)
        .expect("unable to create file");
    let mut count = 0;

    for n in (0..flen).step_by(8192) {
        let data = read_file_chunk(&infile, &buffer, password.clone(), n);
        let mut pos = 0;

        while pos < data.len() {
            let bytes_written = buffer
                .write(&data[pos..])
                .expect("Unable to write content to file");
            pos += bytes_written;
        }

        if count % 1000 == 0 {
            print!("{} of {} bytes\r", n, flen);
        }
        count += 1;
    }
    println!(
        "done!                                                                                  "
    );
    buffer
        .flush()
        .expect("unable to ensure file written to disk");
    println!("File fully processed!");
}

fn read_file_chunk(file: &str, encfile: &File, key: &str, byte: u64) -> Vec<u8> {
    use std::fs;

    let mut cipher = ChacCha20::new(key.to_string(), &get_nonce());

    let cstart = (byte as f64 / 64.0).floor() as u64;
    let bstart = cstart * 64;
    let diff = byte - bstart;

    let flen = fs::metadata(file).expect("unable to get metadata").len() - bstart;
    let mainvec: Vec<u8>;

    if flen < 8192 {
        let mut buf: Vec<u8>;
        let mut content: [u8; 8192] = [0; 8192];
        match encfile.read_exact_at(&mut content, bstart) {
            Ok(_) => (),
            Err(_) => (),
        };

        buf = content[..flen as usize].to_vec();

        cipher.set_current_block(bstart);
        cipher.stream(&mut buf);
        mainvec = buf;
    } else {
        let mut bufdata: [u8; 8192] = [0; 8192];
        encfile
            .read_exact_at(&mut bufdata, bstart)
            .expect("unable to read file");

        cipher.set_current_block(bstart);
        cipher.stream(&mut bufdata);
        mainvec = bufdata.to_vec();
    }
    return mainvec[diff as usize..].to_vec();
}

fn get_nonce() -> Vec<u8> {
    let data = b"8023d6f881dcf6ed";
    let mut ret: Vec<u8> = Vec::new();
    for n in data {
        ret.push(n.clone());
    }
    ret
}

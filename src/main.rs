
extern crate clap;
extern crate hex;

use clap::{App, Arg};
use image;
use std::{collections::HashSet, fs, io::{prelude::*, BufReader}, path};

type HTTPRequest = (String, Vec<u8>);
type Dictionary = (String, Vec<String>);

fn main() {

    let matches = App::new("Packet Analyzer")
        .version("0.1.0")
        .author("Adam Vandenbussche")
        .about("Searches binary data for substrings in given dictionaries")
        .arg(Arg::with_name("input directory")
            .short("i")
            .takes_value(true)
            .multiple(false)
            .required(true)
            .help("A directory files to search"))
        .arg(Arg::with_name("output directory")
            .short("o")
            .takes_value(true)
            .multiple(false)
            .required(true)
            .help("The directory in which to save any found images"))
        .arg(Arg::with_name("dictionary")
                .short("d")
                .takes_value(true)
                .multiple(true)
                .min_values(1)
                .required(true)
                .help("A dictionary of words to search for"))
        .get_matches();

    let input_directory = matches.value_of("input directory").unwrap();
    let input_files = fs::read_dir(input_directory).unwrap();

    let output_directory = matches.value_of("output directory").unwrap();

    for input_file in input_files {

        let path = input_file.unwrap().path();
        let filename = path.file_name().unwrap();
        let filename_as_str = filename.to_str().unwrap();

        let file = fs::File::open(&path).expect("Could not open dictionary");
        let mut buf = BufReader::new(file);

        println!("SCANNING FILE {}", filename_as_str);

        let http_request_data = load_http_requests(&mut buf);
        for request in http_request_data {

            println!("Scanning URL {}", request.0);

            if contains_image_data(&request) {
                println!("Requst contains image data!");
                save_image(&request, filename_as_str, output_directory)
            } else {
                println!("Request does not contain image data.");
            }

        }

        let dictionary_iterator = matches.values_of("dictionary");
        let dictionaries = dictionary_iterator.unwrap().map(|d| load_dictionary(path::Path::new(d))).collect::<Vec<Dictionary>>();
        search_buffer_for_words(&mut buf, &dictionaries);


        println!();

    }

}

fn search_buffer_for_words(file_buffer: &mut BufReader<fs::File>, dictionaries: &Vec<Dictionary>) {

    let mut searched_lines = HashSet::new();
    let mut sensitive_lines = HashSet::new();

    loop {

        let line = get_utf8_line(file_buffer);
        if line_is_null(&line) { break }

        let searched_line = line.clone();
        if searched_lines.contains(&searched_line) { continue }

        for dictionary in dictionaries {
            for word in &dictionary.1 {
                if word.len() < 4 { continue }
                if line.to_ascii_lowercase().contains(&word.to_ascii_lowercase()) {
                    if sensitive_lines.contains(&line) { continue }
                    sensitive_lines.insert(line.clone());
                    println!("Potentially sensitive line: {}", line)
                }
            }
        }

        searched_lines.insert(searched_line);
    }
}

fn load_dictionary(dictionary_path: &path::Path) -> Dictionary {
    let dictionary_name = dictionary_path.file_name().unwrap();
    let dictionary_name_as_string = dictionary_name.to_str().expect("Could not parse dictionary name");
    let file = fs::File::open(dictionary_path).expect("Could not open dictionary");
    let buf = BufReader::new(file);
    let dictionary: Dictionary = (String::from(dictionary_name_as_string), buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect());
    dictionary
}

fn load_http_requests(buf: &mut BufReader<fs::File>) -> Vec<HTTPRequest> {

    let mut requests = Vec::new();

    loop {

        let line = get_utf8_line(buf);

        if line_is_null(&line) { break }
        if line == "BEGINTLS" { break }

        let components = line.split_whitespace().collect::<Vec<&str>>();
        match components.len() {
            1 => {
                let new_request: HTTPRequest = (components[0].to_string(), Vec::new());
                requests.push(new_request);
                println!("Request contains no body")
            },
            2 => {
                let new_request: HTTPRequest = (components[0].to_string(), hex::decode(components[1]).unwrap());
                requests.push(new_request)
            },
            _ => {
                println!("Line contains too many components")
            }
        }

    }

    requests

}

fn get_utf8_line(file_buffer: &mut BufReader<fs::File>) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let bytes_read = file_buffer.read_until(0x0A as u8, &mut buf).unwrap();
    if bytes_read == 0 { return String::from_utf8(vec![0x00]).unwrap() }

    let mut ascii_buf: Vec<u8> = Vec::new();

    for byte in buf {
        if byte.is_ascii_alphanumeric() || byte.is_ascii_punctuation() || byte == b'\x09' {
            ascii_buf.push(byte);
        }
    }

    String::from_utf8(ascii_buf).unwrap()
}

fn line_is_null(line: &String) -> bool {
    if line.len() == 1 && line == "\x00" { return true }
    false
}

fn contains_image_data(request: &HTTPRequest) -> bool {
    if request.1.len() == 0 { return false }
    image::load_from_memory(&request.1).is_ok()
}

fn save_image(request: &HTTPRequest, filename: &str, directory: &str) {
    let image = image::load_from_memory(&request.1).expect("Cannot load image from data!");
    image.save(&format!("{}/{}.jpg", directory, filename)).expect(&format!("Could not save image to {}/{}.jpg", directory, filename));
}
use concrete_lib::*;
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use std::io::{BufRead, BufReader};
use std::time;
use serde::{Serialize, Deserialize};
use rand::*;
use core::ptr::null;
use itertools::Itertools;
use ndarray::Array;
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::LineWriter;

// Message-code struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteMessageCode {
    code : i32
}

// Ciphertext message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteCiphertext {
    message : VectorLWE
}

// Secret Key message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteSecretKey {
    secret_key : LWESecretKey
}

// Key Switching message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteKSK {
    change_key : LWEKSK
}

// Operation request
#[derive(Serialize, Deserialize, Debug)]
struct OperationRequest {
    sensor_ip : String,
    ciphertext_amount : i32
}

// Operation response
#[derive(Serialize, Deserialize, Debug)]
struct OperationResponse {
    ciphertexts : Vec<VectorLWE>
}

fn received_code_0(stream : &TcpStream){
    // Receive ciphertext from sensor
    let ciphertext = receive_ciphertext(stream);
    save_ciphertext(stream, ciphertext);
}

fn add_to_database(stream : &TcpStream, ciphertext_filename : String){
    // Get peer's IP address
    let peer_ip_owned : String = stream.peer_addr().unwrap().ip().to_string().to_owned();
    // Generate peer's Secret Key filename
    let suffix_borrowed : String = "_database.txt".to_owned();
    let filename = format!("{}{}", peer_ip_owned, suffix_borrowed);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&filename).unwrap();

    let mut file = LineWriter::new(file);
    file.write_all(ciphertext_filename.as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
}

fn get_ciphertext_filename(stream : &TcpStream) -> String{
    // Get peer's IP address
    let peer_ip_owned : String = stream.peer_addr().unwrap().ip().to_string().to_owned();
    // Generate peer's Secret Key filename
    let suffix_borrowed : String = "_ciphertext.txt".to_owned();
    let filename = format!("{}{}", peer_ip_owned, suffix_borrowed);
    return filename;
}

fn receive_ciphertext(stream : &TcpStream) -> VectorLWE{
    // RECEIVING MODULE
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    buffer.clear();
    let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

    /*if read_bytes == 0 { // If there is no incoming data
        return null;
    }*/

    // Deserialize
    let ciphertext : ConcreteCiphertext = serde_json::from_slice(&buffer).unwrap();
    return ciphertext.message;
}

fn save_ciphertext(stream : &TcpStream, ciphertext : VectorLWE){
    let ciphertext_filename = get_ciphertext_filename(stream);
    ciphertext.save(&ciphertext_filename).unwrap();
    add_to_database(stream, ciphertext_filename);
}

fn handle_client(stream : TcpStream){
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();

    loop{
        buffer.clear(); // Flush remaining buffer content
        println!("\n\nWaiting client message...");
        let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

        if read_bytes == 0 { // If there is no incoming data
            return ();
        }

        let msg_code : ConcreteMessageCode = serde_json::from_slice(&buffer).unwrap();
        println!("Received message-code: {:?}", msg_code.code);

        let stream_ref = reader.get_ref();

        match msg_code.code {
            0 => received_code_0(stream_ref),
            _ => println!("Incorrect code received!!"),
        }
    }
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:4444").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 4444");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection from: {}", stream.peer_addr().unwrap().ip().to_string());
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client(stream);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
}

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
use chrono;
use chrono::{DateTime, Utc};
use rand::distributions::uniform::SampleBorrow;
use std::convert::TryInto;

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
    ciphertext_amount : i32,
    sensor_ip : String
}

// Operation response
#[derive(Serialize, Deserialize, Debug)]
struct OperationResponse {
    ciphertexts : Vec<OperationIndividualResponse>
}

// Operation response
#[derive(Serialize, Deserialize, Debug)]
struct OperationIndividualResponse {
    ciphertext : VectorLWE,
    initial_datetime : String,
    final_datetime : String
}

fn received_code_0(stream : &TcpStream){
    // Receive ciphertext from sensor
    let ciphertext = receive_ciphertext(stream);
    // Save ciphertext and add entry to respective DB
    save_ciphertext(stream, ciphertext);
}

fn received_code_1(stream : &TcpStream){
    let request = receive_request(stream);
    perform_operation(request);
}

fn perform_operation(request : OperationRequest){
    // Get requested sensor's filename
    let filename = format!("{}{}", request.sensor_ip, "_database.txt");
    // Open file
    let file_database = OpenOptions::new()
        .read(true)
        .open(&filename).unwrap();
    // Obtain reader
    let reader = BufReader::new(file_database);
    // Read lines from file
    let mut temp_ciphertext = VectorLWE::zero(0, 1).unwrap(); // IMPORTANT!! THIS MAY NOT BE CORRECT!
    for (index, line) in reader.lines().enumerate() {
        let mut i : i32 = 1;
        if index < (i.borrow()*request.ciphertext_amount.borrow()).try_into().unwrap(){ // Needed to convert from i32 to usize
            // Read ciphertext filename from file
            let line = line.unwrap(); // Ignore errors.
            if index == 0 {
                temp_ciphertext = VectorLWE::load(&line).unwrap();
            }
            // Open and load ciphertext from filename
            let mut read_ciphertext = VectorLWE::load(&line).unwrap();
            if index > 0 {
                read_ciphertext.add_with_padding_inplace(&temp_ciphertext).unwrap();
            }
            temp_ciphertext = read_ciphertext;
            // Show the line and its number.
            println!("{}. {}", index + 1, line);
        } else{
            i = i+1;
        }


    }
}

fn send_operation_response(mut stream : &TcpStream, response : OperationResponse){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : 4 // VERIFY THIS CODE
    };
    stream.write(&serde_json::to_vec(&msg_code).unwrap()).unwrap();

    // Send message
    stream.write(&serde_json::to_vec(&response).unwrap()).unwrap();
}

fn receive_request(stream : &TcpStream) -> OperationRequest{
    // RECEIVING MODULE
    let mut de = serde_json::Deserializer::from_reader(stream);
    let request : OperationRequest = OperationRequest::deserialize(&mut de).unwrap();
    println!("Received Request: {} Amount: {}", request.sensor_ip, request.ciphertext_amount);
    return request;
}

fn add_to_database(stream : &TcpStream, ciphertext_filename : String){
    // Get peer's IP address
    let peer_ip_owned : String = stream.peer_addr().unwrap().ip().to_string().to_owned();
    // Generate peer's Secret Key filename
    let suffix_borrowed : String = "_database.txt".to_owned();
    let filename = format!("{}{}", peer_ip_owned, suffix_borrowed);
    // Open file or create in case it does not exist
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .open(&filename).unwrap();

    let mut file = LineWriter::new(file);
    // Write entry-line to file
    file.write_all(ciphertext_filename.as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
}

fn get_ciphertext_filename(stream : &TcpStream) -> String{
    // Get peer's IP address
    let peer_ip_owned : String = stream.peer_addr().unwrap().ip().to_string().to_owned();
    // Generate peer's Secret Key filename
    let suffix_borrowed : String = "_ciphertext.txt".to_owned();
    let filename = format!("{}{}{}{}", peer_ip_owned, "_", chrono::offset::Local::now().to_rfc3339(), suffix_borrowed);
    return filename;
}

fn receive_ciphertext(stream : &TcpStream) -> VectorLWE{
    // RECEIVING MODULE
    let mut de = serde_json::Deserializer::from_reader(stream);
    let ciphertext : ConcreteCiphertext= ConcreteCiphertext::deserialize(&mut de).unwrap();
    return ciphertext.message;
}

fn save_ciphertext(stream : &TcpStream, ciphertext : VectorLWE){
    // Obtain ciphertext filename
    let ciphertext_filename = get_ciphertext_filename(stream);
    // Save ciphertext
    ciphertext.save(&ciphertext_filename).unwrap();
    // Add entry to database
    add_to_database(stream, ciphertext_filename);
}

fn handle_client(stream : TcpStream){
    loop{
        // RECEIVING MODULE
        let mut de = serde_json::Deserializer::from_reader(&stream);
        let msg_code : ConcreteMessageCode= ConcreteMessageCode::deserialize(&mut de).unwrap();
        println!("Received message-code: {:?}", msg_code.code);

        match msg_code.code {
            0 => received_code_0(&stream), // Receive ciphertext from sensor
            1 => received_code_1(&stream), // Receive operation request from client
            _ => println!("Incorrect code received!!"),
        }
    }
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3333");
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

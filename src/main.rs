use crypt_file::FileCryptr;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Usage: crypt_file --encrypt <input_file> <output_file> <key>
    // Usage: crypt_file --decrypt <input_file> <output_file> <key>

    let params = validate_params(&args);
    if params.is_none() {
        return;
    }
    let (is_encrypt, input_file, output_file, key) = params.unwrap();
    let fc = FileCryptr::new(input_file, output_file, key);
    if let Err(err) = fc {
        println!("Error: {}", err);
        return;
    }
    let mut fc = fc.unwrap();

    if is_encrypt {
        match fc.encrypt() {
            Ok(_) => {
                println!("File encrypted");
            }
            Err(err) => {
                println!("Error: {}", err);
            }
        };
    } else {
        match fc.decrypt() {
            Ok(_) => {
                println!("File decrypted");
            }
            Err(err) => {
                println!("Error: {}", err);
            }
        };
    }
}

fn validate_params(args: &Vec<String>) -> Option<(bool, String, String, String)> {
    if args.len() != 5 {
        println!("Usage: crypt_file --encrypt <input_file> <output_file> <key>");
        println!("Usage: crypt_file --decrypt <input_file> <output_file> <key>");
        return None;
    }

    // Parse the command line arguments
    let command = args[1].as_str();
    if command != "--encrypt" && command != "--decrypt" {
        println!("Usage: crypt_file --encrypt <input_file> <output_file> <key>");
        println!("Usage: crypt_file --decrypt <input_file> <output_file> <key>");
        return None;
    }
    let is_enctrypt = command == "--encrypt";

    Some((
        is_enctrypt,
        args[2].clone(),
        args[3].clone(),
        args[4].clone(),
    ))
}

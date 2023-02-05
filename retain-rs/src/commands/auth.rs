use crate::commands::ipc::IPCConnection;
use crate::commands::{Command, Response};
use base64::Engine;
use clap::ArgMatches;
use std::io::Write;

pub async fn handle(_args: &ArgMatches, ipc: &mut IPCConnection) -> Result<(), ()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    eprintln!("Authenticate with the B2 API to get started");
    eprintln!(
        "You will need an app key. This consist of the applicationKeyId and the applicationKey"
    );
    eprintln!(
        r#"SECURITY NOTICE - PLEASE READ
The app key will be stored as plaintext in the config file

The app key MUST be restricted to a single bucket. This bucket will be used for backing up files.
Note that the chosen bucket MUST be empty beforehand and should NEVER have any files that aren't created by this program.
Any unexpected files will be deleted, since this program removes files that can't be found on disk.
"#
    );

    eprint!("Application key id: ");
    let _ = stdout.flush();
    let mut line = String::with_capacity(40);
    stdin.read_line(&mut line).unwrap();
    let application_key_id = line.trim();

    eprint!("Application key: ");
    let _ = stdout.flush();
    let mut line = String::with_capacity(40);
    stdin.read_line(&mut line).unwrap();
    let application_key = line.trim();

    let key_string = format!("{}:{}", application_key_id, application_key);
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(key_string);

    let auth = ipc.send_command(Command::Authenticate, encoded_key).await;

    match auth {
        Ok(auth) => match auth {
            (Response::Ok, _) => {
                println!("Auth OK");
            }
            (Response::Err, err) => {
                println!("Authorization failed: {err}");
            }
        },
        Err(err) => println!("Communication failure: {:?}", err),
    }

    Ok(())
}

use structopt::StructOpt;
use std::path::PathBuf;
use rpassword::read_password;
use std::io;
use std::io::Write;

fn get_password(prompt: &str) -> io::Result<String> {
    // Print the prompt without a newline and flush stdout
    print!("{}", prompt);
    io::stdout().flush()?;

    // Read password from stdin without echo
    let password = read_password()?;
    Ok(password)
}

#[derive(Debug, Clone, StructOpt)]
pub struct Args {
    #[structopt(long)]
    url: String,
    /// Create OIDC client in keycloak
    #[structopt(short, long)]
    create_client: Option<String>,
    /// keycloak realm
    #[structopt(short, long)]
    realm: Option<String>,
    /// username of the keycloak admin account
    #[structopt(short, long)]
    username: String,
    /// file to output OIDC config to
    #[structopt(short, long)]
    output: Option<PathBuf>,
    /// Path to keycloak admin account password
    #[structopt(short, long)]
    password_file: Option<PathBuf>,
}

fn main() {
    let args = Args::from_args();
    /*let password = match args.password_file {
        Some(password_file) => {
            read_password_from_file(&password_file).unwrap()
        },
        None => get_password("please enter admin password").unwrap(),
    };*/

}

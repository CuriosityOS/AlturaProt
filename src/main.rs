use altura_prot::{cli, BoxError};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    cli::execute_async(cli::parse_cli()).await
}

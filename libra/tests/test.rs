use libra::{
    client,
    server::{self, TokioStream},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn echo() {
    let echo_listen = TcpListener::bind("127.0.0.1:8764").await.unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = echo_listen.accept().await.unwrap();
            let (mut reader, mut writer) = stream.into_split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        }
    });

    let listen = TcpListener::bind("127.0.0.1:8765").await.unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listen.accept().await.unwrap();
            let (mut dst, mut src) = server::Builder::new(TokioStream)
                .handshake(stream)
                .await
                .unwrap();
            tokio::io::copy_bidirectional(&mut dst, &mut src)
                .await
                .unwrap();
        }
    });

    let stream = TcpStream::connect("127.0.0.1:8765").await.unwrap();
    let mut stream = client::Builder::default()
        .set_addr("127.0.0.1:8764".parse().unwrap())
        .handshake(stream)
        .await
        .unwrap();
    stream.write_all(b"hello world\r\n").await.unwrap();
    let mut data = String::new();
    BufReader::new(stream).read_line(&mut data).await.unwrap();
    println!("{}", data);
    assert_eq!(data, "hello world\r\n")
}

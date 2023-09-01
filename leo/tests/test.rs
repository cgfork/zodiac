use leo::{client, server};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufStream},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn test_echo() {
    let echo_listen = TcpListener::bind("127.0.0.1:9764").await.unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = echo_listen.accept().await.unwrap();
            let (mut reader, mut writer) = stream.into_split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        }
    });

    let listen = TcpListener::bind("127.0.0.1:9765").await.unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listen.accept().await.unwrap();
            let buf = BufStream::new(stream);
            let (mut src, dst) = server::Builder::default().handshake(buf).await.unwrap();
            let mut dst = TcpStream::connect(&dst).await.unwrap();
            tokio::io::copy_bidirectional(&mut src, &mut dst)
                .await
                .unwrap();
        }
    });

    let stream = TcpStream::connect("127.0.0.1:9765").await.unwrap();
    let buf = BufStream::new(stream);
    let mut stream = client::Builder::default()
        .set_host_port("127.0.0.1".to_string(), 9764)
        .handshake(buf)
        .await
        .unwrap();
    stream.write_all(b"hello world\r\n").await.unwrap();
    stream.flush().await.unwrap();
    let mut data = String::new();
    BufReader::new(stream).read_line(&mut data).await.unwrap();
    println!("{}", data);
    assert_eq!(data, "hello world\r\n")
}

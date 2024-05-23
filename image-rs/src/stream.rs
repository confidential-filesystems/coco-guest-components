// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use sha2::Digest;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::digest::{DigestHasher, LayerDigestHasher, DIGEST_SHA256_PREFIX, DIGEST_SHA512_PREFIX};
use crate::unpack::unpack;
use crate::ERR_BAD_UNCOMPRESSED_DIGEST;

const CAPACITY: usize = 65536;//65536;//32768;

// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(slog::o!("subsystem" => "cgroups"))
}

// Wrap a channel with [`Read`](std::io::Read) support.
// This can bridge the [`AsyncRead`](tokio::io::AsyncRead) from
// decrypt/decompress and impl Read for unpack.
struct ChannelRead {
    rx: Receiver<Vec<u8>>,
    current: Cursor<Vec<u8>>,
}

impl ChannelRead {
    fn new(rx: Receiver<Vec<u8>>) -> ChannelRead {
        ChannelRead {
            rx,
            current: Cursor::new(vec![]),
        }
    }
}

impl Read for ChannelRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Receive new buffer when we finish handled previous data.
        if self.current.position() == self.current.get_ref().len() as u64 {
            if let Ok(buffer) = self.rx.recv() {
                self.current = Cursor::new(buffer);
            } else {
                slog::info!(sl(), "confilesystem17 - ChannelRead.read(): Err ?");
            }

            // When recv() finished or failed, the sender will close the channel
            // which means EOF. The following read will also exit with EOF from
            // the exhausted cursor.
        }

        std::io::Read::read(&mut self.current, buf)
    }
}

/// stream_processing will handle async uncompressed layer data and
/// unpack to the destination, returns layer digest for verification.
pub async fn stream_processing(
    layer_reader: impl AsyncRead + Unpin,
    diff_id: &str,
    destination: &Path,
) -> Result<String> {
    let dest = destination.to_path_buf();
    let hasher = if diff_id.starts_with(DIGEST_SHA256_PREFIX) {
        LayerDigestHasher::Sha256(sha2::Sha256::new())
    } else if diff_id.starts_with(DIGEST_SHA512_PREFIX) {
        LayerDigestHasher::Sha512(sha2::Sha512::new())
    } else {
        bail!("confilesystem17 - {}: {:?}", ERR_BAD_UNCOMPRESSED_DIGEST, diff_id);
    };

    channel_processing(layer_reader, hasher, dest, diff_id.to_string())
        .await
        .map_err(|e| anyhow!("confilesystem17 - hasher {} {:?}", DIGEST_SHA256_PREFIX, e))
}

async fn channel_processing(
    mut layer_reader: (impl AsyncRead + Unpin),
    mut hasher: LayerDigestHasher,
    destination: PathBuf,
    diff_id: String,
) -> Result<String> {
    let (tx, rx) = channel();
    //let diff_id_tmp = diff_id.clone();
    let destination_tmp = destination.clone();
    let unpack_thread = std::thread::spawn(move || {
        let mut input = ChannelRead::new(rx);

        //slog::info!(sl(), "confilesystem17 - channel_processing(): In unpack_thread() destination.as_path() = {:?}, diff_id = {:?}",
        //        destination.as_path(), diff_id_tmp);
        if let Err(e) = unpack(&mut input, destination_tmp.as_path()) {
            // TODO
            //slog::info!(sl(), "confilesystem17 - channel_processing(): Err unpack() destination.as_path() = {:?}, diff_id = {:?} -> e = {:?}",
            //    destination.as_path(), diff_id_tmp, e);
            fs::remove_dir_all(destination_tmp.as_path())
                .context("Failed to roll back when unpacking")?;
            return Err(e);
        }

        //slog::info!(sl(), "confilesystem17 - channel_processing(): Out unpack_thread() destination.as_path() = {:?}, diff_id = {:?}",
        //    destination.as_path(), diff_id_tmp);
        Result::<()>::Ok(())
    });

    //std::thread::sleep(std::time::Duration::from_secs(1));

    let mut layer_data_num: u64 = 0;
    let mut layer_data_total: u64 = 0;
    let mut last_n = 0;
    loop {
        let mut buffer = vec![0u8; CAPACITY];
        let n = layer_reader
            .read(&mut buffer)
            .await
            .map_err(|e| anyhow!("channel: read failed {:?}", e))?;
        if n == 0 {
            break;
        }

        layer_data_num = layer_data_num + 1;
        layer_data_total = layer_data_total + (n as u64);
        buffer.resize(n, 0);
        hasher.digest_update(&buffer);
        //slog::info!(sl(), "confilesystem17 - channel_processing(): CAPACITY = {:?}, n = {:?}, buffer.len() = {:?}",
        //    CAPACITY, n, buffer.len());
        tx.send(buffer)
            .map_err(|e| anyhow!("confilesystem17 - channel: send failed - destination.as_path() = {:?}, diff_id = {:?}, CAPACITY = {:?}, last_n = {:?}, n = {:?}, layer_data_num = {:?}, layer_data_total = {:?}, e = {:?}",
                destination.as_path(), diff_id, CAPACITY, last_n, n, layer_data_num, layer_data_total, e))?;
        last_n = n;
    }
    slog::info!(sl(), "confilesystem17 - channel_processing(): OK - destination.as_path() = {:?}, diff_id = {:?}, CAPACITY = {:?}, last_n = {:?}, layer_data_num = {:?}, layer_data_total = {:?}",
        destination.as_path(), diff_id, CAPACITY, last_n, layer_data_num, layer_data_total);

    // Close the channel to signal EOF.
    drop(tx);

    tokio::task::spawn_blocking(|| unpack_thread.join())
        .await?
        .map_err(|e| anyhow!("confilesystem17 - channel: unpack thread failed {:?}", e))
        .unwrap()?;

    Ok(hasher.digest_finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rand::rand_bytes;
    use std::fs::File;
    use std::io::BufReader;
    use tar::{Builder, Header};
    use tempfile;

    #[tokio::test]
    async fn test_channel_processing() {
        let mut data = [0; 100000];
        rand_bytes(&mut data).unwrap();
        let data_digest = sha2::Sha256::digest(data.as_slice());

        let mut ar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(100000);
        header.set_cksum();
        ar.append_data(&mut header, "file.txt", data.as_slice())
            .unwrap();

        let layer_data = ar.into_inner().unwrap();

        let layer_digest = format!(
            "{}{:x}",
            DIGEST_SHA256_PREFIX,
            sha2::Sha256::digest(layer_data.as_slice())
        );

        let tempdir = tempfile::tempdir().unwrap();
        let file_path = tempdir.path().join("layer0");

        let hasher = LayerDigestHasher::Sha256(sha2::Sha256::new());

        let layer_digest_new =
            channel_processing(layer_data.as_slice(), hasher, file_path.to_path_buf())
                .await
                .unwrap();
        assert_eq!(layer_digest, layer_digest_new);

        let file = File::open(file_path.join("file.txt")).unwrap();
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer).unwrap();
        let data_digest_new = sha2::Sha256::digest(buffer);
        assert_eq!(data_digest, data_digest_new);
    }

    #[tokio::test]
    async fn test_stream_processing() {
        let mut data = [0; 100000];
        rand_bytes(&mut data).unwrap();

        let mut ar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(100000);
        header.set_cksum();
        ar.append_data(&mut header, "file.txt", data.as_slice())
            .unwrap();

        let layer_data = ar.into_inner().unwrap();

        let layer_digest = format!(
            "{}{:x}",
            DIGEST_SHA256_PREFIX,
            sha2::Sha256::digest(layer_data.as_slice())
        );

        let tempdir = tempfile::tempdir().unwrap();
        let file_path = tempdir.path().join("layer0");

        let layer_digest_new = stream_processing(layer_data.as_slice(), &layer_digest, &file_path)
            .await
            .unwrap();
        assert_eq!(layer_digest, layer_digest_new);

        let tempdir = tempfile::tempdir().unwrap();
        let file_path = tempdir.path().join("layer1");
        let layer_digest = format!(
            "{}{:x}",
            DIGEST_SHA512_PREFIX,
            sha2::Sha512::digest(layer_data.as_slice())
        );

        let layer_digest_new = stream_processing(layer_data.as_slice(), &layer_digest, &file_path)
            .await
            .unwrap();
        assert_eq!(layer_digest, layer_digest_new);
    }
}

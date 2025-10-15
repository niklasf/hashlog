use std::{fs, fs::File, io::Read, path, path::PathBuf};

use clap::Parser;
use digest::Digest;
use rusqlite::{Connection, OpenFlags};
use sha1::Sha1;
use sha2::Sha256;

#[derive(clap::Parser, Debug)]
enum Command {
    Add(Add),
    Remove(Remove),
}

#[derive(clap::Parser, Debug)]
struct Add {
    #[clap(long)]
    md5: bool,
    #[clap(long)]
    sha1: bool,
    #[clap(long)]
    sha256: bool,
    files: Vec<PathBuf>,
}

#[derive(clap::Parser, Debug)]
struct Remove {
    files: Vec<PathBuf>,
}

fn main() {
    let opt = Command::parse();

    let conn = init_database();

    match opt {
        Command::Add(add) => do_add(&conn, &add),
        Command::Remove(remove) => do_remove(&conn, &remove),
    }
}

fn do_add(conn: &Connection, add: &Add) {
    assert!(add.md5 || add.sha1 || add.sha256);

    let hostname = hostname::get()
        .expect("hostname")
        .to_str()
        .expect("hostname as str")
        .to_owned();

    let mut buffer = [0; 1 << 14];

    let mut stmt = conn
        .prepare(
            "INSERT INTO hashes (hostname, path, algorithm, hash, size) VALUES (?, ?, ?, ?, ?)",
        )
        .expect("prepare statement");

    for file in &add.files {
        let abs_path = path::absolute(file)
            .expect("absolute path")
            .to_str()
            .expect("path to string")
            .to_owned();

        let mut reader = File::open(&abs_path).expect("open file");

        let mut md5 = add.md5.then(md5::Context::new);
        let mut sha1 = add.sha1.then(Sha1::new);
        let mut sha256 = add.sha256.then(Sha256::new);
        let mut size = 0;

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(md5) = &mut md5 {
                        md5.consume(&buffer[..n]);
                    }
                    if let Some(sha1) = &mut sha1 {
                        sha1.update(&buffer[..n]);
                    }
                    if let Some(sha256) = &mut sha256 {
                        sha256.update(&buffer[..n]);
                    }
                    size += n as i64;
                }
                Err(e) => panic!("Error reading {file:?}: {e}"),
            }
        }

        if let Some(md5) = md5 {
            stmt.execute((&hostname, &abs_path, "md5", &md5.finalize().0, size))
                .expect("insert md5");
        }
        if let Some(sha1) = sha1 {
            stmt.execute((&hostname, &abs_path, "sha1", &sha1.finalize()[..], size))
                .expect("insert sha1");
        }
        if let Some(sha256) = sha256 {
            stmt.execute((&hostname, &abs_path, "sha256", &sha256.finalize()[..], size))
                .expect("insert sha256");
        }
    }
}

fn do_remove(conn: &Connection, remove: &Remove) {
    let hostname = hostname::get()
        .expect("hostname")
        .to_str()
        .expect("hostname as str")
        .to_owned();

    let mut stmt = conn
        .prepare("DELETE FROM hashes WHERE hostname = ? AND path = ?")
        .expect("prepare statement");

    for file in &remove.files {
        let abs_path = path::absolute(file)
            .expect("absolute path")
            .to_str()
            .expect("path to string")
            .to_owned();

        stmt.execute((&hostname, &abs_path)).expect("delete hashes");
    }
}

fn init_database() -> Connection {
    let directory = dirs::data_dir().expect("data dir").join("hashlog");

    fs::create_dir_all(&directory).expect("create directory");

    let conn = Connection::open_with_flags(
        directory.join("hashlog.db"),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .expect("open database");

    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            path TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            hash BLOB NOT NULL,
            size INTEGER NOT NULL,
            hashed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_hashes_hostname_path ON hashes (hostname, path);
        "#,
    )
    .expect("initialize schema");

    conn
}

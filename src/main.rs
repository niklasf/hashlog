use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    path::{self, PathBuf},
};

use clap::Parser;
use digest::Digest;
use rusqlite::{Connection, OpenFlags};
use sha1::Sha1;
use sha2::Sha256;
use walkdir::WalkDir;

#[derive(clap::Parser, Debug)]
enum Command {
    Add(Add),
    Remove(Remove),
    Export(Export),
    Check(Check),
}

#[derive(clap::Parser, Debug)]
struct Add {
    #[clap(long)]
    md5: bool,
    #[clap(long)]
    sha1: bool,
    #[clap(long)]
    sha256: bool,
    #[clap(long)]
    update: bool,
    paths: Vec<PathBuf>,
}

#[derive(clap::Parser, Debug)]
struct Remove {
    paths: Vec<PathBuf>,
}

#[derive(clap::Parser, Debug)]
struct Export {
    #[clap(long)]
    md5: bool,
    #[clap(long)]
    sha1: bool,
    #[clap(long)]
    sha256: bool,
    paths: Vec<PathBuf>,
}

#[derive(clap::Parser, Debug)]
struct Check {
    checksum_files: Vec<PathBuf>,
    #[clap(long, num_args = 1..)]
    prefix: Vec<String>,
}

fn main() {
    let opt = Command::parse();

    let conn = init_database();

    match opt {
        Command::Add(add) => do_add(&conn, &add),
        Command::Remove(remove) => do_remove(&conn, &remove),
        Command::Export(export) => do_export(&conn, &export),
        Command::Check(check) => do_check(&conn, &check),
    }
}

fn do_add(conn: &Connection, add: &Add) {
    assert!(add.md5 || add.sha1 || add.sha256);

    let hostname = hostname::get()
        .expect("hostname")
        .to_str()
        .expect("hostname as str")
        .to_owned();

    let mut buffer = [0; 1 << 16];

    let mut insert_stmt = conn
        .prepare(
            "INSERT INTO hashes (hostname, path, algorithm, hash, size) VALUES (?, ?, ?, ?, ?)",
        )
        .expect("prepare insert statement");

    let exists = |abs_path: &str, algorithm: &str| {
        conn.prepare_cached(
            "SELECT hash FROM hashes WHERE hostname = ? AND path = ? AND algorithm = ?",
        )
        .expect("prepare select statement")
        .exists((&hostname, &abs_path, algorithm))
        .expect("existance")
    };

    for path in &add.paths {
        for entry in WalkDir::new(path) {
            let entry = entry.expect("entry");
            if !entry.file_type().is_file() {
                continue;
            }

            let abs_path = path::absolute(entry.path())
                .expect("absolute path")
                .to_str()
                .expect("path to string")
                .to_owned();

            let mut md5 =
                (add.md5 && (add.update || !exists(&abs_path, "md5"))).then(md5::Context::new);
            let mut sha1 = (add.sha1 && (add.update || !exists(&abs_path, "sha1"))).then(Sha1::new);
            let mut sha256 =
                (add.sha256 && (add.update || !exists(&abs_path, "sha256"))).then(Sha256::new);

            if !md5.is_some() && !sha1.is_some() && !sha256.is_some() {
                continue;
            }

            println!("{abs_path}");

            let mut reader = File::open(&abs_path).expect("open file");
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
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => panic!("Error reading {abs_path:?}: {e}"),
                }
            }

            if let Some(md5) = md5 {
                insert_stmt
                    .execute((&hostname, &abs_path, "md5", &md5.finalize().0, size))
                    .expect("insert md5");
            }
            if let Some(sha1) = sha1 {
                insert_stmt
                    .execute((&hostname, &abs_path, "sha1", &sha1.finalize()[..], size))
                    .expect("insert sha1");
            }
            if let Some(sha256) = sha256 {
                insert_stmt
                    .execute((&hostname, &abs_path, "sha256", &sha256.finalize()[..], size))
                    .expect("insert sha256");
            }
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

    for path in &remove.paths {
        for entry in WalkDir::new(path) {
            let entry = entry.expect("entry");

            let abs_path = path::absolute(entry.path())
                .expect("absolute path")
                .to_str()
                .expect("path to string")
                .to_owned();

            stmt.execute((&hostname, &abs_path)).expect("delete hashes");
        }
    }
}

fn do_export(conn: &Connection, export: &Export) {
    let hostname = hostname::get()
        .expect("hostname")
        .to_str()
        .expect("hostname as str")
        .to_owned();

    assert!(u32::from(export.md5) + u32::from(export.sha1) + u32::from(export.sha256) == 1);

    let algorithm = if export.md5 {
        "md5"
    } else if export.sha1 {
        "sha1"
    } else {
        "sha256"
    };

    let mut stmt = conn
        .prepare("SELECT LOWER(HEX(hash)) FROM hashes WHERE hostname = ? AND path = ? AND algorithm = ? ORDER BY id DESC LIMIT 1")
        .expect("prepare statement");

    for path in &export.paths {
        for entry in WalkDir::new(path) {
            let entry = entry.expect("entry");
            if !entry.file_type().is_file() {
                continue;
            }

            let abs_path = path::absolute(entry.path())
                .expect("absolute path")
                .to_str()
                .expect("path to string")
                .to_owned();

            let mut rows = stmt
                .query((&hostname, &abs_path, algorithm))
                .expect("query");

            while let Some(row) = rows.next().expect("next") {
                let hash: String = row.get(0).expect("hash");
                println!("{}  {}", hash, entry.path().display());
            }
        }
    }
}

fn do_check(conn: &Connection, check: &Check) {
    let hostname = hostname::get()
        .expect("hostname")
        .to_str()
        .expect("hostname as str")
        .to_owned();

    let mut stmt = conn
        .prepare("SELECT path FROM hashes WHERE hash = ? AND hostname = ? ORDER BY id DESC LIMIT 1")
        .expect("prepare statement");

    for checksum_file in &check.checksum_files {
        let reader = BufReader::new(File::open(checksum_file).expect("open checksum file"));
        for line in reader.lines() {
            let line = line.expect(&format!("read line from {}", checksum_file.display()));
            let (hash, path) = line
                .split_once("  ")
                .or_else(|| line.split_once(" *"))
                .expect(&format!("split line: {}", line));
            let hash_bytes = hex::decode(hash).expect(&format!("decode hash: {}", hash));

            let mut rows = stmt.query((hash_bytes, &hostname)).expect("query");

            let candidate_paths = if check.prefix.is_empty() {
                vec![path.to_owned()]
            } else {
                check
                    .prefix
                    .iter()
                    .map(|p| format!("{}/{}", p, path))
                    .collect()
            };

            let mut found = None;
            let mut other_files = Vec::new();

            while let Some(row) = rows.next().expect("next") {
                let db_path: String = row.get(0).expect("get path");
                if candidate_paths.contains(&db_path) {
                    found = Some(db_path);
                    break;
                } else {
                    other_files.push(db_path);
                }
            }

            println!(
                "{}",
                found.expect(&format!(
                    "hash {} of {:?} does not match (but these files have it: {:?})",
                    hash, path, other_files
                ))
            )
        }
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

        CREATE UNIQUE INDEX IF NOT EXISTS idx_hashes_path ON hashes (hostname, path, algorithm);
        CREATE INDEX IF NOT EXISTS idx_hashes_hash ON hashes (hash);
        "#,
    )
    .expect("initialize schema");

    conn
}

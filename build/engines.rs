use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn run(command: &mut Command) -> Result<()> {
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other(format!("{command:?} exited with {status}")).into());
    }
    Ok(())
}

fn compiler(tool: &str, target: &str, default: impl Into<OsString>) -> OsString {
    let variable = format!("{tool}_{}", target.replace('-', "_"));
    println!("cargo:rerun-if-env-changed={variable}");
    println!("cargo:rerun-if-env-changed={tool}");
    env::var_os(variable)
        .or_else(|| env::var_os(tool))
        .unwrap_or_else(|| default.into())
}

struct Build {
    project: PathBuf,
    out: PathBuf,
    arch: String,
    cross: bool,
    cc: OsString,
    cxx: OsString,
}

impl Build {
    fn engine(&self, name: &str, target: &str, options: &[&str]) -> Result<PathBuf> {
        let relative = format!("vendor/{name}.tar.gz");
        println!("cargo:rerun-if-changed={relative}");
        let directory = self.out.join(name);
        let source = directory.join("source");
        let build = directory.join("build");
        fs::create_dir_all(&source)?;
        run(Command::new("tar")
            .args(["-xzf"])
            .arg(self.project.join(relative))
            .args(["--strip-components=1", "-C"])
            .arg(&source))?;

        let mut configure = Command::new("cmake");
        configure
            .arg("-S")
            .arg(&source)
            .arg("-B")
            .arg(&build)
            .args([
                "-G",
                "Ninja",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                "-DBUILD_SHARED_LIBS=OFF",
                "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
            ])
            .arg(option("-DCMAKE_C_COMPILER=", &self.cc))
            .arg(option("-DCMAKE_CXX_COMPILER=", &self.cxx))
            .args(options);
        if self.cross {
            configure
                .arg("-DCMAKE_SYSTEM_NAME=Linux")
                .arg(format!("-DCMAKE_SYSTEM_PROCESSOR={}", self.arch));
        }
        run(&mut configure)?;
        let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "1".into());
        run(Command::new("cmake").arg("--build").arg(&build).args([
            "--target",
            target,
            "--parallel",
            &jobs,
        ]))?;
        Ok(build)
    }
}

fn option(prefix: &str, value: &OsStr) -> OsString {
    let mut arg = OsString::from(prefix);
    arg.push(value);
    arg
}

fn link_search(directory: &Path) {
    println!("cargo:rustc-link-search=native={}", directory.display());
}

pub fn build() -> Result<()> {
    println!("cargo:rerun-if-changed=build/engines.rs");
    println!("cargo:rerun-if-changed=build/aarch64-musl-cc");
    println!("cargo:rerun-if-changed=build/x86_64-musl-cc");
    let project = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("engines");
    fs::create_dir_all(&out)?;
    let target = env::var("TARGET")?;
    let arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let musl = env::var("CARGO_CFG_TARGET_ENV")? == "musl";
    let cross = env::var("HOST")? != target;
    let (keystone, unicorn) = match arch.as_str() {
        "aarch64" => ("AArch64", "aarch64"),
        "x86_64" => ("X86", "x86"),
        _ => {
            return Err(
                io::Error::other(format!("unsupported engine architecture: {arch}")).into(),
            );
        }
    };
    let (cc, cxx) = if musl {
        let cc = project.join(format!("build/{arch}-musl-cc"));
        let cxx = out.join("musl-cxx");
        let script = format!("#!/bin/sh\nexec zig c++ -target {arch}-linux-musl \"$@\"\n");
        if fs::read_to_string(&cxx).ok().as_deref() != Some(&script) {
            fs::write(&cxx, script)?;
            fs::set_permissions(&cxx, fs::Permissions::from_mode(0o755))?;
        }
        (cc.into_os_string(), cxx.into_os_string())
    } else {
        let (cc, cxx) = if cross {
            (
                format!("{arch}-linux-gnu-gcc"),
                format!("{arch}-linux-gnu-g++"),
            )
        } else {
            ("cc".into(), "c++".into())
        };
        (compiler("CC", &target, cc), compiler("CXX", &target, cxx))
    };

    let build = Build {
        project,
        out,
        arch,
        cross,
        cc,
        cxx,
    };
    let keystone = build.engine(
        "keystone-0.9.2",
        "keystone",
        &[
            "-DBUILD_LIBS_ONLY=ON",
            "-DLLVM_ENABLE_ZLIB=OFF",
            "-DLLVM_ENABLE_TERMINFO=OFF",
            &format!("-DLLVM_TARGETS_TO_BUILD={keystone}"),
            &format!("-DLLVM_HOST_TRIPLE={target}"),
        ],
    )?;
    let unicorn = build.engine(
        "unicorn-engine-sys-2.1.5",
        "unicorn_archive",
        &[
            "-DUNICORN_BUILD_TESTS=OFF",
            "-DUNICORN_INSTALL=OFF",
            "-DUNICORN_LEGACY_STATIC_ARCHIVE=ON",
            &format!("-DUNICORN_ARCH={unicorn}"),
        ],
    )?;
    link_search(&keystone.join("llvm/lib"));
    link_search(&unicorn);
    println!("cargo:rustc-link-lib=static=keystone");
    println!("cargo:rustc-link-lib=static=unicorn");
    if musl {
        // The configured Zig linker resolves this to its static C++ runtime.
        println!("cargo:rustc-link-arg=-lc++");
    } else {
        let archive = Command::new(&build.cxx)
            .arg("-print-file-name=libstdc++.a")
            .output()?;
        let archive = String::from_utf8(archive.stdout)?;
        let location = Path::new(archive.trim());
        if !location.is_absolute() || !location.is_file() {
            return Err(io::Error::other("GNU C++ compiler must provide libstdc++.a").into());
        }
        link_search(location.parent().unwrap());
        println!("cargo:rustc-link-lib=static=stdc++");
    }
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
    Ok(())
}

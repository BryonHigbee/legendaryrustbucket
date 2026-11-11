//! Native Rust installation, update, verification and repair pipeline.
//! Downloads Epic BuildPatch chunks with a bounded worker pool, validates hashes,
//! stages complete files, then replaces them safely without deleting user files.
use crate::{epic, manifest, store};
use manifest::{ChunkInfo, FileInfo, Manifest};
use rayon::prelude::*;
use reqwest::blocking::Client;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct InstallOptions {
    pub app: String,
    pub dir: Option<PathBuf>,
    pub workers: usize,
    pub dry_run: bool,
}

pub fn default_path() -> Result<PathBuf, String> {
    dirs::data_local_dir().map(|base|base.join("LegendaryRustBucket/Games/RocketLeague"))
        .ok_or("No user data directory; pass --dir PATH".into())
}

fn safe_join(root: &Path, name: &str) -> Result<PathBuf, String> {
    let rel=manifest::path_in_install(name)?;
    let mut current=root.to_path_buf();
    // Never follow symlinked intermediate directories or output file paths.
    for component in rel.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!("Refusing to follow installation symlink: {}",current.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Cannot inspect installation path: {e}")),
        }
    }
    Ok(current)
}

fn cache_path(cache_dir: &Path, info: &ChunkInfo) -> PathBuf {
    cache_dir.join(format!("{}.chunk", hex::encode(info.guid)))
}

fn download_chunk(client:&Client, bases:&[String], cache_dir:&Path, info:&ChunkInfo,secrets:&manifest::Secrets)->Result<(),String>{
    let path=cache_path(cache_dir,info);
    if let Ok(data)=fs::read(&path) {
        if manifest::decode_chunk_with_secrets(&data,info,secrets).is_ok() {return Ok(());}
        // Corrupted cached chunks must not silently poison an installation.
        fs::remove_file(&path).map_err(|e| format!("Cannot remove corrupt cache chunk: {e}"))?;
    }
    let mut errors=Vec::new();
    for attempt in 0..3 {
        for base in bases {
            // Only accept secured Epic CDN paths; never allow untrusted HTTP or
            // file:// paths in production.
            let base_url=match reqwest::Url::parse(base) {
                Ok(url) if url.scheme()=="https" =>url,
                _=>{errors.push("Insecure CDN origin rejected".into());continue;}
            };
            let mut url=base_url;
            let append=info.url_path.split('/').collect::<Vec<_>>();
            if url.path_segments_mut().map(|mut p|{p.pop_if_empty();p.extend(&append);}).is_err() {
                errors.push("Cannot join chunk CDN URL".into());continue;
            }
            let response=match client.get(url).send() {
                Ok(response)=>response,
                Err(e)=>{errors.push(format!("Chunk network error: {e}"));continue;}
            };
            if !response.status().is_success(){
                errors.push(format!("CDN chunk HTTP {}",response.status()));continue;
            }
            let mut data=Vec::new();
            if response.take(33*1024*1024).read_to_end(&mut data).is_err() || data.len()>=33*1024*1024 {
                errors.push("Chunk download exceeds safety limit".into());continue;
            }
            if let Err(e)=manifest::decode_chunk_with_secrets(&data,info,secrets) {
                errors.push(format!("Chunk integrity error: {e}"));continue;
            }
            let temp=path.with_extension("chunk.part");
            fs::write(&temp,&data).map_err(|e|format!("Cannot write chunk cache: {e}"))?;
            match fs::rename(&temp,&path) {
                Ok(())=>return Ok(()),
                Err(e)=>{
                    let _=fs::remove_file(&temp);
                    // Another process may have created cache file. Verify it.
                    if let Ok(other)=fs::read(&path) {
                        if manifest::decode_chunk_with_secrets(&other,info,secrets).is_ok(){return Ok(());}
                    }
                    return Err(format!("Cannot publish cached chunk: {e}"));
                }
            }
        }
        if attempt<2 {std::thread::sleep(Duration::from_millis(300 * (1<<attempt)));}
    }
    Err(format!("Failed to retrieve chunk {} after retries: {}",hex::encode(info.guid),errors.into_iter().rev().take(3).collect::<Vec<_>>().join("; ")))
}

fn temp_path(target:&Path)->Result<PathBuf,String>{
    let name=target.file_name().and_then(|s|s.to_str()).ok_or("Invalid output file name")?;
    Ok(target.with_file_name(format!("{name}.lrb-part")))
}
fn publish_file(staged:&Path,target:&Path)->Result<(),String>{
    if target.exists(){
        let name=target.file_name().and_then(|s|s.to_str()).ok_or("Invalid output filename")?;
        let backup=target.with_file_name(format!("{name}.lrb-backup"));
        if backup.exists(){return Err(format!("Previous backup exists: {}. Resolve it before updating.",backup.display()));}
        fs::rename(target,&backup).map_err(|e|format!("Cannot back up existing file: {e}"))?;
        if let Err(e)=fs::rename(staged,target) {
            let _=fs::rename(&backup,target);
            return Err(format!("Cannot replace file (original restored): {e}"));
        }
        fs::remove_file(backup).map_err(|e|format!("Updated file, but could not remove backup: {e}"))?;
    } else {
        fs::rename(staged,target).map_err(|e|format!("Cannot publish staged file: {e}"))?;
    }
    Ok(())
}
fn assemble_file(root:&Path,cache:&Path,game_file:&FileInfo,chunks:&HashMap<[u8;16],ChunkInfo>,secrets:&manifest::Secrets)->Result<(),String>{
    let path=safe_join(root,&game_file.name)?;
    if let Some(parent)=path.parent(){fs::create_dir_all(parent).map_err(|e|format!("Cannot create install folder: {e}"))?;}
    let temp=temp_path(&path)?;
    if temp.exists(){fs::remove_file(&temp).map_err(|e|format!("Cannot remove previous partial: {e}"))?;}
    let output=OpenOptions::new().write(true).create_new(true).open(&temp)
        .map_err(|e|format!("Cannot create staging file {}: {e}",temp.display()))?;
    let result=(|| -> Result<(),String> {
        let mut output=BufWriter::new(output);
        let mut digest=Sha1::new();
        let mut written=0u64;
        for part in &game_file.parts {
            let chunk=chunks.get(&part.guid).ok_or("Manifest references unavailable chunk")?;
            let bytes=fs::read(cache_path(cache,chunk)).map_err(|e|format!("Cached chunk missing: {e}"))?;
            let decoded=manifest::decode_chunk_with_secrets(&bytes,chunk,secrets)?;
            let end=part.offset.checked_add(part.size).ok_or("Chunk offset overflow")?;
            let slice=decoded.get(part.offset..end).ok_or("Chunk part out of bounds")?;
            output.write_all(slice).map_err(|e|format!("Cannot write game file: {e}"))?;
            digest.update(slice);
            written=written.checked_add(slice.len() as u64).ok_or("File length overflow")?;
        }
        output.flush().map_err(|e|format!("Cannot flush game file: {e}"))?;
        let output=output.into_inner().map_err(|e|format!("Cannot finish game file: {e}"))?;
        output.sync_all().map_err(|e|format!("Cannot sync game file: {e}"))?;
        let actual:[u8;20]=digest.finalize().into();
        if written!=game_file.size || actual!=game_file.sha {
            return Err(format!("File SHA-1 mismatch after assembly: {}",game_file.name));
        }
        Ok(())
    })();
    if let Err(e)=result {let _=fs::remove_file(&temp);return Err(e);}
    publish_file(&temp,&path)?;
    #[cfg(unix)]
    if game_file.executable {
        use std::os::unix::fs::PermissionsExt;
        let mut p=fs::metadata(&path).map_err(|e|e.to_string())?.permissions();
        p.set_mode(p.mode()|0o111);
        fs::set_permissions(&path,p).map_err(|e|e.to_string())?;
    }
    Ok(())
}

fn read_manifest_for_game(game:&store::InstalledGame)->Result<Manifest,String>{
    let index=game.install_path.join(".lrb/index.bin");
    if index.is_file() {
        let data=fs::read(&index).map_err(|e|format!("Cannot read LRB install index: {e}"))?;
        if data.len()>128*1024*1024{return Err("LRB install index exceeds safety limit".into());}
        use bincode::Options;
        return bincode::DefaultOptions::new().with_fixint_encoding().with_limit(128*1024*1024)
            .deserialize(&data).map_err(|e|format!("Invalid LRB install index: {e}"));
    }
    let data=fs::read(game.install_path.join(".lrb/manifest.bin"))
        .map_err(|e|format!("No saved LRB install manifest for this game: {e}. Run lrb update to fetch it."))?;
    manifest::parse(&data)
}
pub fn verify(game:&store::InstalledGame)->Result<(),String>{
    let parsed=read_manifest_for_game(game)?;
    let root=game.install_path.canonicalize().map_err(|e|format!("Cannot access install directory: {e}"))?;
    let mut mismatched=0usize;
    let mut correct=0usize;
    for file in &parsed.files {
        let target=safe_join(&root,&file.name)?;
        if manifest::file_sha_matches(&target,&file.sha)? {correct+=1;} else {
            mismatched+=1;
            println!("MISSING OR CHANGED: {}",file.name);
        }
    }
    println!("Full SHA-1 verification: {correct} correct, {mismatched} missing/changed files");
    if mismatched>0 {return Err("Game installation has missing or corrupted files. Use lrb repair.".into());}
    Ok(())
}

pub fn install(options:InstallOptions)->Result<(),String>{
    if !(1..=16).contains(&options.workers){return Err("--workers must be 1..16".into());}
    let plan=epic::download_plan(&options.app)?;
    if plan.manifest.launch_exe.trim().is_empty() {
        return Err("Epic game manifest does not provide a launch executable; cannot register an online-launchable game".into());
    }
    let game_exe=manifest::path_in_install(&plan.manifest.launch_exe)?;
    let root=options.dir.unwrap_or(default_path()?);
    if root.exists() && !root.is_dir(){return Err("--dir must be a directory".into());}
    if !options.dry_run {
        fs::create_dir_all(&root).map_err(|e|format!("Cannot create installation folder: {e}"))?;
    }
    // No filesystem modification while previewing. Existing files may be compared.
    let root=if root.exists(){root.canonicalize().map_err(|e|e.to_string())?} else {root};
    let mut changed=Vec::new();
    let mut skipped=0usize;
    let mut total=0u64;
    for file in &plan.manifest.files {
        let target=safe_join(&root,&file.name)?;
        if manifest::file_sha_matches(&target,&file.sha)? {skipped+=1;continue;}
        changed.push(file);
        total=total.checked_add(file.size).ok_or("Install size overflow")?;
    }
    println!("Epic game: {} (namespace {})",plan.app_name,plan.namespace);
    println!("Build: {} | destination: {}",plan.manifest.version,root.display());
    println!("Files already correct: {skipped} | files to install/update: {} | output size: {:.1} GiB",
        changed.len(),total as f64/(1024_f64.powi(3)));
    if options.dry_run {
        println!("Dry-run: no files downloaded, written, or registered.");
        return Ok(());
    }
    let state_dir=root.join(".lrb");
    fs::create_dir_all(&state_dir).map_err(|e|e.to_string())?;
    let cache=state_dir.join("chunks");
    fs::create_dir_all(&cache).map_err(|e|format!("Cannot create cache: {e}"))?;
    let mut required=HashSet::new();
    for file in &changed {for part in &file.parts {required.insert(part.guid);}}
    let chunks:Vec<_>=required.into_iter().map(|guid|plan.manifest.chunks.get(&guid).cloned().ok_or("Unknown manifest chunk")).collect::<Result<_,_>>()?;
    println!("Required unique chunks: {} | download workers: {}",chunks.len(),options.workers);
    let client=Client::builder().timeout(Duration::from_secs(45))
        .user_agent("EpicGamesLauncher/14.0.8-22004686+++Portal+Release-Live")
        .build().map_err(|e|e.to_string())?;
    let pool=rayon::ThreadPoolBuilder::new().num_threads(options.workers).build()
        .map_err(|e|e.to_string())?;
    pool.install(||chunks.par_iter().try_for_each(|chunk|download_chunk(&client,&plan.bases,&cache,chunk,&plan.secrets)))?;
    println!("Chunks downloaded and verified. Assembling game files...");
    for (i,file) in changed.iter().enumerate() {
        assemble_file(&root,&cache,file,&plan.manifest.chunks,&plan.secrets)?;
        if i%100==0 || i+1==changed.len(){println!("Completed {}/{} files",i+1,changed.len());}
    }
    // Required launch executable must exist before claiming successful installation.
    if !safe_join(&root,game_exe.to_string_lossy().as_ref())?.is_file() {
        return Err("Installation completed but Epic launch executable is missing; not registering".into());
    }
    // Save a locally verified copy for offline repair/verification.
    let manifest_tmp=state_dir.join("manifest.bin.tmp");
    fs::write(&manifest_tmp,&plan.raw_manifest).map_err(|e|e.to_string())?;
    let manifest_path=state_dir.join("manifest.bin");
    if manifest_path.exists() { fs::remove_file(&manifest_path).map_err(|e|e.to_string())?; }
    fs::rename(&manifest_tmp,&manifest_path).map_err(|e|e.to_string())?;
    // Store the parsed manifest without encryption keys so offline full
    // verification still works when Epic encrypts manifest filenames.
    use bincode::Options;
    let index=bincode::DefaultOptions::new().with_fixint_encoding()
        .serialize(&plan.manifest).map_err(|e|format!("Cannot serialize install index: {e}"))?;
    let index_tmp=state_dir.join("index.bin.tmp");
    fs::write(&index_tmp,&index).map_err(|e|format!("Cannot save install index: {e}"))?;
    let index_path=state_dir.join("index.bin");
    if index_path.exists() {fs::remove_file(&index_path).map_err(|e|e.to_string())?;}
    fs::rename(&index_tmp,&index_path).map_err(|e|e.to_string())?;
    let registered=store::InstalledGame{
        app_name:plan.app_name.clone(),title:"Rocket League".into(),install_path:root.clone(),
        executable:game_exe,namespace:plan.namespace,platform:"Windows".into(),
        deployment_id:plan.deployment_id
    };
    store::register(registered)?;
    // Cache is retained only if cleanup fails. Interrupted installs keep cache for resumes.
    if let Err(e)=fs::remove_dir_all(&cache) {
        eprintln!("Warning: completed, but chunk cache cleanup failed: {e}");
    }
    println!("Installed/updated {} build {}. Next: lrb verify --full; lrb eac install; lrb online-check",
        plan.app_name,plan.manifest.version);
    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn prevents_path_traversal_and_bad_workers(){
        let root=std::env::temp_dir();
        assert!(safe_join(&root,"../escape").is_err());
        assert!(safe_join(&root,"C:/Windows").is_err());
        let options=InstallOptions{app:"Rocket League".into(),dir:None,workers:0,dry_run:true};
        assert!(install(options).is_err()); // Before any network call.
    }
    #[test] fn download_cache_names_are_deterministic(){
        let chunk=ChunkInfo{guid:[0x12;16],secret_guid:[0;16],hash:0,sha:[0;20],size:4,url_path:"ChunksV4/test.chunk".into()};
        let path=cache_path(Path::new("cache"),&chunk);
        assert!(path.to_string_lossy().contains("12121212"));
    }
}

//! Epic BuildPatch manifests and chunk decoding (JSON and unencrypted binary).
//! Strict bounds, SHA-1 and path validation prevent installing untrusted files.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use flate2::read::ZlibDecoder;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_MANIFEST: usize = 128 * 1024 * 1024;
const MAX_CHUNK: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 250_000;
const MANIFEST_MAGIC: u32 = 0x44BEC00C;
const CHUNK_MAGIC: u32 = 0xB1FE3AA2;

type Guid = [u8; 16];

#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub guid: Guid,
    pub hash: u64,
    pub sha: [u8; 20],
    pub size: u32,
    pub url_path: String,
}
#[derive(Debug, Clone)]
pub struct Part {
    pub guid: Guid,
    pub offset: usize,
    pub size: usize,
}
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub sha: [u8; 20],
    pub parts: Vec<Part>,
    pub executable: bool,
    pub size: u64,
}
#[derive(Debug, Clone)]
pub struct Manifest {
    pub app_name: String,
    pub version: String,
    pub launch_exe: String,
    pub files: Vec<FileInfo>,
    pub chunks: HashMap<Guid, ChunkInfo>,
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let hash = Sha1::digest(data);
    hash.into()
}
pub fn hex_digest(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn path_in_install(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() || raw.contains('\0') || raw.contains(':') || raw.starts_with('/') || raw.starts_with('\\') {
        return Err(format!("Unsafe manifest file name: {raw:?}"));
    }
    let normalized = raw.replace('\\', "/");
    if normalized.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        return Err(format!("Unsafe relative manifest path: {raw:?}"));
    }
    let path = PathBuf::from(normalized);
    if !path.components().all(|component| matches!(component, Component::Normal(_))) {
        return Err(format!("Unsafe manifest path: {raw:?}"));
    }
    Ok(path)
}
fn limit_decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ZlibDecoder::new(data).take((limit as u64) + 1)
        .read_to_end(&mut out).map_err(|e| format!("Invalid zlib data: {e}"))?;
    if out.len() > limit { return Err("Decompressed payload exceeds safety limit".into()); }
    Ok(out)
}
fn guid_hex(guid: Guid) -> String {
    let n = (0..4).map(|i| u32::from_le_bytes(guid[4*i..4*i+4].try_into().unwrap()));
    n.map(|x| format!("{x:08X}")).collect()
}
fn chunk_path(version: u32, group: u8, hash: u64, guid: Guid, secret: Guid) -> String {
    let folder = if version >= 22 {"ChunksV5"} else if version >= 15 {"ChunksV4"} else if version >= 6 {"ChunksV3"} else if version >= 3 {"ChunksV2"} else {"Chunks"};
    if version >= 22 {
        let secret_part = if secret == [0;16] {"plain".into()} else {URL_SAFE_NO_PAD.encode(secret)};
        format!("{folder}/{secret_part}/{group:02}/{}_{}.chunk",
            URL_SAFE_NO_PAD.encode(hash.to_le_bytes()), URL_SAFE_NO_PAD.encode(guid))
    } else {
        format!("{folder}/{group:02}/{hash:016X}_{}.chunk", guid_hex(guid))
    }
}
fn parse_blob_number(s: &str) -> Result<u64, String> {
    if s.len() % 3 != 0 || s.len() > 24 { return Err("Invalid Epic encoded integer".into()); }
    let mut v = 0u64;
    for (i, triplet) in s.as_bytes().chunks(3).enumerate() {
        let digits = std::str::from_utf8(triplet).map_err(|e| e.to_string())?;
        let byte = digits.parse::<u16>().map_err(|e| e.to_string())?;
        if byte > 255 { return Err("Epic encoded integer byte >255".into()); }
        v |= (byte as u64) << (i * 8);
    }
    Ok(v)
}
fn json_str<'a>(obj: &'a Value, key: &str) -> Result<&'a str, String> {
    obj.get(key).and_then(Value::as_str).ok_or_else(|| format!("Manifest missing {key}"))
}
fn parse_json(data: &[u8]) -> Result<Manifest, String> {
    let value: Value = serde_json::from_slice(data).map_err(|e| format!("Invalid JSON manifest: {e}"))?;
    let version = parse_blob_number(value.get("ManifestFileVersion").and_then(Value::as_str).unwrap_or("013000000000"))? as u32;
    let cfl = value.get("ChunkFilesizeList").and_then(Value::as_object).ok_or("JSON manifest missing ChunkFilesizeList")?;
    let hashes = value.get("ChunkHashList").and_then(Value::as_object).ok_or("JSON manifest missing ChunkHashList")?;
    let shas = value.get("ChunkShaList").and_then(Value::as_object).ok_or("JSON manifest missing ChunkShaList")?;
    let groups = value.get("DataGroupList").and_then(Value::as_object).ok_or("JSON manifest missing DataGroupList")?;
    if cfl.len() > MAX_ENTRIES { return Err("Too many chunks in manifest".into()); }
    let mut chunks = HashMap::new();
    for (key, size) in cfl {
        let raw = hex::decode(key).map_err(|e| e.to_string())?;
        let guid: Guid = raw.try_into().map_err(|_| "Invalid chunk GUID length")?;
        let hash = parse_blob_number(hashes.get(key).and_then(Value::as_str).ok_or("Chunk hash missing")?)?;
        let sha_raw = hex::decode(shas.get(key).and_then(Value::as_str).ok_or("Chunk SHA missing")?).map_err(|e| e.to_string())?;
        let sha: [u8;20] = sha_raw.try_into().map_err(|_| "Invalid chunk SHA length")?;
        let group = parse_blob_number(groups.get(key).and_then(Value::as_str).ok_or("Chunk group missing")?)?;
        let size = parse_blob_number(size.as_str().ok_or("Chunk size must be string")?)?;
        if group > 255 || size > u32::MAX as u64 { return Err("Invalid chunk size/group".into()); }
        let info = ChunkInfo { guid, hash, sha, size: 1024*1024, url_path: chunk_path(version, group as u8, hash, guid, [0;16]) };
        if chunks.insert(guid,info).is_some() { return Err("Duplicate chunk GUID".into()); }
    }
    let list = value.get("FileManifestList").and_then(Value::as_array).ok_or("JSON manifest missing FileManifestList")?;
    if list.len() > MAX_ENTRIES { return Err("Too many files".into()); }
    let mut files = Vec::with_capacity(list.len());
    for f in list {
        let name = json_str(f,"Filename")?.to_string();
        path_in_install(&name)?;
        // Epic JSON manifests encode each SHA-1 byte as 3 decimal digits, not
        // a u64. Decode all 20 bytes explicitly.
        let encoded = json_str(f,"FileHash")?;
        if encoded.len() != 60 { return Err("Invalid JSON SHA-1 length".into()); }
        let mut sha=[0;20];
        for (idx, triplet) in encoded.as_bytes().chunks(3).enumerate() {
            let n=std::str::from_utf8(triplet).map_err(|e|e.to_string())?.parse::<u16>().map_err(|e|e.to_string())?;
            if n > 255 {return Err("Invalid SHA-1 byte".into());}
            sha[idx]=n as u8;
        }
        let parts_json = f.get("FileChunkParts").and_then(Value::as_array).ok_or("JSON FileChunkParts missing")?;
        let mut parts = Vec::with_capacity(parts_json.len());
        let mut file_size = 0u64;
        for p in parts_json {
            let raw=hex::decode(json_str(p,"Guid")?).map_err(|e|e.to_string())?;
            let guid: Guid=raw.try_into().map_err(|_|"Invalid part GUID length")?;
            let offset=parse_blob_number(json_str(p,"Offset")?)? as usize;
            let size=parse_blob_number(json_str(p,"Size")?)? as usize;
            let chunk=chunks.get(&guid).ok_or("File refers to an unknown chunk")?;
            if offset.checked_add(size).is_none_or(|end| end > chunk.size as usize) {return Err("Chunk part range outside decoded chunk".into());}
            file_size=file_size.checked_add(size as u64).ok_or("File size overflow")?;
            parts.push(Part{guid,offset,size});
        }
        files.push(FileInfo{name,sha,parts,size:file_size,executable:f.get("bIsUnixExecutable").and_then(Value::as_bool).unwrap_or(false)});
    }
    let mut manifest=Manifest{app_name:value.get("AppNameString").and_then(Value::as_str).unwrap_or("").into(),version:value.get("BuildVersionString").and_then(Value::as_str).unwrap_or("").into(),launch_exe:value.get("LaunchExeString").and_then(Value::as_str).unwrap_or("").into(),files,chunks};
    // JSON manifests may omit launch data for addons; don't guess a binary.
    if !manifest.launch_exe.is_empty() { path_in_install(&manifest.launch_exe)?; }
    validate(&mut manifest)?;
    Ok(manifest)
}

struct Cursor<'a> { data: &'a [u8], pos: usize }
impl<'a> Cursor<'a> {
    fn new(data: &'a [u8])->Self{Self{data,pos:0}}
    fn take(&mut self, n:usize)->Result<&'a [u8],String>{
        let end=self.pos.checked_add(n).ok_or("Manifest offset overflow")?;
        if end>self.data.len(){return Err("Truncated manifest".into());}
        let s=&self.data[self.pos..end];self.pos=end;Ok(s)
    }
    fn u8(&mut self)->Result<u8,String>{Ok(self.take(1)?[0])}
    fn u32(&mut self)->Result<u32,String>{Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))}
    fn u64(&mut self)->Result<u64,String>{Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))}
    fn i32(&mut self)->Result<i32,String>{Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))}
    fn hash(&mut self)->Result<[u8;20],String>{Ok(self.take(20)?.try_into().unwrap())}
    fn guid(&mut self)->Result<Guid,String>{Ok(self.take(16)?.try_into().unwrap())}
    fn fstr(&mut self)->Result<String,String>{
        let len=self.i32()?;
        if len==0{return Ok(String::new());}
        let chars=len.unsigned_abs() as usize;
        if chars>1_000_000{return Err("Epic string too long".into());}
        if len>0 {
            let b=self.take(chars)?;
            if b[chars-1]!=0{return Err("Epic string not NUL terminated".into());}
            std::str::from_utf8(&b[..chars-1]).map(str::to_owned).map_err(|e|e.to_string())
        } else {
            let bytes=self.take(chars.checked_mul(2).ok_or("String length overflow")?)?;
            if bytes[bytes.len()-2..]!=[0,0]{return Err("Epic UTF-16 string not NUL terminated".into());}
            let u16s=bytes[..bytes.len()-2].chunks_exact(2).map(|x|u16::from_le_bytes([x[0],x[1]]));
            String::from_utf16(&u16s.collect::<Vec<_>>()).map_err(|e|e.to_string())
        }
    }
    fn section_end(&mut self, start:usize, size:usize)->Result<(),String>{
        let end=start.checked_add(size).ok_or("Section size overflow")?;
        if end<self.pos || end>self.data.len() {return Err("Invalid Epic manifest section bounds".into());}
        self.pos=end;Ok(())
    }
    fn bounded_count(&mut self)->Result<usize,String>{
        let count=self.u32()? as usize;
        if count>MAX_ENTRIES{return Err("Epic manifest has too many entries".into());}
        Ok(count)
    }
}
fn parse_binary(data:&[u8])->Result<Manifest,String>{
    let mut outer=Cursor::new(data);
    if outer.u32()?!=MANIFEST_MAGIC{return Err("Invalid Epic manifest magic".into());}
    let head_size=outer.u32()? as usize;
    let uncompressed=outer.u32()? as usize;
    let compressed=outer.u32()? as usize;
    let expected_hash=outer.hash()?;
    let stored_as=outer.u8()?;
    let version=outer.u32()?;
    if !(41..=128).contains(&head_size) || uncompressed>MAX_MANIFEST || compressed>MAX_MANIFEST {
        return Err("Epic manifest header size out of bounds".into());
    }
    if version>=22 {outer.take(32)?;}
    if stored_as&2 !=0 {return Err("Encrypted Epic manifests are not yet supported".into());}
    if head_size<outer.pos || head_size>data.len(){return Err("Invalid Epic header length".into());}
    outer.pos=head_size;
    let raw=outer.take(data.len()-head_size)?;
    if raw.len()!=compressed {return Err("Manifest compressed body size mismatch".into());}
    let body=if stored_as&1!=0 {limit_decompress(raw,MAX_MANIFEST)?} else {raw.to_vec()};
    if body.len()!=uncompressed || sha1_bytes(&body)!=expected_hash{return Err("Manifest body size or SHA-1 mismatch".into());}
    let mut r=Cursor::new(&body);

    let meta_start=r.pos;
    let meta_size=r.u32()? as usize;
    let data_version=r.u8()?;
    let feature=r.u32()?;
    let _is_file_data=r.u8()?;
    let _app_id=r.u32()?;
    let app_name=r.fstr()?;
    let build_version=r.fstr()?;
    let launch_exe=r.fstr()?;
    let _launch_cmd=r.fstr()?;
    let pre_count=r.bounded_count()?;
    for _ in 0..pre_count {r.fstr()?;}
    for _ in 0..3 {r.fstr()?;}
    if data_version>=1 {r.fstr()?;}
    if data_version>=2 {r.fstr()?;r.fstr()?;}
    r.section_end(meta_start,meta_size)?;

    let chunk_start=r.pos;
    let chunk_section_size=r.u32()? as usize;
    let _section_version=r.u8()?;
    let count=r.bounded_count()?;
    let mut guid=Vec::with_capacity(count);
    for _ in 0..count {guid.push(r.guid()?);}
    let mut hash=Vec::with_capacity(count);
    for _ in 0..count {hash.push(r.u64()?);}
    let mut sha=Vec::with_capacity(count);
    for _ in 0..count {sha.push(r.hash()?);}
    let mut groups=Vec::with_capacity(count);
    for _ in 0..count {groups.push(r.u8()?);}
    let mut sizes=Vec::with_capacity(count);
    for _ in 0..count {sizes.push(r.u32()?);}
    for _ in 0..count {r.u64()?;} // downloaded compressed byte sizes
    let mut secrets=vec![[0;16];count];
    if feature>=22 {
        for secret in secrets.iter_mut() {*secret=r.guid()?;}
        for _ in 0..count {r.u32()?;} // compressed window size
        for _ in 0..count {r.take(16)?;} // GCM tags
    }
    r.section_end(chunk_start,chunk_section_size)?;
    let mut chunks=HashMap::with_capacity(count);
    for i in 0..count {
        if sizes[i]==0 || sizes[i] as usize>MAX_CHUNK{return Err("Unsupported chunk window size".into());}
        let item=ChunkInfo{guid:guid[i],hash:hash[i],sha:sha[i],size:sizes[i],
            url_path:chunk_path(feature,groups[i],hash[i],guid[i],secrets[i])};
        if chunks.insert(guid[i],item).is_some(){return Err("Duplicate Epic chunk GUID".into());}
    }

    let start=r.pos;
    let section_size=r.u32()? as usize;
    let file_list_version=r.u8()?;
    let count=r.bounded_count()?;
    let mut names=Vec::with_capacity(count);
    for _ in 0..count {names.push(r.fstr()?);}
    for _ in 0..count {let symlink=r.fstr()?;if !symlink.is_empty(){return Err("Symlinked install files are not supported for safety".into());}}
    let mut shas=Vec::with_capacity(count);
    for _ in 0..count {shas.push(r.hash()?);}
    let mut flags=Vec::with_capacity(count);
    for _ in 0..count {flags.push(r.u8()?);}
    for _ in 0..count {let tags=r.bounded_count()?;for _ in 0..tags {r.fstr()?;}}
    let mut files=Vec::with_capacity(count);
    for idx in 0..count {
        let pcount=r.bounded_count()?;
        let mut parts=Vec::with_capacity(pcount);
        let mut file_size=0_u64;
        for _ in 0..pcount {
            let begin=r.pos;
            let part_size=r.u32()? as usize;
            if part_size<28{return Err("Epic chunk part too small".into());}
            let guid=r.guid()?;
            let offset=r.u32()? as usize;
            let size=r.u32()? as usize;
            let chunk=chunks.get(&guid).ok_or("File references unknown chunk GUID")?;
            if offset.checked_add(size).is_none_or(|end|end>chunk.size as usize){return Err("Chunk part outside uncompressed window".into());}
            file_size=file_size.checked_add(size as u64).ok_or("File size overflow")?;
            r.section_end(begin,part_size)?;
            parts.push(Part{guid,offset,size});
        }
        path_in_install(&names[idx])?;
        files.push(FileInfo{name:names[idx].clone(),sha:shas[idx],parts,size:file_size,executable:flags[idx]&4!=0});
    }
    if file_list_version>=1 {
        for _ in 0..count {if r.u32()?!=0 {r.take(16)?;}}
        for _ in 0..count {r.fstr()?;}
    }
    if file_list_version>=2 {for _ in 0..count {r.take(32)?;}}
    r.section_end(start,section_size)?;
    let mut result=Manifest{app_name,version:build_version,launch_exe,files,chunks};
    if !result.launch_exe.is_empty(){path_in_install(&result.launch_exe)?;}
    validate(&mut result)?;
    Ok(result)
}

fn validate(manifest:&mut Manifest)->Result<(),String>{
    let mut names=std::collections::HashSet::new();
    for f in &manifest.files {
        let clean=path_in_install(&f.name)?;
        // Rocket League targets Windows: avoid case collisions.
        if !names.insert(clean.to_string_lossy().to_lowercase()) {return Err("Duplicate case-insensitive Epic file path".into());}
        let computed=f.parts.iter().map(|p|p.size as u64).sum::<u64>();
        if computed!=f.size{return Err("File part sizes do not match".into());}
    }
    if manifest.files.is_empty(){return Err("Manifest contains no installable files".into());}
    Ok(())
}
pub fn parse(data:&[u8])->Result<Manifest,String>{
    if data.len()>MAX_MANIFEST {return Err("Manifest larger than safety limit".into());}
    if data.first()==Some(&b'{'){parse_json(data)} else {parse_binary(data)}
}

/// Decode a BuildPatch chunk and check its GUID, SHA-1 and size.
pub fn decode_chunk(data:&[u8], expected:&ChunkInfo)->Result<Vec<u8>,String>{
    if data.len()>MAX_CHUNK+512{return Err("Chunk exceeds size limit".into());}
    let mut r=Cursor::new(data);
    if r.u32()?!=CHUNK_MAGIC{return Err("Invalid Epic chunk magic".into());}
    let version=r.u32()?;
    let header=r.u32()? as usize;
    let compressed_len=r.u32()? as usize;
    let guid=r.guid()?;
    let _rolling_hash=r.u64()?;
    let stored=r.u8()?;
    let mut sha=None;
    let mut hash_type=0;
    if version>=2 {sha=Some(r.hash()?);hash_type=r.u8()?;}
    let uncompressed_len=if version>=3 {r.u32()? as usize}else{expected.size as usize};
    if version>=4 {r.take(32)?;} // Secret GUID / GCM tag, if present.
    if stored&2!=0 {return Err("Encrypted Epic chunks are not yet supported".into());}
    if guid!=expected.guid || header!=r.pos || compressed_len!=data.len().saturating_sub(header){
        return Err("Chunk GUID/header/payload size mismatch".into());
    }
    if uncompressed_len!=expected.size as usize || uncompressed_len>MAX_CHUNK{
        return Err("Chunk uncompressed size mismatch".into());
    }
    let raw=&data[header..];
    let decoded=if stored&1!=0 {limit_decompress(raw,MAX_CHUNK)?} else {raw.to_vec()};
    if decoded.len()!=uncompressed_len{return Err("Chunk decoded size mismatch".into());}
    let digest=sha1_bytes(&decoded);
    if hash_type&2 !=0 && sha.is_some_and(|h|h!=digest) {
        return Err("Internal Epic chunk SHA-1 mismatch".into());
    }
    if expected.sha!=[0;20] && expected.sha!=digest{return Err("Chunk SHA-1 mismatch against manifest".into());}
    Ok(decoded)
}

pub fn file_sha_matches(path:&Path,expected:&[u8;20])->Result<bool,String>{
    let file=match std::fs::File::open(path){
        Ok(file)=>file,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(false),
        Err(e)=>return Err(format!("Cannot read {}: {e}",path.display())),
    };
    let mut hash=Sha1::new();
    let mut reader=std::io::BufReader::new(file);
    let mut buf=[0u8;128*1024];
    loop {let n=reader.read(&mut buf).map_err(|e|e.to_string())?;if n==0 {break;}hash.update(&buf[..n]);}
    let value:[u8;20]=hash.finalize().into();
    Ok(&value==expected)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn unsafe_paths_rejected(){
        for path in ["../evil","/abs","C:/drive","a//b","a/./b","a/../b","a\\..\\b"] {assert!(path_in_install(path).is_err(),"{path}");}
        assert!(path_in_install("Binaries\\Win64\\RocketLeague.exe").is_ok());
    }
    #[test] fn blob_numeric_encoding(){
        assert_eq!(parse_blob_number("001002000000").unwrap(),513);
        assert!(parse_blob_number("999").is_err());
    }
    #[test] fn guid_path_is_stable(){
        let path=chunk_path(18,1,0x1234,[1;16],[0;16]);
        assert!(path.starts_with("ChunksV4/01/0000000000001234_"));
    }
    #[test] fn invalid_chunk_rejected(){
        let info=ChunkInfo{guid:[0;16],hash:0,sha:[0;20],size:1024,url_path:"x".into()};
        assert!(decode_chunk(b"random",&info).is_err());
    }
}

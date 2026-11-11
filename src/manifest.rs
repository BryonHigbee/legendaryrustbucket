//! Epic BuildPatch manifests and chunks: JSON, binary, zlib and AES-GCM.
//! Strict bounds, SHA-1 and path validation prevent installing untrusted files.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use flate2::read::ZlibDecoder;
use aes_gcm::{Aes256Gcm, Nonce, Tag, aead::{AeadInPlace, KeyInit}};
use serde::{Serialize, Deserialize};
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
pub type Secrets = HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub guid: Guid,
    pub secret_guid: Guid,
    pub hash: u64,
    pub sha: [u8; 20],
    pub size: u32,
    pub url_path: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Part {
    pub guid: Guid,
    pub offset: usize,
    pub size: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub sha: [u8; 20],
    pub parts: Vec<Part>,
    pub executable: bool,
    pub size: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn decrypt_gcm(data:&[u8],nonce:&[u8],tag:&[u8],secret_guid:Guid,secrets:&Secrets)->Result<Vec<u8>,String>{
    if nonce.len()!=12 || tag.len()!=16{return Err("Invalid Epic AES-GCM IV or authentication tag length".into());}
    let name=guid_hex(secret_guid);
    let secret=secrets.get(&name).ok_or_else(||format!("Encrypted Epic content requires missing key {name}"))?;
    let key=hex::decode(secret).map_err(|_|"Invalid Epic manifest AES key encoding")?;
    if key.len()!=32{return Err("Unsupported Epic AES-GCM key length (expected AES-256)".into());}
    let cipher=Aes256Gcm::new_from_slice(&key).map_err(|_|"Invalid Epic AES-GCM key")?;
    let mut plaintext=data.to_vec();
    cipher.decrypt_in_place_detached(Nonce::from_slice(nonce),b"",&mut plaintext,Tag::from_slice(tag))
        .map_err(|_|"Epic AES-GCM authentication failed")?;
    Ok(plaintext)
}
fn guid_hex(guid: Guid) -> String {
    let n = (0..4).map(|i| u32::from_le_bytes(guid[4*i..4*i+4].try_into().unwrap()));
    n.map(|x| format!("{x:08X}")).collect()
}
fn json_guid(hex_str: &str) -> Result<Guid, String> {
    let raw=hex::decode(hex_str).map_err(|e|e.to_string())?;
    let mut guid: Guid=raw.try_into().map_err(|_| "Invalid JSON chunk GUID length")?;
    // JSON GUIDs are big-endian 32-bit groups; binary chunks store little-endian
    // groups. Normalize so the two manifest formats reference the same identity.
    for group in guid.chunks_exact_mut(4) {group.reverse();}
    Ok(guid)
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
        let guid=json_guid(key)?;
        let hash = parse_blob_number(hashes.get(key).and_then(Value::as_str).ok_or("Chunk hash missing")?)?;
        let sha_raw = hex::decode(shas.get(key).and_then(Value::as_str).ok_or("Chunk SHA missing")?).map_err(|e| e.to_string())?;
        let sha: [u8;20] = sha_raw.try_into().map_err(|_| "Invalid chunk SHA length")?;
        let group = parse_blob_number(groups.get(key).and_then(Value::as_str).ok_or("Chunk group missing")?)?;
        let size = parse_blob_number(size.as_str().ok_or("Chunk size must be string")?)?;
        if group > 255 || size > u32::MAX as u64 { return Err("Invalid chunk size/group".into()); }
        let info = ChunkInfo { guid, secret_guid: [0;16], hash, sha, size: 1024*1024, url_path: chunk_path(version, group as u8, hash, guid, [0;16]) };
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
            let guid=json_guid(json_str(p,"Guid")?)?;
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
fn parse_binary(data:&[u8], secrets:&Secrets)->Result<Manifest,String>{
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
    let mut outer_secret=[0;16];
    let mut outer_tag=[0;16];
    if version>=22 {outer_secret=outer.guid()?;outer_tag=outer.take(16)?.try_into().unwrap();}
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
    let mut launch_exe=r.fstr()?;
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
    let mut chunk_secret_guids=vec![[0;16];count];
    if feature>=22 {
        for secret in chunk_secret_guids.iter_mut() {*secret=r.guid()?;}
        for _ in 0..count {r.u32()?;} // compressed window size
        for _ in 0..count {r.take(16)?;} // GCM tags
    }
    r.section_end(chunk_start,chunk_section_size)?;
    let mut chunks=HashMap::with_capacity(count);
    for i in 0..count {
        if sizes[i]==0 || sizes[i] as usize>MAX_CHUNK{return Err("Unsupported chunk window size".into());}
        let item=ChunkInfo{guid:guid[i],secret_guid:chunk_secret_guids[i],hash:hash[i],sha:sha[i],size:sizes[i],
            url_path:chunk_path(feature,groups[i],hash[i],guid[i],chunk_secret_guids[i])};
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
        files.push(FileInfo{name:names[idx].clone(),sha:shas[idx],parts,size:file_size,executable:flags[idx]&4!=0});
    }
    if file_list_version>=1 {
        for _ in 0..count {if r.u32()?!=0 {r.take(16)?;}}
        for _ in 0..count {r.fstr()?;}
    }
    if file_list_version>=2 {for _ in 0..count {r.take(32)?;}}
    r.section_end(start,section_size)?;

    // Custom fields always follow the file manifest list.
    let cf_start=r.pos;
    let cf_size=r.u32()? as usize;
    let _cf_version=r.u8()?;
    let cf_count=r.bounded_count()?;
    for _ in 0..cf_count {r.fstr()?;}
    for _ in 0..cf_count {r.fstr()?;}
    r.section_end(cf_start,cf_size)?;

    if stored_as&2!=0 {
        if version<24 || feature<24 {
            return Err("Unsupported encrypted Epic manifest version".into());
        }
        let ed_start=r.pos;
        let ed_size=r.u32()? as usize;
        let _ed_version=r.u8()?;
        let cipher_section_size=r.u32()? as usize;
        let cipher_start=r.pos-4;
        let encrypted_header_start=r.pos;
        let header_size=r.u32()? as usize;
        let _header_version=r.u32()?;
        let encrypted_flags=r.u8()?;
        let uncompressed_size=r.u32()? as usize;
        let _compressed_size=r.u32()?;
        let iv_len=r.u32()? as usize;
        if iv_len>64 {return Err("Invalid Epic encrypted metadata nonce length".into());}
        let iv=r.take(iv_len)?.to_vec();
        r.section_end(encrypted_header_start,header_size)?;
        let ciphertext_size=r.u32()? as usize;
        if ciphertext_size>MAX_MANIFEST{return Err("Epic encrypted metadata exceeds size limit".into());}
        let ciphertext=r.take(ciphertext_size)?;
        let plaintext=decrypt_gcm(ciphertext,&iv,&outer_tag,outer_secret,secrets)?;
        r.section_end(cipher_start,cipher_section_size)?;
        r.section_end(ed_start,ed_size)?;
        let plaintext=if encrypted_flags&1!=0 {
            let expanded=limit_decompress(&plaintext,MAX_MANIFEST)?;
            if expanded.len()!=uncompressed_size {return Err("Epic decrypted metadata size mismatch".into());}
            expanded
        } else {
            if plaintext.len()!=uncompressed_size {return Err("Epic decrypted metadata size mismatch".into());}
            plaintext
        };
        let mut private=Cursor::new(&plaintext);
        launch_exe=private.fstr()?;
        let _launch_command=private.fstr()?;
        let count=private.bounded_count()?;
        for _ in 0..count {private.fstr()?;}
        for _ in 0..5 {private.fstr()?;}
        for file in &mut files {
            file.name=private.fstr()?;
            let symlink=private.fstr()?;
            if !symlink.is_empty(){return Err("Epic symlink targets are unsupported".into());}
        }
        // Future Epic versions may add optional trailing encrypted metadata.
    }
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
pub fn parse_with_secrets(data:&[u8],secrets:&Secrets)->Result<Manifest,String>{
    if data.len()>MAX_MANIFEST {return Err("Manifest larger than safety limit".into());}
    if data.first()==Some(&b'{'){parse_json(data)} else {parse_binary(data,secrets)}
}
pub fn parse(data:&[u8])->Result<Manifest,String>{parse_with_secrets(data,&Secrets::new())}

/// Decode a BuildPatch chunk and check its GUID, SHA-1 and size.
pub fn decode_chunk_with_secrets(data:&[u8], expected:&ChunkInfo,secrets:&Secrets)->Result<Vec<u8>,String>{
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
    let (chunk_secret,tag)=if version>=4 {(r.guid()?,r.take(16)?.to_vec())} else {([0;16],Vec::new())};
    if version>=4 && chunk_secret!=expected.secret_guid{return Err("Chunk encryption GUID differs from Epic manifest".into());}
    if guid!=expected.guid || header!=r.pos || compressed_len!=data.len().saturating_sub(header){
        return Err("Chunk GUID/header/payload size mismatch".into());
    }
    if uncompressed_len!=expected.size as usize || uncompressed_len>MAX_CHUNK{
        return Err("Chunk uncompressed size mismatch".into());
    }
    let raw=&data[header..];
    let raw=if stored&2!=0 {
        let sha=sha.ok_or("Encrypted chunk header missing nonce SHA")?;
        decrypt_gcm(raw,&sha[..12],&tag,chunk_secret,secrets)?
    }else{raw.to_vec()};
    let decoded=if stored&1!=0 {limit_decompress(&raw,MAX_CHUNK)?} else {raw};
    if decoded.len()!=uncompressed_len{return Err("Chunk decoded size mismatch".into());}
    let digest=sha1_bytes(&decoded);
    if hash_type&2 !=0 && sha.is_some_and(|h|h!=digest) {
        return Err("Internal Epic chunk SHA-1 mismatch".into());
    }
    if expected.sha!=[0;20] && expected.sha!=digest{return Err("Chunk SHA-1 mismatch against manifest".into());}
    Ok(decoded)
}

pub fn decode_chunk(data:&[u8],expected:&ChunkInfo)->Result<Vec<u8>,String>{
    decode_chunk_with_secrets(data,expected,&Secrets::new())
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

    #[test]
    fn json_guids_are_normalized_to_binary_chunk_order() {
        let guid=json_guid("00000001000000020000000300000004").unwrap();
        assert_eq!(guid,[1,0,0,0,2,0,0,0,3,0,0,0,4,0,0,0]);
        assert!(guid_hex(guid).ends_with("00000001000000020000000300000004"));
    }

    #[test]
    fn synthetic_chunk_is_reconstructed_and_authenticated() {
        let bytes=b"GAME";
        let guid=[7u8;16];
        let digest=sha1_bytes(bytes);
        let mut raw=Vec::new();
        raw.extend_from_slice(&CHUNK_MAGIC.to_le_bytes());
        raw.extend_from_slice(&3u32.to_le_bytes());
        raw.extend_from_slice(&66u32.to_le_bytes());
        raw.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        raw.extend_from_slice(&guid);
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&digest);
        raw.push(2);
        raw.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        raw.extend_from_slice(bytes);
        let chunk=ChunkInfo{guid,secret_guid:[0;16],hash:0,sha:digest,size:4,url_path:"test.chunk".into()};
        assert_eq!(decode_chunk(&raw,&chunk).unwrap(),bytes);
        *raw.last_mut().unwrap()=b'X';
        assert!(decode_chunk(&raw,&chunk).is_err());
    }

    #[test]
    fn synthetic_json_manifest_maps_parts_to_chunks() {
        let key="00000001000000020000000300000004";
        let content=b"GAME";
        let sha_bytes=sha1_bytes(content);
        let sha_encoded=sha_bytes.iter().map(|byte|format!("{byte:03}")).collect::<String>();
        let mut a=serde_json::Map::new();
        let mut b=serde_json::Map::new();
        let mut c=serde_json::Map::new();
        let mut d=serde_json::Map::new();
        a.insert(key.into(),serde_json::json!("004000000000"));
        b.insert(key.into(),serde_json::json!("001000000000000000000000"));
        c.insert(key.into(),serde_json::json!(hex::encode(sha_bytes)));
        d.insert(key.into(),serde_json::json!("001"));
        let manifest=serde_json::json!({
            "ManifestFileVersion":"018000000000",
            "AppNameString":"Sugar","BuildVersionString":"unit-test",
            "LaunchExeString":"Binaries/Win64/RocketLeague.exe",
            "ChunkFilesizeList":a,"ChunkHashList":b,
            "ChunkShaList":c,"DataGroupList":d,
            "FileManifestList":[{
                "Filename":"Game.bin","FileHash":sha_encoded,
                "FileChunkParts":[{"Guid":key,"Offset":"000","Size":"004"}]
            }]
        }).to_string();
        let parsed=parse(manifest.as_bytes()).unwrap();
        assert_eq!(parsed.files.len(),1);
        assert_eq!(parsed.files[0].size,4);
        assert_eq!(parsed.files[0].parts[0].guid,json_guid(key).unwrap());
        assert!(parsed.chunks.contains_key(&json_guid(key).unwrap()));
    }

    #[test]
    fn decrypts_authenticated_aes_256_gcm_epic_chunk() {
        let payload=b"GAME";
        let digest=sha1_bytes(payload);
        let guid=[7u8;16];
        let secret_guid=[9u8;16];
        let key=[8u8;32];
        let mut ciphertext=payload.to_vec();
        let cipher=Aes256Gcm::new_from_slice(&key).unwrap();
        let tag=cipher.encrypt_in_place_detached(Nonce::from_slice(&digest[..12]),b"",&mut ciphertext).unwrap();
        let mut chunk=Vec::new();
        chunk.extend_from_slice(&CHUNK_MAGIC.to_le_bytes());
        chunk.extend_from_slice(&4u32.to_le_bytes());
        chunk.extend_from_slice(&98u32.to_le_bytes());
        chunk.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&guid);
        chunk.extend_from_slice(&0u64.to_le_bytes());
        chunk.push(2);
        chunk.extend_from_slice(&digest);
        chunk.push(2);
        chunk.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&secret_guid);
        chunk.extend_from_slice(&tag);
        chunk.extend_from_slice(&ciphertext);
        let expected=ChunkInfo{guid,secret_guid,hash:0,sha:digest,size:4,url_path:"test.chunk".into()};
        let mut secrets=Secrets::new();
        secrets.insert(guid_hex(secret_guid),hex::encode(key));
        assert_eq!(decode_chunk_with_secrets(&chunk,&expected,&secrets).unwrap(),payload);
        *chunk.last_mut().unwrap()^=1;
        assert!(decode_chunk_with_secrets(&chunk,&expected,&secrets).is_err());
    }

    fn fstring(buf:&mut Vec<u8>,s:&str) {
        if s.is_empty() {buf.extend_from_slice(&0u32.to_le_bytes());return;}
        buf.extend_from_slice(&((s.len()+1) as u32).to_le_bytes());
        buf.extend_from_slice(s.as_bytes());buf.push(0);
    }
    fn finish_section(buf:&mut [u8]) {let len=buf.len() as u32;buf[..4].copy_from_slice(&len.to_le_bytes());}
    fn meta(feature:u32,encrypted:bool)->Vec<u8>{
        let mut section=vec![0u8;4];
        section.push(0);
        section.extend_from_slice(&feature.to_le_bytes());
        section.push(0);
        section.extend_from_slice(&0u32.to_le_bytes());
        fstring(&mut section,"Sugar");
        fstring(&mut section,"unit-test");
        fstring(&mut section,if encrypted {""} else {"Binaries/Win64/RocketLeague.exe"});
        fstring(&mut section,"");
        section.extend_from_slice(&0u32.to_le_bytes());
        for _ in 0..3 {fstring(&mut section,"");}
        finish_section(&mut section);
        section
    }
    fn file_list(encrypted:bool)->Vec<u8>{
        let mut section=vec![0u8;4];
        section.push(0);
        section.extend_from_slice(&1u32.to_le_bytes());
        fstring(&mut section,if encrypted {""} else {"Binaries/Win64/RocketLeague.exe"});
        fstring(&mut section,"");
        section.extend_from_slice(&sha1_bytes(&[]));
        section.push(0);
        section.extend_from_slice(&0u32.to_le_bytes());
        section.extend_from_slice(&0u32.to_le_bytes());
        finish_section(&mut section);
        section
    }
    fn manifest_bytes(body:&[u8],feature:u32,encrypted:bool,secret:Guid,tag:&[u8;16])->Vec<u8>{
        let mut bytes=Vec::new();
        bytes.extend_from_slice(&MANIFEST_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&(if encrypted {73u32} else {41u32}).to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&sha1_bytes(body));
        bytes.push(if encrypted {2} else {0});
        bytes.extend_from_slice(&feature.to_le_bytes());
        if encrypted{bytes.extend_from_slice(&secret);bytes.extend_from_slice(tag);}
        bytes.extend_from_slice(body);
        bytes
    }
    fn custom_fields_empty()->Vec<u8>{
        let mut section=vec![0u8;4];section.push(0);
        section.extend_from_slice(&0u32.to_le_bytes());
        finish_section(&mut section);section
    }
    #[test]
    fn binary_manifest_parser_reads_unencrypted_game_metadata(){
        let mut body=meta(18,false);
        let mut chunks=vec![0u8;4];chunks.push(0);chunks.extend_from_slice(&0u32.to_le_bytes());
        finish_section(&mut chunks);
        body.extend_from_slice(&chunks);
        body.extend_from_slice(&file_list(false));
        body.extend_from_slice(&custom_fields_empty());
        let raw=manifest_bytes(&body,18,false,[0;16],&[0;16]);
        let parsed=parse(&raw).unwrap();
        assert_eq!(parsed.app_name,"Sugar");
        assert_eq!(parsed.files[0].name,"Binaries/Win64/RocketLeague.exe");
    }
    #[test]
    fn encrypted_binary_manifest_metadata_roundtrip(){
        let key=[6u8;32];let nonce=[8u8;12];let secret=[1u8;16];
        let mut plaintext=Vec::new();
        fstring(&mut plaintext,"Binaries/Win64/RocketLeague.exe");
        fstring(&mut plaintext,"");
        plaintext.extend_from_slice(&0u32.to_le_bytes());
        for _ in 0..5{fstring(&mut plaintext,"");}
        fstring(&mut plaintext,"Binaries/Win64/RocketLeague.exe");
        fstring(&mut plaintext,"");
        let mut ciphertext=plaintext.clone();
        let cipher=Aes256Gcm::new_from_slice(&key).unwrap();
        let tag=cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce),b"",&mut ciphertext).unwrap();
        let mut body=meta(24,true);
        let mut chunks=vec![0u8;4];chunks.push(0);chunks.extend_from_slice(&0u32.to_le_bytes());
        finish_section(&mut chunks);
        body.extend_from_slice(&chunks);
        body.extend_from_slice(&file_list(true));
        body.extend_from_slice(&custom_fields_empty());

        let mut encrypted=vec![0u8;4];
        encrypted.push(0);
        let cipher_start=encrypted.len();
        encrypted.extend_from_slice(&0u32.to_le_bytes());
        let header_start=encrypted.len();
        encrypted.extend_from_slice(&0u32.to_le_bytes());
        encrypted.extend_from_slice(&0u32.to_le_bytes());
        encrypted.push(0);
        encrypted.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        encrypted.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        encrypted.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
        encrypted.extend_from_slice(&nonce);
        let header_len=(encrypted.len()-header_start) as u32;
        encrypted[header_start..header_start+4].copy_from_slice(&header_len.to_le_bytes());
        encrypted.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        encrypted.extend_from_slice(&ciphertext);
        let cipher_len=(encrypted.len()-cipher_start) as u32;
        encrypted[cipher_start..cipher_start+4].copy_from_slice(&cipher_len.to_le_bytes());
        finish_section(&mut encrypted);
        body.extend_from_slice(&encrypted);
        let raw=manifest_bytes(&body,24,true,secret,tag.as_slice().try_into().unwrap());
        let mut secrets=Secrets::new();secrets.insert(guid_hex(secret),hex::encode(key));
        let parsed=parse_with_secrets(&raw,&secrets).unwrap();
        assert_eq!(parsed.launch_exe,"Binaries/Win64/RocketLeague.exe");
        assert_eq!(parsed.files[0].name,"Binaries/Win64/RocketLeague.exe");
        assert!(parse(&raw).is_err());
    }
    #[test] fn invalid_chunk_rejected(){
        let info=ChunkInfo{guid:[0;16],secret_guid:[0;16],hash:0,sha:[0;20],size:1024,url_path:"x".into()};
        assert!(decode_chunk(b"random",&info).is_err());
    }
}

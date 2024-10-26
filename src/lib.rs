//! Fugue import/export glue for Radare and Rizin.
//!
//! Example use:
//! ```rust,ignore
//! use fugue::db::DatabaseImporter;
//! use fugue::ir::LanguageDB;
//!
//! let ldb = LanguageDB::from_directory_with("path/to/processors", true)?;
//! let mut dbi = DatabaseImporter::new("/bin/ls");
//!
//! dbi.register_backend(Radare::new_rizin()?);
//!
//! let db = dbi.import(&ldb)?;
//! ```

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use fugue_db::backend::{Backend, Imported};
use fugue_db::Error as ExportError;
use iset::IntervalSet;
use itertools::Itertools;
use r2pipe::R2Pipe;
pub use r2pipe::R2PipeSpawnOptions;
use serde::Deserialize;
use thiserror::Error;
use url::Url;
use which::{which, which_in};

mod schema;

#[derive(Debug, Error)]
pub enum Error {
    #[error("r2/rizin is not available as a backend")]
    NotAvailable,
    #[error("invalid path to r2/rizin: {0}")]
    InvalidPath(which::Error),
    #[error("invalid import URL: {0}")]
    InvalidImportPath(String),
    #[error("invalid shared memory mapping: {0}")]
    InvalidImportShm(shared_memory::ShmemError),
    #[error("invalid file-system path: {0}")]
    InvalidImportFile(std::io::Error),
    #[error("coult not export to file: {0}")]
    CannotExportToFile(std::io::Error),
    #[error("coult not map file: {0}")]
    CannotMapFile(std::io::Error),
    #[error("could not deserialise output from `{0}`: {1}")]
    Deserialise(&'static str, #[source] serde_json::Error),
    #[error("pipe communication error: {0}")]
    Pipe(#[from] r2pipe::Error),
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
}

impl From<Error> for ExportError {
    fn from(e: Error) -> Self {
        ExportError::importer_error("fugue-radare", e)
    }
}

#[derive(Debug, Deserialize)]
struct MetadataBin<'d> {
    arch: &'d str,
    bintype: &'d str,
    bits: u32,
    endian: &'d str,
}

#[derive(Debug, Deserialize)]
struct MetadataCore<'d> {
    file: &'d str,
    #[allow(unused)]
    size: u32,
}

#[derive(Debug, Deserialize)]
struct MetadataHashes<'d> {
    #[allow(unused)]
    md5: &'d str,
    #[allow(unused)]
    sha1: &'d str,
    #[allow(unused)]
    sha256: &'d str,
}

#[derive(Debug, Deserialize)]
struct Metadata<'d> {
    #[serde(borrow)]
    core: MetadataCore<'d>,
    #[serde(borrow)]
    bin: MetadataBin<'d>,
}

impl<'d> Metadata<'d> {
    fn format(format: &str) -> Result<&'static str, Error> {
        Ok(match format {
            "elf" | "elf64" => "ELF",
            "mach0" | "mach064" => "Mach-O",
            "pe" | "pe64" => "PE",
            "te" => "TE",
            "any" => "Raw",
            _ => return Err(Error::UnsupportedFormat(format.to_string())),
        })
    }

    fn processor(processor: &str, bits: u32) -> Result<(&'static str, &'static str), Error> {
        Ok(match processor {
            "arm" => {
                if bits == 64 {
                    ("AARCH64", "v8A")
                } else {
                    ("ARM", "v7")
                }
            }
            "mips" => ("MIPS", "default"),
            "ppc" => ("PowerPC", "default"),
            "x86" => ("x86", "default"), // TODO: handle 16-bit variants
            _ => return Err(Error::UnsupportedArch(processor.to_string())),
        })
    }

    fn endian(endian: &str) -> bool {
        endian != "little" && endian != "LE"
    }
}

#[derive(Debug, Deserialize)]
struct Version<'d> {
    name: &'d str,
    version: &'d str,
}

#[derive(Debug, Deserialize)]
struct SegmentInfo<'d> {
    name: &'d str,
    size: u32,
    vsize: u32,
    perm: &'d str,
    #[serde(default)]
    paddr: u64,
    vaddr: i128,
}

impl<'d> SegmentInfo<'d> {
    fn is_executable(&self) -> bool {
        self.perm.contains("x")
    }

    fn is_readable(&self) -> bool {
        self.perm.contains("r")
    }

    fn is_writable(&self) -> bool {
        self.perm.contains("w")
    }

    fn address(&self) -> Option<u64> {
        if self.vaddr < 0 || self.vaddr > u64::MAX as i128 {
            None
        } else {
            Some(self.vaddr as u64)
        }
    }

    fn is_code(&self) -> bool {
        self.is_executable()
    }

    fn is_data(&self) -> bool {
        !self.is_code()
    }
}

#[derive(Debug, Deserialize)]
struct Symbol<'d> {
    realname: &'d str, // imported should match name of relocation?
    #[serde(rename = "type")]
    kind: &'d str,
    #[serde(default)]
    vaddr: u64,
    #[serde(default)]
    #[allow(unused)]
    paddr: u64,
    is_imported: bool,
}

#[derive(Debug, Deserialize)]
struct Relocation<'d> {
    name: Option<&'d str>,
    vaddr: u64,
}

#[derive(Debug, Deserialize)]
struct InterRef<'d> {
    from: u64, // source
    #[serde(rename = "type")]
    kind: &'d str, // we care about "CALL"
    fcn_addr: Option<u64>, // source fcn
}

#[derive(Debug, Default, Deserialize)]
struct BasicBlock {
    addr: u64,
    size: u32,
    jump: Option<u64>,
    fail: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct Function<'d> {
    offset: u64,
    name: &'d str, // source fcn
}

pub enum Backing {
    M(File, memmap::Mmap),
    S(shared_memory::Shmem),
}

impl Deref for Backing {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::M(_, ref m) => m.deref(),
            Self::S(ref s) => unsafe { s.as_slice() },
        }
    }
}

pub struct RadareExporter<'db> {
    config: R2PipeSpawnOptions,

    builder: flatbuffers::FlatBufferBuilder<'db>,
    pipe: R2Pipe,

    backing: Backing,

    endian: bool, // little = false; big = true
    address_size: u32,
    bits: u32,
}

impl<'db> RadareExporter<'db> {
    pub fn new_with<P: AsRef<str>>(path: P, mut config: R2PipeSpawnOptions) -> Result<Self, Error> {
        if config.exepath.is_empty() {
            config.exepath.push_str("r2");
        }

        let path = path.as_ref();

        let backing = if let Some(id) = path
            .strip_prefix("shm:/")
            .and_then(|rest| rest.rsplit_once("/").map(|(v, _)| v))
        {
            let sc = shared_memory::ShmemConf::new().os_id(id);
            Backing::S(sc.open().map_err(Error::InvalidImportShm)?)
        } else {
            let path = path.strip_prefix("file://").unwrap_or(&path);
            let file = File::open(path).map_err(Error::InvalidImportFile)?;

            let mm = unsafe { memmap::Mmap::map(&file) }.map_err(Error::CannotMapFile)?;

            Backing::M(file, mm)
        };

        Ok(Self {
            builder: flatbuffers::FlatBufferBuilder::new(),
            pipe: R2Pipe::spawn(path, Some(config.clone()))?,
            config,
            backing,
            endian: Default::default(),
            address_size: Default::default(),
            bits: Default::default(),
        })
    }

    pub fn new<P: AsRef<str>>(path: P) -> Result<Self, Error> {
        Self::new_with(path, Default::default())
    }

    pub fn analyse_with<S: AsRef<str>>(&mut self, command: S) -> Result<(), Error> {
        self.pipe
            .cmd(command.as_ref())
            .map(|_| ())
            .map_err(Error::Pipe)
    }

    pub fn analyse(&mut self) -> Result<(), Error> {
        self.analyse_with("aaaa")
    }

    fn export_project(&mut self) -> Result<flatbuffers::WIPOffset<schema::Project<'db>>, Error> {
        let (arch, meta) = self.export_metadata()?;
        let avec = self.builder.create_vector_from_iter(std::iter::once(arch));

        let (segs, seg_ivt) = self.export_segments()?;
        let svec = self.builder.create_vector_from_iter(segs.into_iter());

        let fcns = self.export_functions(&seg_ivt)?;
        let fvec = self.builder.create_vector_from_iter(fcns.into_iter());

        let mut dbuilder = schema::ProjectBuilder::new(&mut self.builder);

        dbuilder.add_architectures(avec);
        dbuilder.add_segments(svec);
        dbuilder.add_functions(fvec);
        dbuilder.add_metadata(meta);

        Ok(dbuilder.finish())
    }

    fn export_version(&mut self) -> Result<String, Error> {
        // NOTE: no json output for rizin...
        let vers = if self.config.exepath.ends_with("rizin")
            || self.config.exepath.ends_with("rizin.exe")
        {
            self.pipe.cmd(&format!("!{} -v", self.config.exepath))?
        } else {
            let value3 = self.pipe.cmd(&format!("!{} -vj", self.config.exepath))?;
            let version = serde_json::from_str::<Version>(&value3)
                .map_err(|e| Error::Deserialise("!r2 -vj", e))?;
            format!("{} {}", version.name, version.version)
        };

        Ok(vers)
    }

    fn export_metadata(
        &mut self,
    ) -> Result<
        (
            flatbuffers::WIPOffset<schema::Architecture<'db>>,
            flatbuffers::WIPOffset<schema::Metadata<'db>>,
        ),
        Error,
    > {
        let value1 = self.pipe.cmd("ij")?;
        let corebin =
            serde_json::from_str::<Metadata>(&value1).map_err(|e| Error::Deserialise("ij", e))?;

        let md5 = md5::compute(&*self.backing);
        let sha256 = <sha2::Sha256 as sha2::Digest>::digest(&*self.backing);

        let mut exporter = self
            .export_version()
            .unwrap_or_else(|_| "radare (unknown version)".to_string());

        if exporter.is_empty() {
            exporter = Path::new(&self.config.exepath)
                .file_name()
                .and_then(|path| path.to_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| self.config.exepath.clone());
        }

        let (def_arch_processor, def_arch_variant) =
            Metadata::processor(&corebin.bin.arch, corebin.bin.bits)?;
        let endian = Metadata::endian(&corebin.bin.endian);

        self.endian = endian;
        self.bits = corebin.bin.bits;
        self.address_size = corebin.bin.bits;

        let processor = self.builder.create_string(def_arch_processor);
        let variant = self.builder.create_string(def_arch_variant);

        let arch = {
            let mut abuilder = schema::ArchitectureBuilder::new(&mut self.builder);

            abuilder.add_processor(processor);
            abuilder.add_bits(corebin.bin.bits);
            abuilder.add_endian(endian);
            abuilder.add_variant(variant);

            abuilder.finish()
        };

        let meta = {
            let input_path = self.builder.create_string(&corebin.core.file);
            let input_md5 = self.builder.create_vector(&*md5);
            let input_sha256 = self.builder.create_vector(&*sha256);
            let input_format = self
                .builder
                .create_string(Metadata::format(&corebin.bin.bintype)?);
            let exporter = self.builder.create_string(&exporter);

            let mut mbuilder = schema::MetadataBuilder::new(&mut self.builder);

            mbuilder.add_input_path(input_path);
            mbuilder.add_input_md5(input_md5);
            mbuilder.add_input_sha256(input_sha256);
            mbuilder.add_input_format(input_format);
            mbuilder.add_input_size(self.backing.len() as u32);
            mbuilder.add_exporter(exporter);

            mbuilder.finish()
        };

        Ok((arch, meta))
    }

    fn export_segment(
        &mut self,
        seg: SegmentInfo,
    ) -> Result<flatbuffers::WIPOffset<schema::Segment<'db>>, Error> {
        // TODO: remove this alloc?
        let mut content = vec![0u8; seg.vsize as usize];
        if seg.size > 0 {
            assert!(seg.size <= seg.vsize);
            content[..seg.size as usize].copy_from_slice(
                &self.backing[seg.paddr as usize..(seg.paddr as usize + seg.size as usize)],
            );
        }

        let name = self.builder.create_string(seg.name);
        let bytes = self.builder.create_vector(&content);

        let mut sbuilder = schema::SegmentBuilder::new(&mut self.builder);

        sbuilder.add_name(name);
        sbuilder.add_address(seg.address().unwrap());
        sbuilder.add_size_(seg.vsize);
        sbuilder.add_alignment_(1); // can we get this from r2?
        sbuilder.add_address_size(self.address_size);
        sbuilder.add_endian(self.endian);
        sbuilder.add_bits(self.bits);
        sbuilder.add_code(seg.is_code());
        sbuilder.add_data(seg.is_data());
        sbuilder.add_external(false);
        sbuilder.add_executable(seg.is_executable());
        sbuilder.add_readable(seg.is_readable());
        sbuilder.add_writable(seg.is_writable());
        sbuilder.add_bytes(bytes);

        Ok(sbuilder.finish())
    }

    fn export_segments(
        &mut self,
    ) -> Result<
        (
            Vec<flatbuffers::WIPOffset<schema::Segment<'db>>>,
            IntervalSet<u64>,
        ),
        Error,
    > {
        let segsv = self.pipe.cmd("iSj")?;
        let seginfos = serde_json::from_str::<Vec<SegmentInfo>>(&segsv)
            .map_err(|e| Error::Deserialise("iSj", e))?;

        let mut seg_ivt = IntervalSet::new();
        let segs = seginfos
            .into_iter()
            .filter_map(|s| {
                if s.name.is_empty() && s.size == 0 {
                    None
                } else {
                    let vaddr = s.address()?;
                    seg_ivt.insert(vaddr..vaddr.checked_add(s.vsize as u64)?);
                    Some(self.export_segment(s))
                }
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok((segs, seg_ivt))
    }

    fn export_interref(
        &mut self,
        from: InterRef,
        to_id: u32,
        is_call: bool,
        fcn_map: &HashMap<u64, u32>,
    ) -> flatbuffers::WIPOffset<schema::InterRef<'db>> {
        let mut ibuilder = schema::InterRefBuilder::new(&mut self.builder);

        ibuilder.add_address(from.from);
        ibuilder.add_source(
            *from
                .fcn_addr
                .as_ref()
                .and_then(|addr| fcn_map.get(addr))
                .unwrap_or(&0xffff_ffff),
        );
        ibuilder.add_target(to_id);
        ibuilder.add_call(is_call);

        ibuilder.finish()
    }

    fn export_pred_intraref(
        &mut self,
        fcn_id: u32,
        from: u64,
        to_id: u64,
        blk_map: &HashMap<u64, u64>,
    ) -> flatbuffers::WIPOffset<schema::IntraRef<'db>> {
        let source = blk_map[&from];
        let mut ibuilder = schema::IntraRefBuilder::new(&mut self.builder);

        ibuilder.add_source(source);
        ibuilder.add_target(to_id);
        ibuilder.add_function(fcn_id);

        ibuilder.finish()
    }

    fn export_succ_intraref(
        &mut self,
        fcn_id: u32,
        from_id: u64,
        to: u64,
        blk_map: &HashMap<u64, u64>,
    ) -> flatbuffers::WIPOffset<schema::IntraRef<'db>> {
        let target = blk_map[&to];
        let mut ibuilder = schema::IntraRefBuilder::new(&mut self.builder);

        ibuilder.add_source(from_id);
        ibuilder.add_target(target);
        ibuilder.add_function(fcn_id);

        ibuilder.finish()
    }

    fn export_block(
        &mut self,
        fcn: u32,
        block: BasicBlock,
        id: u64,
        preds: Vec<u64>,
        succs: Vec<u64>,
        blk_map: &HashMap<u64, u64>,
    ) -> flatbuffers::WIPOffset<schema::BasicBlock<'db>> {
        let predsi = preds
            .into_iter()
            .map(|pred| self.export_pred_intraref(fcn, pred, id, blk_map))
            .collect::<Vec<_>>();

        let preds = self.builder.create_vector_from_iter(predsi.into_iter());

        let succsi = succs
            .into_iter()
            .filter(|succ| blk_map.contains_key(succ)) // filters out inter-procedural edges
            .map(|succ| self.export_succ_intraref(fcn, id, succ, blk_map))
            .collect::<Vec<_>>();

        let succs = self.builder.create_vector_from_iter(succsi.into_iter());

        let mut bbuilder = schema::BasicBlockBuilder::new(&mut self.builder);

        bbuilder.add_address(block.addr);
        bbuilder.add_size_(block.size);
        bbuilder.add_predecessors(preds);
        bbuilder.add_successors(succs);

        bbuilder.finish()
    }

    fn export_function(
        &mut self,
        name: String,
        address: u64,
        imported: bool,
        id: u32,
        fcn_map: &HashMap<u64, u32>,
        seg_ivt: &IntervalSet<u64>,
    ) -> Result<flatbuffers::WIPOffset<schema::Function<'db>>, Error> {
        let (entry, blocks) = if !imported {
            let blksv = self.pipe.cmd(&format!("afbj @ {:#x}", address))?;
            let blks = serde_json::from_str::<Vec<BasicBlock>>(&blksv)
                .map_err(|e| Error::Deserialise("afbj", e))?;

            let mut blk_map = HashMap::with_capacity(blks.len());
            let mut blk_ibps_map =
                HashMap::<u64, (u64, BasicBlock, Vec<u64>, Vec<u64>)>::with_capacity(blks.len());

            for (i, blk) in blks
                .into_iter()
                .filter(|b| seg_ivt.has_overlap(b.addr..=b.addr))
                .enumerate()
            {
                let bid = (id as u64) << 32 | (i as u64);
                let addr = blk.addr;

                let mut succs = Vec::new();
                if let Some(addr) = blk.jump {
                    succs.push(addr);
                }

                if let Some(addr) = blk.fail {
                    succs.push(addr);
                }

                for succ in succs.iter() {
                    let ibps = blk_ibps_map.entry(*succ).or_default();
                    ibps.2.push(addr); // set self as a pred
                }

                blk_map.insert(addr, bid);

                let ibps = blk_ibps_map.entry(addr).or_default();
                ibps.0 = bid;
                ibps.1 = blk;
                ibps.3.extend(succs.into_iter());
            }

            let entry = *blk_map.get(&address).unwrap_or(&0xffffffff_ffffffff);
            let blocks = blk_ibps_map
                .into_iter()
                .sorted_by_key(|(_, (bid, _, _, _))| *bid)
                .filter(|(addr, _)| blk_map.contains_key(&addr)) // work around for r2 inserting inter-procedural successors -_-
                .map(|(_, (bid, blk, preds, succs))| {
                    self.export_block(id, blk, bid, preds, succs, &blk_map)
                })
                .collect::<Vec<_>>();
            (entry, blocks)
        } else {
            (0xffffffff_ffffffff, Vec::default())
        };

        let refsv = self.pipe.cmd(&format!("axtj @ {:#x}", address))?;
        let refs = serde_json::from_str::<Vec<InterRef>>(&refsv)
            .map_err(|e| Error::Deserialise("axtj", e))?;

        let references = refs
            .into_iter()
            // ensures call type and jumps that are from outside this function
            .filter(|r| r.kind == "CALL" || (r.kind == "CODE" && r.fcn_addr != Some(address)))
            .map(|r| {
                let is_call = r.kind == "CALL";
                self.export_interref(r, id, is_call, fcn_map)
            })
            .collect::<Vec<_>>();

        let symbol = self.builder.create_string(name.trim());
        let basic_blocks = self.builder.create_vector_from_iter(blocks.into_iter());
        let references = self.builder.create_vector_from_iter(references.into_iter());

        let mut fbuilder = schema::FunctionBuilder::new(&mut self.builder);

        fbuilder.add_address(address);
        fbuilder.add_entry(entry);
        fbuilder.add_symbol(symbol);
        fbuilder.add_blocks(basic_blocks);
        fbuilder.add_references(references);

        Ok(fbuilder.finish())
    }

    fn export_functions(
        &mut self,
        seg_ivt: &IntervalSet<u64>,
    ) -> Result<Vec<flatbuffers::WIPOffset<schema::Function<'db>>>, Error> {
        let symbolsv = self.pipe.cmd("isj")?;
        let symbols = serde_json::from_str::<Vec<Symbol>>(&symbolsv)
            .map_err(|e| Error::Deserialise("isj", e))?;

        let relocsv = self.pipe.cmd("irj")?;
        let relocs = serde_json::from_str::<Vec<Relocation>>(&relocsv)
            .map_err(|e| Error::Deserialise("irj", e))?;

        let fcnsv = self.pipe.cmd("aflj")?; // functions: previously aflqj
        let fcns = serde_json::from_str::<Vec<Function>>(&fcnsv)
            .map_err(|e| Error::Deserialise("aflj", e))?;

        let mut n2a_map = HashMap::new();
        let mut a2n_map = HashMap::new(); // we use index as fn id for addr -> id

        for (id, fcn) in fcns.iter().enumerate() {
            let id = id as u32;
            a2n_map.insert(fcn.offset, id);
            n2a_map.insert(fcn.name.to_owned(), (fcn.offset, false, id));
        }

        let mut unmatched = HashSet::new();

        for sym in symbols
            .into_iter()
            .filter(|s| s.kind == "FUNC" && s.is_imported)
        {
            if sym.vaddr != 0 {
                let id = n2a_map.len() as u32;
                a2n_map.insert(sym.vaddr, id);
                n2a_map.insert(sym.realname.to_string(), (sym.vaddr, true, id));
            } else {
                unmatched.insert(sym.realname);
            }
        }

        for (addr, name) in relocs.into_iter().filter_map(|r| {
            if let Some(name) = r.name {
                Some((r.vaddr, name))
            } else {
                None
            }
        }) {
            if unmatched.contains(name) {
                let id = n2a_map.len() as u32;
                a2n_map.insert(addr, id);
                n2a_map.insert(name.to_string(), (addr, true, id));
            }
        }

        n2a_map
            .into_iter()
            .sorted_by_key(|(_name, (_addr, _imported, id))| *id)
            .map(|(name, (addr, imported, id))| {
                self.export_function(name, addr, imported, id, &a2n_map, seg_ivt)
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    fn export(&mut self) -> Result<(), Error> {
        let project = self.export_project()?;
        schema::finish_project_buffer(&mut self.builder, project);
        Ok(())
    }

    pub fn to_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        self.builder.reset();
        self.export()?;

        let path = path.as_ref();
        let mut file = File::create(path).map_err(Error::CannotExportToFile)?;

        file.write_all(self.builder.finished_data())
            .map_err(Error::CannotExportToFile)?;

        Ok(())
    }

    pub fn to_bytes(&mut self) -> Result<&[u8], Error> {
        self.builder.reset();
        self.export()?;
        Ok(self.builder.finished_data())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Radare {
    r2_path: Option<PathBuf>,
    fdb_path: Option<PathBuf>,
    overwrite: bool,
    analysis_commands: Vec<String>,
}

impl Default for Radare {
    fn default() -> Self {
        Self {
            r2_path: None,
            fdb_path: None,
            overwrite: false,
            analysis_commands: Vec::default(),
        }
    }
}

impl Radare {
    fn find_r2<F: Fn(&str) -> Result<PathBuf, Error>>(f: F) -> Result<PathBuf, Error> {
        if let Ok(local) = f("radare2").or_else(|_| f("r2")).or_else(|_| f("rizin")) {
            Ok(local)
        } else {
            f("radare2.exe")
                .or_else(|_| f("r2.exe"))
                .or_else(|_| f("rizin.exe"))
        }
    }

    fn find_rz<F: Fn(&str) -> Result<PathBuf, Error>>(f: F) -> Result<PathBuf, Error> {
        if let Ok(local) = f("rizin") {
            Ok(local)
        } else {
            f("rizin.exe")
        }
    }

    pub fn new() -> Result<Self, Error> {
        if let Ok(r2_path) = Self::find_r2(|p| which(p).map_err(Error::InvalidPath)) {
            Ok(Self {
                r2_path: Some(r2_path),
                ..Default::default()
            })
        } else {
            Err(Error::NotAvailable)
        }
    }

    pub fn new_rizin() -> Result<Self, Error> {
        if let Ok(rz_path) = Self::find_rz(|p| which(p).map_err(Error::InvalidPath)) {
            Ok(Self {
                r2_path: Some(rz_path),
                ..Default::default()
            })
        } else {
            Err(Error::NotAvailable)
        }
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let root_dir = path.as_ref();
        let r2_path =
            Self::find_r2(|p| which_in(p, Some(root_dir), ".").map_err(Error::InvalidPath))?;

        Ok(Self {
            r2_path: Some(r2_path),
            ..Default::default()
        })
    }

    pub fn export_path<P: AsRef<Path>>(mut self, path: P, overwrite: bool) -> Self {
        self.fdb_path = Some(path.as_ref().to_owned());
        self.overwrite = overwrite;
        self
    }

    pub fn with_analysis<S: AsRef<str>>(mut self, command: S) -> Self {
        self.analysis_commands.push(command.as_ref().to_owned());
        self
    }
}

impl Backend for Radare {
    type Error = Error;

    fn name(&self) -> &'static str {
        "fugue-radare"
    }

    fn is_available(&self) -> bool {
        self.r2_path.is_some()
    }

    fn is_preferred_for(&self, path: &Url) -> Option<bool> {
        Some(path.scheme() == "shm")
    }

    fn import(&self, program: &Url) -> Result<Imported, Self::Error> {
        let program = if program.scheme() == "file" {
            program
                .to_file_path()
                .map_err(|_| Error::UnsupportedScheme(program.scheme().to_owned()))?
                .to_string_lossy()
                .to_string()
        } else if program.scheme() == "shm" {
            program.to_string()
        } else {
            return Err(Error::UnsupportedScheme(program.scheme().to_owned()));
        };

        let r2_path = self.r2_path.as_ref().ok_or_else(|| Error::NotAvailable)?;
        let config = R2PipeSpawnOptions {
            exepath: format!("{}", r2_path.display()),
            ..Default::default()
        };

        let mut exporter = RadareExporter::new_with(&program, config)?;
        if self.analysis_commands.is_empty() {
            exporter.analyse()?;
        } else {
            for cmd in self.analysis_commands.iter() {
                exporter.analyse_with(cmd)?;
            }
        }

        if let Some(ref fdb_path) = self.fdb_path {
            if fdb_path.exists() && !self.overwrite {
                return Ok(Imported::File(fdb_path.clone()));
            } else {
                exporter.to_file(fdb_path)?;
                Ok(Imported::File(fdb_path.clone()))
            }
        } else {
            Ok(Imported::Bytes(exporter.to_bytes()?.to_vec()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_available() -> Result<(), Error> {
        let r2 = Radare::new()?;
        assert!(r2.is_available());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_available_bwrap() -> Result<(), Error> {
        let r2 = Radare::from_path("./tests")?;
        assert!(r2.is_available());
        Ok(())
    }

    #[test]
    fn test_import_true() -> Result<(), Error> {
        let mut ex = RadareExporter::new_with(
            "./tests/true",
            R2PipeSpawnOptions {
                exepath: "radare2".to_string(),
                ..Default::default()
            },
        )?;
        ex.analyse()?;

        let _ = ex.to_bytes()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_import_true_bwrap() -> Result<(), Error> {
        let mut ex = RadareExporter::new_with(
            "/bin/true",
            R2PipeSpawnOptions {
                exepath: "./tests/radare2".to_string(),
                ..Default::default()
            },
        )?;

        ex.analyse()?;
        let _ = ex.to_bytes()?;

        Ok(())
    }

    #[test]
    fn test_import_true_rizin() -> Result<(), Error> {
        let mut ex = RadareExporter::new_with(
            "./tests/true",
            R2PipeSpawnOptions {
                exepath: "rizin".to_string(),
                ..Default::default()
            },
        )?;
        ex.analyse()?;

        let _ = ex.to_bytes()?;
        Ok(())
    }

    #[test]
    fn test_import_true_rizin_shm() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read;

        let mut file = File::open("./tests/true")?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        let mut shm = shared_memory::ShmemConf::new().size(bytes.len()).create()?;

        unsafe {
            shm.as_slice_mut().copy_from_slice(&bytes);
        }

        let path = format!("shm:/{}/{}", shm.get_os_id(), bytes.len());
        let purl = Url::parse(&path)?;

        let riz = Radare::new_rizin()?.export_path("/tmp/ls-rz.fdb", true);
        let _imp = riz.import(&purl)?;

        Ok(())
    }

    #[test]
    fn test_import_true_export() -> Result<(), Error> {
        let mut ex = RadareExporter::new("./tests/true")?;
        ex.analyse()?;
        let _ = ex.to_file("/tmp/ls.fdb")?;
        Ok(())
    }

    #[test]
    fn test_import_efi_export() -> Result<(), Error> {
        let mut ex = RadareExporter::new("./tests/tetris.efi")?;
        ex.analyse()?;
        let _ = ex.to_file("/tmp/tetris.fdb")?;
        Ok(())
    }

    #[test]
    fn test_db() -> Result<(), Box<dyn std::error::Error>> {
        use fugue::db::DatabaseImporter;
        use fugue::ir::disassembly::IRBuilderArena;
        use fugue::ir::LanguageDB;

        let ldb = LanguageDB::from_directory_with("./tests", true)?;
        let irb = IRBuilderArena::with_capacity(4096);
        let mut dbi = DatabaseImporter::new("./tests/tetris.efi");

        dbi.register_backend(Radare::new_rizin()?);
        let db = dbi.import(&ldb)?;

        let mut ctx = db.translators().next().unwrap().context_database();

        for f in db.functions() {
            println!("=== function: {:x} ===", f.address());
            for b in f.blocks() {
                println!("=== block insns: {:x} ===", b.address());

                for insn in b.disassemble(&irb)? {
                    println!("{}", insn.display());
                }

                println!("=== block pcode: {:x} ===", b.address());

                for stmt in b.lift_with(&mut ctx)? {
                    println!("{}", stmt.display());
                }
            }
        }

        Ok(())
    }
}

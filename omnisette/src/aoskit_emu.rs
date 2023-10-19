use std::{
    io::{Seek, SeekFrom, Cursor},
    rc::Rc,
    os::unix::fs::MetadataExt,
    path::Path
};
use mach_object::{
    Symbol, SymbolIter, MachHeader, Section, LoadCommand, OFile,
    CPU_TYPE_X86, CPU_TYPE_X86_64,
    CPU_TYPE_ARM, CPU_TYPE_ARM64,
    CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64
};
use memmap2::{MmapMut, MmapOptions};
use android_loader::sysv64;

#[derive(Debug)]
pub struct MachHook {
    mmap: MmapMut,
    header: MachHeader,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    sections: Vec<Rc<Section>>,
}

macro_rules! symbols{
    ($iter:ident, $hook:ident) => {
        let mut sym_cursor = Cursor::new($hook.mmap.as_ref());
        // If this returns an error, then the macho is malformed (due to it not having a valid
        // symoff) and impossible to parse correctly anyways.
        sym_cursor.seek(SeekFrom::Start($hook.symoff as u64)).unwrap();
        let mut $iter = SymbolIter::new(
            &mut sym_cursor,
            $hook.sections.clone(),
            $hook.nsyms,
            $hook.stroff as u32,
            $hook.strsize,
            $hook.header.is_bigend(),
            $hook.header.is_64bit()
        );
    }
}

#[derive(Debug)]
pub enum NewMachHookErr {
    FileUnreadable(std::io::Error),
    MmapFailed(std::io::Error),
    OFileParseFailed(mach_object::MachError),
	ProtectErr(region::Error),
    NoFileMatchedArch,
    NonMachOrFatFile,
    NoSymtabInFile,
}

impl std::fmt::Display for NewMachHookErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use NewMachHookErr::*;
        match self {
            FileUnreadable(e) => write!(f, "Input file is unreadable: {e}"),
            MmapFailed(e) => write!(f, "Mmap'ing file data into memory failed: {e}"),
            OFileParseFailed(e) => write!(f, "Couldn't parse Mach-o file: {e}"),
			ProtectErr(e) => write!(f, "Couldn't protection mmap'ed region: {e}"),
            NoFileMatchedArch => write!(f, "Input file had no sections that matched the arch of this device"),
            NonMachOrFatFile => write!(f, "This is a mach-o file, but something like an ar file which we can't process"),
            NoSymtabInFile => write!(f, "The input file somehow has no Symtab load command")
        }
    }
}

impl std::error::Error for NewMachHookErr {}

#[derive(Debug)]
pub struct SymbolNotFound<'s>(&'s str);

impl std::fmt::Display for SymbolNotFound<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Symbol for '{}' was not found", self.0)
    }
}

impl std::error::Error for SymbolNotFound<'_> {}

impl MachHook {
    pub fn new<P: AsRef<Path> + Clone>(lib_path: P, loc: Option<(u64, u64)>) -> Result<Self, NewMachHookErr> {
		let file = std::fs::OpenOptions::new()
			.read(true)
			.write(true)
			.open(&lib_path)
			.map_err(NewMachHookErr::FileUnreadable)?;
        let size = loc.map_or_else(
            || std::fs::metadata(&lib_path).map_or(0, |m| m.size()),
            |(start, end)| end - start
        ) as usize;

        let mmap = unsafe {
			MmapOptions::new()
				.offset(loc.map_or(0, |l| l.0))
				.len(size)
				.map_mut(&file)
				.map_err(NewMachHookErr::MmapFailed)?
		};

        unsafe {
            region::protect(mmap.as_ptr(), size, region::Protection::READ_WRITE_EXECUTE)
				.map_err(NewMachHookErr::ProtectErr)?;
        }

        fn header_matches(header: &MachHeader) -> bool {
            if cfg!(target_arch = "x86_64") {
                header.cputype == CPU_TYPE_X86_64
            } else if cfg!(target_arch = "x86") {
                header.cputype == CPU_TYPE_X86 && !header.is_64bit()
            } else if cfg!(target_arch = "aarch64") {
                header.cputype == CPU_TYPE_ARM64
            } else if cfg!(target_arch = "arm") {
                header.cputype == CPU_TYPE_ARM && !header.is_64bit()
            } else if cfg!(target_arch = "powerpc") {
                header.cputype == CPU_TYPE_POWERPC && !header.is_64bit()
            } else if cfg!(target_arch = "powerpc64") {
                header.cputype == CPU_TYPE_POWERPC64
            } else {
                false
            }
        }

        let mut cursor = Cursor::new(mmap.as_ref());

        let (header, commands) = match OFile::parse(&mut cursor).map_err(NewMachHookErr::OFileParseFailed)? {
            OFile::MachFile { header, commands } => (header, commands),
            OFile::FatFile { magic: _, files } => return files.into_iter().map(|(arch, _)|
					Self::new(lib_path.clone(), Some((arch.offset, arch.offset + arch.size)))
			).find_map(|hook| hook.ok().and_then(|h| header_matches(&h.header).then_some(h)))
			.ok_or_else(|| NewMachHookErr::NoFileMatchedArch),
            _ => return Err(NewMachHookErr::NonMachOrFatFile)
        };

        if !header_matches(&header) {
            return Err(NewMachHookErr::NoFileMatchedArch);
        }

        let (symoff, nsyms, stroff, strsize) = commands.iter()
            .find_map(|cmd| match &cmd.0 {
                LoadCommand::SymTab {
                    symoff, nsyms, stroff, strsize
                } => Some((*symoff, *nsyms, *stroff, *strsize)),
                _ => None
            }).ok_or_else(|| NewMachHookErr::NoSymtabInFile)?;

        let sections: Vec<Rc<Section>> = commands
            .iter()
            .filter_map(|cmd| match cmd.0 {
                LoadCommand::Segment { ref sections, .. }
                | LoadCommand::Segment64 { ref sections, .. } => Some(sections),
                _ => None
            })
            .flat_map(Vec::clone)
            .collect();

        Ok(Self {
            mmap,
            header,
            symoff,
            nsyms,
            stroff,
            strsize,
            sections,
        })
    }

    pub fn get_symbol_ptr(&self, symbol_name: &str) -> Option<*const ()> {
		let offset = self.mmap.as_ptr() as usize;
        symbols!(symbols, self);

        symbols.find(|s| s.name() == Some(symbol_name))
            .and_then(|sym| match sym {
                Symbol::Absolute { entry, .. } | Symbol::Defined { entry, .. } => Some((entry + offset) as *const ()),
                Symbol::Undefined { .. } | Symbol::Prebound { .. } => None,
                Symbol::Indirect { symbol, .. } => symbol.and_then(|s| self.get_symbol_ptr(s)),
                Symbol::Debug { addr, .. } => Some((addr + offset) as *const ())
            })
    }

    // substitution must be a pointer to a sysv64 calling convention function
    pub fn hook_fn<'s>(
        &mut self, symbol_name: &'s str, substitution: *const ()
    ) -> Result<*const (), SymbolNotFound<'s>> {
        symbols!(symbols, self);

        let symbol = symbols.position(|s| s.name() == Some(symbol_name))
            .ok_or(SymbolNotFound(symbol_name))?;

        let is_64bit = self.header.is_64bit();
        let sym_size = if is_64bit { 16 } else { 12 };
        let start = self.symoff as usize + (symbol * sym_size);
        let sym_data = &mut self.mmap.as_mut()[start..start + sym_size];

        let flags = sym_data[4];
        const N_TYPE: u8 = 0x03;
        const N_ABS: u8 = 0x2;

        // Make it an absolute symbol
        sym_data[4] = (flags & !N_TYPE) | N_ABS;

        // Overwrite the 'value' of the symbol to make it the address of the intended function
        let ret = if is_64bit {
            let ptr: [u8; 8] = bytemuck::cast(substitution as usize);
            let ret: [u8; 8] = sym_data[8..].try_into().unwrap();
            sym_data[8..].copy_from_slice(&ptr);
            let ret_ptr: usize = bytemuck::cast(ret);
            ret_ptr as *const ()
        } else {
            let ptr: [u8; 4] = bytemuck::cast(substitution as usize);
            let ret: [u8; 4] = sym_data[8..].try_into().unwrap();
            sym_data[8..].copy_from_slice(&ptr);
            let ret_ptr: usize = bytemuck::cast(ret);
            ret_ptr as *const ()
        };

        Ok(ret)
    }

    #[sysv64]
    pub unsafe fn dlopen(name: *const libc::c_char) -> *mut libc::c_void {
        #[cfg_attr(not(target_family = "windows"), allow(unused_mut))]
        let mut path_str = std::ffi::CStr::from_ptr(name).to_str().unwrap();

        let _path: String;
        #[cfg(target_family = "windows")]
        {
            _path = path_str.chars()
                .map(|x| match x {
                    '\\' => '/',
                    c => c
                }).collect::<String>();

            path_str = _path.as_str();
        }

        match MachHook::new(path_str, None) {
            Ok(lib) => Box::into_raw(Box::new(lib)) as *mut libc::c_void,
            Err(_) => std::ptr::null_mut(),
        }
    }

    #[sysv64]
    pub unsafe fn dlsym(hook: *mut MachHook, symbol: *const libc::c_char) -> *mut libc::c_void {
        let symbol = std::ffi::CStr::from_ptr(symbol).to_str().unwrap();
        match hook.as_ref().and_then(|lib| lib.get_symbol_ptr(symbol)) {
            Some(func) => func as *mut libc::c_void,
            None => std::ptr::null_mut(),
        }
    }

    #[sysv64]
    pub unsafe fn dlclose(library: *mut MachHook) {
        let _ = Box::from_raw(library);
    }
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub extern "C" fn set_android_id_stub(_id: *const u8, _length: u32) -> i32 {
    0
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub extern "C" fn set_android_id_stub(_id: *const u8, _length: u32) -> i32 {
    0
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub extern "C" fn set_android_prov_path_stub(_path: *const u8) -> i32 {
    0
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub extern "sysv64" fn set_android_prov_path_stub(_path: *const u8) -> i32 {
    0
}

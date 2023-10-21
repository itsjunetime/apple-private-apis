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
    CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64,
    S_LAZY_SYMBOL_POINTERS, S_SYMBOL_STUBS, S_NON_LAZY_SYMBOL_POINTERS,
    S_LAZY_DYLIB_SYMBOL_POINTERS, S_THREAD_LOCAL_VARIABLE_POINTERS,
	SEG_DATA
};
use memmap2::{MmapMut, MmapOptions};
use android_loader::sysv64;

static USIZE_LEN: usize = std::mem::size_of::<usize>();

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
        #[allow(unused_mut)]
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
        let file = std::fs::read(&lib_path).map_err(NewMachHookErr::FileUnreadable)?;
        let size = loc.map_or_else(
            || std::fs::metadata(&lib_path).map_or(0, |m| m.size()),
            |(start, end)| end - start
        ) as usize;

        let mut mmap = MmapOptions::new()
            .len(size)
            .map_anon()
            .map_err(NewMachHookErr::MmapFailed)?;

        let start = loc.map_or(0, |l| l.0) as usize;
        mmap[..].copy_from_slice(&file[start..start + size]);
		let mmap_start = mmap.as_ptr();

        println!("mmap'ed at {:?}", mmap_start);

        unsafe {
            region::protect(mmap_start, size, region::Protection::READ_WRITE_EXECUTE)
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

        let mut hook = Self {
            mmap,
            header,
            symoff,
            nsyms,
            stroff,
            strsize,
            sections,
        };

        symbols!(symbols, hook);

        let handle = unsafe { libc::dlopen(std::ptr::null(), 0) };
        let syms: Vec<_> = symbols.flat_map(|sym| match sym {
            Symbol::Undefined { name, .. } | Symbol::Prebound { name, .. } => {
                let Some(name) = name else {
                    return None;
                };
                let c_name = std::ffi::CString::new(&name[1..]).unwrap();
                let ptr = unsafe { libc::dlsym(handle, c_name.as_ptr()) };
                Some((name.to_string(), ptr as *const ()))
            },
            Symbol::Absolute { name, entry, .. } | Symbol::Defined { name, entry, .. } =>
                name.map(|n| (n.to_string(), (entry + mmap_start as usize) as *const ())),
            Symbol::Debug { name, addr, .. } =>
                name.map(|n| (n.to_string(), (addr + mmap_start as usize) as *const ())),
            // We'll handle indirects later
            Symbol::Indirect { .. } =>None
        }).collect();

        for (name, resolved_addr) in syms {
            if let Err(e) = hook.hook_fn(&name, resolved_addr) {
                println!("couldn't hook {name} to {resolved_addr:?}: {e}");
            }
        }

        // now we gotta resolve indirect symbols
        // got bless https://github.com/opensource-apple/cctools/blob/master/otool/ofile_print.c#L7093
        let (indirectoff, nindirect) = commands.iter()
            .find_map(|cmd| match &cmd.0 {
                LoadCommand::DySymTab { indirectsymoff, nindirectsyms, .. } => Some((indirectsymoff, nindirectsyms)),
                _ => None
            }).ok_or_else(|| NewMachHookErr::NoSymtabInFile)?;

        let indirect_table = &hook.mmap.as_ref()[*indirectoff as usize..][..*nindirect as usize * 4];
        let is_64bit = hook.header.is_64bit();

        symbols!(symbols, hook);
        let symbols: Vec<_> = symbols.collect();

        let relocs = hook.sections.iter().flat_map(|sec| {
            let s_type = sec.flags.sect_type();
            let stride = if s_type == S_SYMBOL_STUBS {
                sec.reserved2
            } else if s_type == S_LAZY_SYMBOL_POINTERS ||
               s_type == S_NON_LAZY_SYMBOL_POINTERS ||
               s_type == S_LAZY_DYLIB_SYMBOL_POINTERS ||
               s_type == S_THREAD_LOCAL_VARIABLE_POINTERS {
                if is_64bit { 8 } else { 4 }
            } else {
                return None;
            } as usize;

            if stride == 0 {
                return None;
            }

            let start = sec.reserved1 as usize;

            Some(indirect_table.chunks(4).skip(start).enumerate().filter_map(|(indir_idx, sym_idx)| {
                let idx = u32::from_le_bytes(sym_idx.try_into().unwrap()) as usize;
                let write_to = sec.addr + (indir_idx * stride);

                if idx < symbols.len() {
                    let sym = &symbols[idx];
                    // they gotta be resolved at this point
                    let Symbol::Absolute { entry, .. } = sym else {
                        return None;
                    };
                    Some((write_to, *entry))
                } else {
                    println!("trying to get index {idx}???");
                    None
                }
            }).collect::<Vec<_>>())
        })
        .flatten()
        .collect::<Vec<_>>();

		fn write_addr_to(mem: &mut [u8], write_to: usize, addr: usize) {
			let loc = &mut mem[write_to..][..USIZE_LEN];
			let ptr = addr.to_le_bytes();
			loc.copy_from_slice(&ptr);
		}

        for (write_to, data) in relocs {
			write_addr_to(hook.mmap.as_mut(), write_to, data);
        }

		// Now we need to go through every address in __DATA/__const and relocate it to the current
		// executing address. I think. I cannot find any documentation about this anywhere so I'm
		// just guessing
		let (const_start, const_end) = hook.sections.iter()
			.find(|sec| sec.segname == SEG_DATA && sec.sectname == "__const")
			.map(|sec| (sec.offset as usize, sec.size))
			.unwrap();

		let mmap_len = hook.mmap.len();
		for (offset, slice) in hook.mmap.as_mut()[const_start..][..const_end].chunks_mut(USIZE_LEN).enumerate() {
			let addr = usize::from_le_bytes(slice.try_into().unwrap());
			if addr < mmap_len {
				write_addr_to(slice, 0, addr + mmap_start as usize);
			} else {
				eprintln!("Couldn't relocate __DATA/__const {addr} since it is outside bounds (max {mmap_len}, at {:?})", (const_start + (offset * USIZE_LEN)) as *const ());
			}
		}

		// time to cheat!
		// At 0x116d08, there should be a reference to a subroutine that checks the OS version.
		// We just want to hijack that reference to make it work

		let noop_loc = noop_stub as usize;
		println!("writing {noop_loc} to 0x116d08");
		write_addr_to(hook.mmap.as_mut(), 0x116d08, noop_loc + 2);

        Ok(hook)
    }

    pub fn get_symbol_ptr(&self, symbol_name: &str) -> Option<*const ()> {
        // symbols should be resolved with offsets added in at this point
        symbols!(symbols, self);

        symbols.find(|s| s.name() == Some(symbol_name))
            .and_then(|sym| match sym {
                Symbol::Absolute { entry, .. } | Symbol::Defined { entry, .. } => Some(entry as *const ()),
                Symbol::Undefined { .. } | Symbol::Prebound { .. } => None,
                Symbol::Indirect { symbol, .. } => symbol.and_then(|s| self.get_symbol_ptr(s)),
                Symbol::Debug { addr, .. } => Some(addr as *const ())
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
pub extern "C" fn noop_stub() -> i32 {
    0
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub extern "C" fn noop_stub() -> i32 {
    0
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

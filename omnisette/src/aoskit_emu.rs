use std::{
	io::{Seek, SeekFrom, Cursor},
	rc::Rc,
	os::unix::fs::MetadataExt,
	path::Path,
	ffi::{CString, CStr}
};
use mach_object::{
	Symbol, SymbolIter, MachHeader, Section, LoadCommand, OFile,
	CPU_TYPE_X86, CPU_TYPE_X86_64,
	CPU_TYPE_ARM, CPU_TYPE_ARM64,
	CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64,
	S_LAZY_SYMBOL_POINTERS, S_SYMBOL_STUBS, S_NON_LAZY_SYMBOL_POINTERS,
	S_LAZY_DYLIB_SYMBOL_POINTERS, S_THREAD_LOCAL_VARIABLE_POINTERS,
	SEG_DATA, MachCommand,
};
use memmap2::{MmapMut, MmapOptions};
use android_loader::sysv64;

static USIZE_LEN: usize = std::mem::size_of::<usize>();
const EXPORT_SYMBOL_FLAGS_REEXPORT: usize = 0x08;
const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: usize = 0x10;

#[derive(Debug)]
struct Binding {
	file_offset: usize,
	library_ordinal: isize,
	addend: isize,
	trailing_flags: u8,
	sym_type: u8,
	sym_name: String,
}

#[derive(Debug)]
pub struct SymInfo {
	symoff: u64,
	nsyms: u32,
	stroff: u32,
	strsize: u32
}

#[derive(Debug)]
pub struct MachHook {
	mmap: MmapMut,
	header: MachHeader,
	commands: Vec<MachCommand>,
	sections: Vec<Rc<Section>>,
	bindings: Vec<Binding>,
	sym_info: SymInfo
}

macro_rules! symbols{
	($iter:ident, $hook:ident) => {
		let mut sym_cursor = Cursor::new($hook.mmap.as_ref());
		// If this returns an error, then the macho is malformed (due to it not having a valid
		// symoff) and impossible to parse correctly anyways.
		sym_cursor.seek(SeekFrom::Start($hook.sym_info.symoff)).unwrap();
		#[allow(unused_mut)]
		let mut $iter = SymbolIter::new(
			&mut sym_cursor,
			$hook.sections.clone(),
			$hook.sym_info.nsyms,
			$hook.sym_info.stroff,
			$hook.sym_info.strsize,
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

// since the compiler thinks the fields aren't read even though they're debugged
#[allow(dead_code)]
#[derive(Debug)]
struct TrieEntry {
	// byte offset from the beginning of the trie data it comes from
	pub node_offset: usize,
	pub data: TrieData
}

#[allow(dead_code)]
#[derive(Debug)]
struct TrieData {
	name: String,
	flags: usize,
	address: usize,
	other: usize,
	import_name: Option<String>
}

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

		println!("mmap: {mmap_start:?} -> {:x}", mmap_start as usize + mmap.len());

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
			commands,
			sections,
			bindings: Vec::new(),
			sym_info: SymInfo {
				symoff: symoff as _,
				nsyms,
				stroff,
				strsize
			}
		};

		hook.relocate_symbols();

		// now we gotta resolve indirect symbols
		hook.resolve_indirects()?;

		// hook.check_export_info();

		hook.rebind();

		hook.do_const_relocs();

		// time to cheat!
		// At 0x116d08, there should be a reference to a subroutine that checks the OS version.
		// We just want to hijack that reference to make it work

		#[cfg(target_arch = "x86_64")]
		{
			let noop_loc = noop_stub as usize;
			println!("writing {noop_loc:x} to 0x116d08");
			hook.write_ptr_to(0x116d08, noop_loc + 2);
		}

		#[cfg(target_arch = "x86_64")]
		unsafe {
			region::protect(mmap_start, size, region::Protection::READ_WRITE_EXECUTE).unwrap();
		}

		println!("mmap start: {:?}", mmap_start);

		Ok(hook)
	}

	fn relocate_symbols(&mut self) {
		// we need this to be signed because, since we're using images extracted from dyldex, their
		// expected load position may be way higher than the mmap_start, so we'll need to offset the
		// symbols back
		let sym_offset = self.mmap.as_ptr() as isize - self.load_addr() as isize;
		println!("sym_offset: {sym_offset}");
		symbols!(symbols, self);

		let handle = unsafe { libc::dlopen(std::ptr::null(), 0) };
		let syms: Vec<_> = symbols.flat_map(|sym| match sym {
			Symbol::Undefined { name, .. } | Symbol::Prebound { name, .. } => {
				let Some(name) = name else {
					return None;
				};
				let c_name = CString::new(&name[1..]).unwrap();
				let ptr = unsafe { libc::dlsym(handle, c_name.as_ptr()) };
				if ptr.is_null() {
					None
				} else {
					println!("found ptr for {name} at {ptr:?}");
					Some((name.to_string(), ptr as *const ()))
				}
			},
			Symbol::Absolute { name, entry, .. } | Symbol::Defined { name, entry, .. } =>
				name.map(|n| (n.to_string(), (entry as isize + sym_offset) as *const ())),
			Symbol::Debug { name, addr, .. } =>
				name.map(|n| (n.to_string(), (addr as isize + sym_offset) as *const ())),
			// We'll handle indirects later
			Symbol::Indirect { .. } =>None
		}).collect();

		for (name, resolved_addr) in syms {
			if let Err(e) = self.hook_fn(&name, resolved_addr) {
				println!("couldn't hook {name} to {resolved_addr:?}: {e}");
			}
		}
	}

	fn resolve_indirects(&mut self) -> Result<(), NewMachHookErr> {
		// got bless https://github.com/opensource-apple/cctools/blob/master/otool/ofile_print.c#L7093
		let (indirectoff, nindirect) = self.commands.iter()
			.find_map(|cmd| match &cmd.0 {
				LoadCommand::DySymTab { indirectsymoff, nindirectsyms, .. } => Some((indirectsymoff, nindirectsyms)),
				_ => None
			}).ok_or_else(|| NewMachHookErr::NoSymtabInFile)?;

		let indirect_table = &self.mmap.as_ref()[*indirectoff as usize..][..*nindirect as usize * 4];
		let is_64bit = self.header.is_64bit();

		symbols!(symbols, self);
		let symbols: Vec<_> = symbols.collect();

		let relocs = self.sections.iter().flat_map(|sec| {
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
				let write_to = sec.offset as usize + (indir_idx * stride);

				if idx < symbols.len() {
					let sym = &symbols[idx];
					// println!("got indir {sym:?}");
					// they gotta be resolved at this point
					let Symbol::Absolute { entry, .. } = sym else {
						return None;
					};
					if *entry == 0 {
						return None;
					}
					Some((write_to, *entry))
				} else {
					println!("trying to get index {idx}???");
					None
				}
			}).collect::<Vec<_>>())
		})
		.flatten()
		.collect::<Vec<_>>();

		for (write_to, addr) in relocs {
			self.write_ptr_to(write_to, addr);
		}

		Ok(())
	}

	fn process_export_node(mut offset: usize, data: &[u8], cumulative: &mut String) -> Vec<TrieData> {
		let mut parent_entry = None;
		let (terminal_size, term_increase) = MachHook::read_uleb128(&data[offset..]);
		if terminal_size != 0 {
			offset += term_increase;
			let mut uleb_ptr = &data[offset + term_increase..];

			let name = cumulative.clone();
			let (flags, flag_increase) = MachHook::read_uleb128(uleb_ptr);
			uleb_ptr = &uleb_ptr[flag_increase..];

			let address: usize;
			let other: usize;
			let import_name: Option<String>;

			let (next_uleb, increase) = MachHook::read_uleb128(uleb_ptr);
			uleb_ptr = &uleb_ptr[increase..];

			if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
				address = 0;
				other = next_uleb;
				import_name = uleb_ptr
					.split(|x| *x == 0)
					.next()
					.map(String::from_utf8_lossy)
					.map(std::borrow::Cow::into_owned);
			} else {
				address = next_uleb;
				if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
					let (uleb_other, _increase) = MachHook::read_uleb128(uleb_ptr);
					other = uleb_other;
					// we should increase uleb_ptr but it's never read again soooo
					//uleb_ptr = &uleb_ptr[increase..];
				} else {
					other = 0;
				}
				import_name = None;
			}

			parent_entry = Some(TrieEntry {
				node_offset: offset,
				data: TrieData {
					name,
					flags,
					address,
					other,
					import_name
				}
			});
		}

		let children_count = data[offset + terminal_size];
		let mut child_vec = Vec::with_capacity(parent_entry.map_or(0, |_| 1) + children_count as usize);
		let mut children = &data[offset + terminal_size + 1..];

		child_vec.extend((0..children_count).flat_map(|_| {
			let edge_str = children.split(|c| *c == 0)
				.next()
				.and_then(|s| std::str::from_utf8(s).ok())
				.unwrap();
			if cumulative.is_empty() {
				cumulative.push_str(edge_str);
			}
			// have to increase by 1 to get the null byte
			children = &children[edge_str.len() + 1..];
			let (child_offset, child_increase) = MachHook::read_uleb128(children);
			children = &children[child_increase..];
			MachHook::process_export_node(child_offset, data, cumulative)
		}));

		child_vec
	}

	fn check_export_info(&self) {
		// based on `processExportNode` in
		// https://opensource.apple.com/source/ld64/ld64-264.3.102/src/abstraction/MachOTrie.hpp.auto.html
		let edit_data = self.commands.iter()
			.find_map(|cmd| match &cmd.0 {
				LoadCommand::DyldExportsTrie(data) => Some((data.off as usize, data.size as usize)),
				_ => None
			});

		if let Some((edit_offset, edit_size)) = edit_data {
			if edit_size > 0 {
				let trie_data = &self.mmap.as_ref()[edit_offset..][..edit_size];
				let mut cumulative = String::new();
				let tries = MachHook::process_export_node(0, trie_data, &mut cumulative);

				println!("tries: {tries:?}");
			} else {
				println!("edit_size is {edit_size}, nothing to process");
			}
		} else {
			println!("No export info");
		}
	}

	fn rebind(&mut self) {
		let dyld_info = self.commands.iter()
			.find_map(|cmd| match &cmd.0 {
				LoadCommand::DyldInfo { bind_off, bind_size, export_off, export_size, .. } =>
					Some((bind_off, bind_size, export_off, export_size)),
				_ => None,
			});

		if let Some((.., export_off, export_size)) = dyld_info {
			let export_data = &self.mmap.as_ref()[*export_off as usize..][..*export_size as usize];
			let mut trie_str = String::new();
			let tries = Self::process_export_node(0, export_data, &mut trie_str);
			println!("tries from dyld_info export info: {tries:?}");
		}

		if let Some((bind_off, bind_size, ..)) = dyld_info {
			let mut cur_seg_idx = 0;
			let mut cur_offset = 0;
			let mut cur_library_ordinal = 0;
			let mut cur_addend = 0;
			let mut cur_trailing_flags = 0;
			let mut cur_name = std::borrow::Cow::Borrowed("");
			let mut cur_type = 0;
			let mut idx = 0;

			let bind_data = &self.mmap.as_ref()[*bind_off as usize..][..*bind_size as usize];

			while idx < *bind_size as usize {
				let instr = bind_data[idx];
				idx += 1;

				match instr & 0xf0 {
					// DONE
					0x00 => continue,
					// SET_DYLIB_ORDINAL_IMM
					0x10 => cur_library_ordinal = (instr & 0x0f) as isize,
					// SET_DYLIB_ORDINAL_ULEB
					0x20 => {
						let (ordinal, increase) = MachHook::read_uleb128(&bind_data[idx..]);
						cur_library_ordinal = ordinal as isize;
						idx += increase;
					},
					// SET_DYLIB_SPECIAL_IMM
					0x30 => cur_library_ordinal = -((instr & 0x0f) as isize),
					// SET_SYMBOL_TRAILING_FLAGS_IMM
					0x40 => {
						cur_trailing_flags = instr & 0x0f;
						cur_name = String::from_utf8_lossy(
							bind_data[idx..].split(|x| *x == 0).next().unwrap()
						);
						idx += cur_name.len() + 1;
					},
					// SET_TYPE_IMM
					0x50 => cur_type = instr & 0x0f,
					// SET_ADDEND_SLEB
					0x60 => {
						let (addend, increase) = MachHook::read_sleb128(&bind_data[idx..]);
						cur_addend = addend;
						idx += increase;
					},
					// SET_SEGMENT_AND_OFFSET_ULEB
					0x70 => {
						cur_seg_idx = instr & 0x0f;
						let (offset, increase) = MachHook::read_uleb128(&bind_data[idx..]);
						cur_offset = offset;
						idx += increase;
					},
					// ADD_ADDR_ULEB
					0x80 => {
						let (offset, increase) = MachHook::read_uleb128(&bind_data[idx..]);
						cur_offset = cur_offset.wrapping_add(offset);
						idx += increase;
					}
					// DO_BIND, DO_BIND_ADD_ADDR_ULEB, DO_BIND_ADD_ADDR_IMM_SCALED
					0x90 | 0xa0 | 0xb0 => {
						let Some(seg_file_off) = self.commands.iter()
							.filter_map(|cmd| match cmd.0 {
								LoadCommand::Segment { fileoff, .. }
								| LoadCommand::Segment64 { fileoff, .. } => Some(fileoff),
								_ => None
							})
							.nth(cur_seg_idx as usize) else {
								println!("Invalid segment index {} for binding '{}'", cur_seg_idx, cur_name);
								continue;
							};

						self.bindings.push(Binding {
							file_offset: seg_file_off + cur_offset,
							library_ordinal: cur_library_ordinal,
							addend: cur_addend,
							trailing_flags: cur_trailing_flags,
							sym_type: cur_type,
							sym_name: cur_name.to_string()
						});
						cur_offset += USIZE_LEN;

						if instr >= 0xb0 {
							// should this be times USIZE_LEN instead? Or just * 4?
							cur_offset += (instr & 0x0f) as usize * USIZE_LEN;
						} else if instr >= 0xa0 {
							let (offset, increase) = MachHook::read_uleb128(&bind_data[idx..]);
							cur_offset += offset;
							idx += increase;
						}
					},
					// DO_BIND_ULEB_TIMES_SKIPPING_ULEB
					0xc0 => {
						let (sym_count, increase) = MachHook::read_uleb128(&bind_data[idx..]);
						idx += increase;
						let (bytes_skip, increase) = MachHook::read_uleb128(&bind_data[idx..]);
						idx += increase;

						let Some(seg_file_off) = self.commands.iter()
							.filter_map(|cmd| match cmd.0 {
								LoadCommand::Segment { fileoff, .. }
								| LoadCommand::Segment64 { fileoff, .. } => Some(fileoff),
								_ => None
							})
							.nth(cur_seg_idx as usize) else {
								println!("Invalid segment index {} for binding '{}'", cur_seg_idx, cur_name);
								continue;
							};

						for _ in 0..sym_count {
							self.bindings.push(Binding {
								file_offset: seg_file_off + cur_offset,
								library_ordinal: cur_library_ordinal,
								addend: cur_addend,
								trailing_flags: cur_trailing_flags,
								sym_type: cur_type,
								sym_name: cur_name.to_string()
							});
							cur_offset += USIZE_LEN + bytes_skip;
						}
					},
					_ => println!("Cannot handle instr {instr:x} at {idx:x}"),
				}
			}
		}

		let handle = unsafe { libc::dlopen(std::ptr::null(), 0) };
		for binding in &self.bindings {
			if binding.sym_type != 1 {
				println!("sym_type for '{}' is {}, don't know how to handle", binding.sym_name, binding.sym_type);
				continue;
			}

			macro_rules! cntn{
				($err:expr$(, $arg:expr)*) => {
					println!($err$(, $arg)*);
					continue;
				}
			}

			let sym_addr = match binding.library_ordinal {
				// SELF | MAIN_EXECUTABLE
				// I don't get what the difference is
				0 | -1 => {
					let Some(ptr) = self.get_symbol_ptr(binding.sym_name.as_str()) else {
						cntn!("Can't get ptr to symbol '{}' in ordinal {}", binding.sym_name, binding.library_ordinal);
					};

					ptr as usize
				},
				-2 | 1.. => {
					// normally, a value from 1.. means that it's from an external library with the
					// ordinal given, but sometimes they're libc functions, so we just check to see
					// if it's loaded in just in case
					let Ok(c_name) = CString::new(&binding.sym_name[1..]) else {
						cntn!("Name '{}' has null character in it, can't dlsym", binding.sym_name);
					};
					unsafe { libc::dlsym(handle, c_name.as_ptr()) as *const () as usize }
				},
				_ => {
					cntn!("Invalid library_ordinal ({}) for '{}'", binding.library_ordinal, binding.sym_name);
				}
			};

			let write_to = binding.file_offset;

			if sym_addr == 0 {
				cntn!("Got null ptr for {} with ordinal {} (should've been written to {write_to:x}, addend {})", &binding.sym_name[1..], binding.library_ordinal, binding.addend);
			}

			println!("Successfully bound {} ({sym_addr:x} at {write_to:x})", binding.sym_name);

			// I don't know how to handle the addend and trailing flags, so we're just ignoring
			// that for now
			Self::write_ptr_to_mem(self.mmap.as_mut(), write_to, sym_addr);
		}

		// there's gotta be a dysymtab; we would've failed much earlier if there wasn't
		let indirectoff = self.commands.iter()
			.find_map(|cmd| match cmd.0 {
				LoadCommand::DySymTab { indirectsymoff, .. } => Some(indirectsymoff),
				_ => None
			}).unwrap();

		symbols!(symbols, self);
		let symbols = symbols.collect::<Vec<_>>();

		let lazy_sec = self.sections.iter()
			.find(|sec| (sec.segname == SEG_DATA || sec.segname == "__DATA_CONST") && sec.sectname == "__la_symbol_ptr");
		if let Some(sec) = lazy_sec {

			// maybe USIZE_LEN should just be 4 here?
			for idx in 0..(sec.size / USIZE_LEN) {
				// each one of these is an index into the indirect symbol table
				let sym_idx_loc = indirectoff as usize + ((idx + sec.reserved1 as usize) * 4);
				let sym_idx = u32::from_le_bytes(self.mmap.as_ref()[sym_idx_loc..][..4].try_into().unwrap());
				// let sym_idx = (indir_sym_idx + sec.reserved1) as usize;
				let bind_loc = sec.offset as usize + (idx * USIZE_LEN);

				let Some(sym) = symbols.get(sym_idx as usize) else {
					println!("Couldn't get sym at idx {sym_idx} (lazy at {bind_loc:x})");
					continue;
				};

				let Some(sym_name) = sym.name() else {
					println!("symbol at idx {sym_idx} has no name (lazy at {bind_loc:x})");
					continue;
				};

				self.bindings.push(Binding {
					file_offset: bind_loc,
					addend: 0,
					// flat_lookup ordinal
					library_ordinal: -2,
					trailing_flags: 0,
					sym_type: 1,
					sym_name: sym_name.to_owned() 
				});
			}
		}
	}

	fn do_const_relocs(&mut self) {
		// Now we need to go through every address in __DATA/__const and relocate it to the current
		// executing address. I think. I cannot find any documentation about this anywhere so I'm
		// just guessing
		let mut relocs: Vec<_> = self.sections.iter()
			.find(|sec| (sec.segname == SEG_DATA || sec.segname == "__DATA_CONST") && sec.sectname == "__const")
			.map(|sec| (0..sec.size)
				 .map(|byte| sec.offset as usize + (byte * USIZE_LEN))
				 .collect()
			).unwrap_or_default();

		let objc_const = self.sections.iter()
			.find(|sec| (sec.segname == SEG_DATA || sec.segname == "__DATA_CONST") && sec.sectname == "__objc_const");

		// and then we need to go through everything in __objc_const and relocate them as an array
		// of structs that start with a u32 (flags) and a u32 (length), then have a set amount of
		// entries according to the flags and length.
		if let Some(sec) = objc_const {
			// flags values:
			// - 0x20: It's 3 pointers, then flags (u64) - normally flags are 0x0000000800000003
			// - 0x1b: It's 3 pointers (probably like name, location, signature or something)
			// - 0x18: Also 3 pointers, last is normally nil
			// - 0x10: It's 2 pointers
			// - 0x01: It's 2 pointers, normally the second one is nil? Also length is always 0,
			//		   and there's always just 1 pointer
			// - 0x00: who fucking knows. seems there's a length in the next u32, then the same
			//		   length stored in the next u64, and then after that the pointers start, and
			//		   most of them seem to be nil.
			//
			// if flags > 0xff, it's just a single normal pointer to relocate I think
			// Also, maybe if the length is same as the first u64, then the length is actually 8 +
			// flags???
			let const_start = sec.offset as usize;
			let const_sec = &self.mmap.as_ref()[const_start..][..sec.size];
			let mut idx = 0;
			// so. I don't understand this whole section. It just works this way, as far as I can
			// tell in this file. Yeah
			relocs.extend(std::iter::from_fn(move || {
				if idx >= sec.size {
					return None;
				}

				let flags = u32::from_le_bytes(const_sec[idx..][..4].try_into().unwrap());
				if flags > 0xff {
					idx += USIZE_LEN;
					return Some(vec![const_start + idx - USIZE_LEN]);
				}

				idx += 4;
				let length = u32::from_le_bytes(const_sec[idx..][..4].try_into().unwrap()) as usize;
				idx += 4;
				let first_ptr = usize::from_le_bytes(const_sec[idx..][..USIZE_LEN].try_into().unwrap());

				if flags == 0x20 {
					let ptr_sec_size = 4 * USIZE_LEN;
					let total_size = ptr_sec_size * length;
					let res = (0..length).map(|sec| sec * 4 * USIZE_LEN).flat_map(|ptr_sec_loc|
						// we ignore the last ptr in this section; it seems to be like flags, but I
						// don't know how to handle it
						(0..3).map(move |loc| const_start + idx + ptr_sec_loc + (loc * USIZE_LEN))
					).collect();
					idx += total_size;
					return Some(res);
				}

				let ptr_sec_start = idx - 8;
				let total_size = match flags {
					// if this is the case, we just always do 8 for some reason
					_ if length == first_ptr => 8,
					// these are normally divided into `length` sections of 3 ptrs, but they all
					// need to be relocated, so we just handle them all individually
					0x1b | 0x18  => 3 * length,
					// these are normally divided into `length` sections of 2 ptr, but same thing
					// as before - all need to be relocated
					0x10 => 2 * length,
					// it seems there's just two pointers here, and length is irrelevant. Normally
					// the second ptr is nil
					0x01 => 2,
					// Normally, when it's 0x00, the length == first_ptr, so we just go by the
					// length as a number of ptrs
					0x00 => length,
					_ => {
						println!("Don't know how to handle reloc case where flags is {flags:x} and length is {length:x} at idx {ptr_sec_start:x}");
						// we need to return some here so that it doesn't stop iterating
						return Some(vec![]);
					}
				};

				let res = (0..total_size).map(|off| const_start + idx + (off * USIZE_LEN)).collect();
				idx += total_size * USIZE_LEN;
				Some(res)
			}).flatten());
		}

		let auth_const = self.sections.iter()
			.find(|sec| sec.segname == "__AUTH_CONST" && sec.sectname == "__objc_const");

		if let Some(sec) = auth_const {
			let const_start = sec.offset as usize;
			let sec_data = &self.mmap.as_ref()[const_start..][..sec.size];
			let mut idx = 0;
			relocs.extend(std::iter::from_fn(|| {
				if idx >= sec.size { return None; }

				let flags = u32::from_le_bytes(sec_data[idx..][..4].try_into().unwrap());
				let res: Vec<_> = if flags > 0xff {
					(0..6).map(|off| const_start + idx + (off * USIZE_LEN)).collect()
				} else {
					idx += USIZE_LEN;
					(1..8).map(|off| const_start + idx + (off * USIZE_LEN)).collect()
				};
				idx += 8 * USIZE_LEN;
				Some(res)
			}).flatten());
		}

		for reloc_at in relocs {
			let mut ptr = usize::from_le_bytes(self.mmap.as_ref()[reloc_at..][..USIZE_LEN].try_into().unwrap());

			if USIZE_LEN == 8 {
				// clear out the top 16 bits 'cause they're only used for pac stuff and can make
				// stuff confusing when we're just working with raw pointers
				ptr &= 0x0000ffffffffffffusize;
			}
			if ptr == 0 { continue; }

			let Some(sec) = self.sections.iter()
				.find(|sec| ptr > sec.addr && ptr < sec.addr + sec.size) else {
					// println!("Couldn't find section to fit ptr at {ptr:x}");
					continue;
				};

			// find its offset from the beginning of the section, offset that from where the
			// section is offset from the beginning of the file, and offset that from the beginning
			// of the memmap.
			let real_addr = (ptr - sec.addr) + sec.offset as usize + self.mmap.as_ptr() as usize;
			self.mmap.as_mut()[reloc_at..][..USIZE_LEN].copy_from_slice(&real_addr.to_le_bytes());
		}
	}

	fn load_addr(&self) -> usize {
		self.commands.iter()
			.find_map(|cmd| match cmd.0 {
				LoadCommand::Segment { vmaddr, .. }
				| LoadCommand::Segment64 { vmaddr, .. } => Some(vmaddr),
				_ => None
			}).unwrap()
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
			// If we can't find it in the symbol table, try to pull it out of our binding map
			.or_else(||
				self.bindings.iter()
					.filter(|b| b.sym_name == symbol_name)
					.map(|b| {
						let ptr_bytes = &self.mmap.as_ref()[b.file_offset..][..USIZE_LEN];
						let ptr = usize::from_le_bytes(ptr_bytes.try_into().unwrap());
						(ptr as isize).saturating_sub(b.addend)
					})
					.find(|&ptr| ptr != 0)
					.map(|p| p as *const ())
			)
	}

	// uhhh if you are using a library extracted from dyld, these won't work. They're weird. I'll
	// figure it out later
	pub fn get_objc_method_ptr(&self, class: &str, method: &str) -> Option<*const ()> {
		fn string_at_ptr_eq(mem: &[u8], ptr: usize, s: &str) -> bool {
			let Ok(Ok(cstr)) = CStr::from_bytes_until_nul(&mem[ptr..]).map(|cstr| cstr.to_str()) else {
				return false;
			};
			cstr == s
		}

		let (offset, size) = self.sections.iter()
			.find(|s| s.segname == "__DATA_CONST" && s.sectname == "__objc_classlist")
			.map(|s| (s.offset, s.size))?;

		let data = self.mmap.as_ref();

		// why do we have to relocate everything by this? who knows
		let reloc = 0x00010000000000000;

		let class_list = &data[offset as usize..][..size];

		for class_ptr_chunk in class_list.chunks(USIZE_LEN) {
			// the ptr to the objc_class object
			let class_ptr = usize::from_le_bytes(class_ptr_chunk.try_into().unwrap());
			// the ptr to the objc_metaclass object
			let Some(metaclass_ptr) = self.get_ptr_at_offset(class_ptr - reloc) else {
				println!("couldn't get metaclass ptr at {:x} ({class_ptr:x} - {reloc:x})", class_ptr - reloc);
				continue;
			};
			// the ptr to the objc_metaclass_data object
			let data_ptr_loc = metaclass_ptr + (USIZE_LEN * 4) - reloc;
			let Some(data_ptr) = self.get_ptr_at_offset(data_ptr_loc) else {
				println!("couldn't get data ptr at {}", data_ptr_loc);
				continue;
			};
			// the ptr to the name of the class
			let name_ptr_loc = data_ptr + 16 + USIZE_LEN - reloc;
			let Some(name_ptr) = self.get_ptr_at_offset(name_ptr_loc) else {
				println!("couldn't get name_ptr at {name_ptr_loc:x}",);
				continue;
			};
			// if the name doesn't equal, continue
			if !string_at_ptr_eq(data, name_ptr % reloc, class) {
				continue;
			}

			// get the pointer to the method list
			let method_list_loc = name_ptr_loc + USIZE_LEN;
			let Some(method_list_ptr) = self.get_ptr_at_offset(method_list_loc) else {
				println!("Couldn't get method list ptr at {method_list_loc:x}");
				continue;
			};

			// grab the data at the method list;
			let method_list_ptr = method_list_ptr % reloc;
			let flags = u32::from_le_bytes(data[method_list_ptr..][..4].try_into().unwrap());
			let num_methods = u32::from_le_bytes(data[method_list_ptr + 4..][..4].try_into().unwrap());
			let mmap_start = self.mmap.as_ptr() as usize;

			// if it's a relative method list
			if flags & 0x80000000 != 0 {
				let method_len = 12;
				let method_list = &data[method_list_ptr + 8..][..num_methods as usize * method_len];

				for (idx, method_data) in method_list.chunks(method_len).enumerate() {
					// get the address this method starts at
					let start_ptr = (idx * method_len) + method_list_ptr + 8;
					// get the pointer to the pointer to the name
					let name_ptr_ptr = u32::from_le_bytes(method_data[..4].try_into().unwrap()) as usize + start_ptr;

					// get the pointer to the name from the pointer to the pointer
					let Some(name_ptr) = self.get_ptr_at_offset(name_ptr_ptr) else {
						println!("Couldn't get name for method idx {idx} at {name_ptr_ptr:x}");
						continue;
					};

					// if it's the right method...
					if string_at_ptr_eq(data, name_ptr % reloc, method) {
						// grab the offset to the implementation
						let offset = u32::from_le_bytes(method_data[8..].try_into().unwrap());
						// offset it, including the offset of the offset from the start_ptr
						// also we have to offset it from 0x100000000, 'cause everything in this
						// binary thinks it's offset by that? I don't get it
						return Some((offset as usize + start_ptr + 8 - 0x100000000 + mmap_start) as *const ());
					}
				}
			} else {
				// otherwise, if it's a normal method list
				let method_len = 3 * USIZE_LEN;
				let method_list = &data[method_list_ptr + 8..][..num_methods as usize * method_len];

				for method_data in method_list.chunks(method_len) {
					// get the pointer to the name
					let name_ptr = usize::from_le_bytes(method_data[..USIZE_LEN].try_into().unwrap()) % reloc;

					// if it's correct, grab the pointer to the implementation and return it
					if string_at_ptr_eq(data, name_ptr, method) {
						let ptr = usize::from_le_bytes(method_data[USIZE_LEN * 2..].try_into().unwrap());
						return Some(((ptr % reloc) + mmap_start) as *const ())
					}
				}
			}
		}

		None
	}

	pub fn make_exec(&self) -> region::Result<()> {
		unsafe {
			region::protect(self.mmap.as_ptr(), self.mmap.len(), region::Protection::READ_EXECUTE)
		}
	}

	pub fn make_writeable(&self) -> region::Result<()> {
		unsafe {
			region::protect(self.mmap.as_ptr(), self.mmap.len(), region::Protection::READ_WRITE)
		}
	}

	pub fn get_ptr_at_offset(&self, offset: usize) -> Option<usize> {
		let data = self.mmap.as_ref();
		if offset > data.len() {
			return None;
		}
		let chunk = self.mmap.as_ref()[offset..][..USIZE_LEN].try_into().unwrap();
		Some(usize::from_le_bytes(chunk))
	}

	pub fn write_ptr_to(&mut self, write_to: usize, ptr: usize) {
		Self::write_ptr_to_mem(self.mmap.as_mut(), write_to, ptr);
	}

	fn write_ptr_to_mem(mem: &mut [u8], write_to: usize, ptr: usize) {
		let loc = &mut mem[write_to..][..USIZE_LEN];
		let ptr = ptr.to_le_bytes();
		loc.copy_from_slice(&ptr);
	}

	// substitution must be a pointer to a sysv64 calling convention function
	pub fn hook_fn<'s>(
		&mut self, symbol_name: &'s str, substitution: *const ()
	) -> Result<*const (), SymbolNotFound<'s>> {
		symbols!(symbols, self);

		let mut ret = Err(SymbolNotFound(symbol_name));

		if let Some(symbol) = symbols.position(|s| s.name() == Some(symbol_name)) {

			let is_64bit = self.header.is_64bit();
			let sym_size = if is_64bit { 16 } else { 12 };
			let start = self.sym_info.symoff as usize + (symbol * sym_size);
			let sym_data = &mut self.mmap.as_mut()[start..start + sym_size];

			let flags = sym_data[4];
			const N_TYPE: u8 = 0x03;
			const N_ABS: u8 = 0x2;

			// Make it an absolute symbol
			sym_data[4] = (flags & !N_TYPE) | N_ABS;

			// Overwrite the 'value' of the symbol to make it the address of the intended function
			ret = Ok(usize::from_le_bytes(sym_data[8..].try_into().unwrap()) as *const ());
			let ptr = (substitution as usize).to_le_bytes();
			sym_data[8..].copy_from_slice(&ptr);

			println!("overwrote symbol information for {symbol_name} at idx {symbol} to {substitution:?}");
		}

		for bind in self.bindings.iter().filter(|b| b.sym_name == symbol_name) {
			let real_addr = ((substitution as isize) + bind.addend) as usize;
			self.mmap[bind.file_offset..][..USIZE_LEN].copy_from_slice(&real_addr.to_le_bytes());

			ret = Ok(bind.file_offset as *const ());

			println!("overwrote pointer to {symbol_name} at offset {:x} (addr {:x}) to {:x}", bind.file_offset, self.mmap.as_ptr() as usize + bind.file_offset, real_addr);
		}

		ret
	}

	#[sysv64]
	pub unsafe fn dlopen(name: *const libc::c_char) -> *mut libc::c_void {
		#[cfg_attr(not(target_family = "windows"), allow(unused_mut))]
		let mut path_str = CStr::from_ptr(name).to_str().unwrap();

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
		let symbol = CStr::from_ptr(symbol).to_str().unwrap();
		match hook.as_ref().and_then(|lib| lib.get_symbol_ptr(symbol)) {
			Some(func) => func as *mut libc::c_void,
			None => std::ptr::null_mut(),
		}
	}

	#[sysv64]
	pub unsafe fn dlclose(library: *mut MachHook) {
		let _ = Box::from_raw(library);
	}

	// https://opensource.apple.com/source/dyld/dyld-195.6/src/ImageLoaderMachOCompressed.cpp.auto.html
	pub fn read_uleb128(data: &[u8]) -> (usize, usize) {
		data.iter()
			.take(9)
			.take_while(|&byte| byte & 0x80 != 0)
			// then we chain the last element which doesn't have the continuation bit but is still
			// within the bounds of the uleb
			.chain(data.iter().take(10).find(|b| **b < 0x80))
			.enumerate()
			.fold((0, 0), |(res, _), (bit, &byte)|
				  (res | ((byte as usize & 0x7f) << (bit * 7)), bit + 1)
			)
	}

	pub fn read_sleb128(data: &[u8]) -> (isize, usize) {
		let (ures, increase) = Self::read_uleb128(data);
		let mut res = ures as isize;
		let shift = increase * 7;
		if res & 1 << (shift - 1) != 0 {
			res |= !0 << shift;
		}
		(res, increase)
	}
}

pub static NDR_RECORD: usize = 0x100000000;

pub extern "C" fn nsversion_of_run_time_library(_lib: *const libc::c_char) -> i32 {
	// maybe?
	0x4e40000
}

pub extern "C" fn mach_msg_stub(_msg: *const libc::c_void, _option: i32, _send_size: i32, _rcv_size: i32, _rcv_name: i32, _timeout: i32, _notify: i32) -> i32 {
	0
}

pub extern "C" fn noop_stub() {}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub extern "C" fn noop_ret_0() -> i32 {
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



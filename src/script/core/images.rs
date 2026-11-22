use super::*;
use crate::modules::{self, Instance, Layout};
use crate::symbols::{self, DebugFile, Line, Search};
use std::{path::PathBuf, sync::Arc};

const MAX_SHARED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SHARED_IMAGES: usize = 32;

#[derive(Default)]
pub(super) struct SharedImages {
    bytes: u64,
    images: BTreeMap<PathBuf, Option<Arc<SharedImage>>>,
}

pub(super) struct SharedImage {
    unwind: OfflineImage,
    debug: Option<DebugFile>,
    layout: Layout,
}

pub(super) enum Image<'a> {
    Main(&'a OfflineImage),
    Shared(Arc<SharedImage>, Instance),
}

impl Image<'_> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Main(image) => image.bytes(),
            Self::Shared(image, _) => image.unwind.bytes(),
        }
    }

    pub fn bias(&self) -> i128 {
        match self {
            Self::Main(image) => i128::from(image.bias()),
            Self::Shared(_, instance) => instance.bias,
        }
    }

    pub fn link(&self, address: u64) -> Option<u64> {
        u64::try_from(i128::from(address) - self.bias()).ok()
    }

    pub fn runtime(&self, link: u64) -> Option<u64> {
        u64::try_from(i128::from(link) + self.bias()).ok()
    }

    pub fn debug<'a>(&'a self, target: &'a Target) -> Option<&'a DebugFile> {
        match self {
            Self::Main(_) => target.debug_image.as_ref(),
            Self::Shared(image, _) => image.debug.as_ref(),
        }
    }

    pub fn line(&self, target: &Target, link: u64) -> Result<Option<Line>> {
        if matches!(self, Self::Main(_))
            && let Some(dwarf) = &target.dwarf
            && let Some(line) = dwarf.line(link)?
        {
            return Ok(Some(line));
        }
        if let Self::Shared(image, _) = self
            && let Some(debug) = &image.debug
            && let Some(line) = symbols::dwarf_line(&object::File::parse(&*debug.bytes)?, link)?
        {
            return Ok(Some(line));
        }
        symbols::dwarf_line(&object::File::parse(self.bytes())?, link)
    }
}

impl AsRef<OfflineImage> for Image<'_> {
    fn as_ref(&self) -> &OfflineImage {
        match self {
            Self::Main(image) => image,
            Self::Shared(image, _) => &image.unwind,
        }
    }
}

impl Target {
    pub(super) fn mapped_file(&self, address: u64) -> Option<(&Module, &Mapping)> {
        self.file_modules
            .iter()
            .find_map(|module| module.mapping_at(address).map(|mapping| (module, mapping)))
    }

    fn shared_image(&self, module: &Module) -> Option<Arc<SharedImage>> {
        if !self.use_recorded_symbols {
            return None;
        }
        let path = module.path();
        if !path.is_absolute() {
            return None;
        }
        let mut cache = self.shared_images.lock().ok()?;
        if let Some(image) = cache.images.get(&path) {
            return image.clone();
        }
        if cache.images.len() == MAX_SHARED_IMAGES {
            return None;
        }
        let limit = MAX_SHARED_BYTES - cache.bytes;
        let image = self
            .load_shared_image(module, &path, limit)
            .ok()
            .map(Arc::new);
        if let Some(image) = &image {
            cache.bytes += image.unwind.bytes().len() as u64;
            cache.bytes += image
                .debug
                .as_ref()
                .map_or(0, |debug| debug.bytes.len() as u64);
        }
        cache.images.insert(path, image.clone());
        image
    }

    fn load_shared_image(&self, module: &Module, path: &Path, limit: u64) -> Result<SharedImage> {
        let bytes = read_image_bytes(path, limit)?;
        let object = object::File::parse(&*bytes)?;
        let architecture = match self.architecture {
            "x86_64" => object::Architecture::X86_64,
            _ => object::Architecture::Aarch64,
        };
        if object.architecture() != architecture
            || !object.is_little_endian()
            || !modules::is_executable_module(&object)
        {
            return Err(error("incompatible ELF module"));
        }
        let mut layout = Layout::from_segments(
            modules::load_segments(&object).collect(),
            module,
            self.file_page,
        )?;
        let note = object
            .section_by_name(".note.gnu.build-id")
            .filter(|note| note.address() != 0)
            .ok_or_else(|| error("module has no mapped GNU build ID"))?;
        let expected = note.data()?;
        if expected.is_empty() || expected.len() > 4096 {
            return Err(error("invalid module GNU build ID note length"));
        }
        let mut observed = vec![0; expected.len()];
        layout.instances.retain(|instance| {
            instance.relocate(note.address()).is_some_and(|address| {
                self.read_at(address, &mut observed).is_ok() && observed == expected
            })
        });
        if layout.instances.is_empty() {
            return Err(error("no module mapping has a matching captured build ID"));
        }
        let debug = (!object.has_debug_symbols())
            .then(|| symbols::find_external_debug(None, path, &object, limit - bytes.len() as u64))
            .flatten()
            .map(|(path, bytes)| DebugFile { path, bytes });
        Ok(SharedImage {
            unwind: OfflineImage::new(bytes, 0)?,
            debug,
            layout,
        })
    }

    pub(super) fn image_at(&self, address: u64) -> Option<Image<'_>> {
        if let Some(image) = &self.image
            && let Some(link) = address.checked_sub(image.bias())
            && let Ok(object) = object::File::parse(image.bytes())
            && object.segments().any(|segment| {
                link.checked_sub(segment.address())
                    .is_some_and(|offset| offset < segment.size())
            })
        {
            return Some(Image::Main(image));
        }
        let (module, map) = self.mapped_file(address)?;
        let image = self.shared_image(module)?;
        let (instance, _) = image.layout.for_address(map, address)?;
        Some(Image::Shared(image, instance))
    }

    pub fn symbols(&self, request: &crate::rpc::SearchSymbolsRequest) -> Result<Value> {
        use std::os::unix::ffi::OsStrExt;
        let limit = request.limit.unwrap_or(256);
        symbols::validate_search(request)?;
        let main_module = self
            .entry
            .and_then(|entry| self.mapped_file(entry).map(|(module, _)| module));
        let mut search = Search::default();
        if let Some(image) = &self.image {
            let backing = Module {
                backing: Backing {
                    major: 0,
                    minor: 0,
                    inode: 0,
                    path: self
                        .executable
                        .as_ref()
                        .unwrap()
                        .path
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                },
                maps: Vec::new(),
            };
            let object = object::File::parse(image.bytes())?;
            search.merge(
                symbols::search_core(
                    &object,
                    self.debug_image.as_ref(),
                    i128::from(image.bias()),
                    main_module.unwrap_or(&backing),
                    request,
                )?,
                limit as usize,
            );
        }
        let mut unavailable = 0;
        for module in &self.file_modules {
            if main_module.is_some_and(|main| std::ptr::eq(main, module)) && self.image.is_some() {
                continue;
            }
            if request.module.as_deref().is_some_and(|filter| {
                !symbols::path_matches(module, filter) && !symbols::may_be_build_id(filter)
            }) {
                continue;
            }
            let Some(image) = self.shared_image(module) else {
                unavailable += 1;
                continue;
            };
            let object = object::File::parse(image.unwind.bytes())?;
            for instance in &image.layout.instances {
                search.merge(
                    symbols::search_core(
                        &object,
                        image.debug.as_ref(),
                        instance.bias,
                        module,
                        request,
                    )?,
                    limit as usize,
                );
            }
        }
        let mut warnings = self.warnings.clone();
        if unavailable > 0 {
            warnings.push(Diagnostic::new(
                "SYMBOL_IMAGES_UNAVAILABLE",
                format!("{unavailable} mapped files had no verified searchable image"),
                None,
            ));
        }
        let mut value = serde_json::to_value(search)?;
        value["warnings"] = json!(warnings);
        Ok(value)
    }
}

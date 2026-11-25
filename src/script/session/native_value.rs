use rquickjs::{
    Atom, BigInt, Class, Ctx, Error, Function, IntoJs, JsLifetime, Object, Result, TypedArray,
    Value,
    class::{ClassKind, JsCell, JsClass, Readable, Trace, Tracer, Writable},
    function::Constructor,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Address,
    Bytes,
    Root,
    Tid,
    InheritTid,
    Parent,
    SelfType,
    Type,
    Info,
    Value,
    TerminatedElement,
    ReadBytes,
    WriteBytes,
    Read,
    Inline,
}

const PRIVATE_SLOTS: [(Slot, &str); 15] = [
    (Slot::Address, "address"),
    (Slot::Bytes, "bytes"),
    (Slot::Root, "root"),
    (Slot::Tid, "tid"),
    (Slot::InheritTid, "inheritTid"),
    (Slot::Parent, "parent"),
    (Slot::SelfType, "self"),
    (Slot::Type, "type"),
    (Slot::Info, "info"),
    (Slot::Value, "value"),
    (Slot::TerminatedElement, "terminatedElement"),
    (Slot::ReadBytes, "readBytesMethod"),
    (Slot::WriteBytes, "writeBytesMethod"),
    (Slot::Read, "readMethod"),
    (Slot::Inline, "inline"),
];

enum Backing {
    Target { address: u64, root: u64 },
    Inline { bytes: [u8; 8], len: usize },
}

const PUBLIC_SLOTS: [(Slot, &str); 5] = [
    (Slot::Type, "$type"),
    (Slot::Parent, "$parent"),
    (Slot::Read, "$read"),
    (Slot::ReadBytes, "$readBytes"),
    (Slot::WriteBytes, "$writeBytes"),
];

struct CompactKeys<'js> {
    atoms: Vec<Atom<'js>>,
    public_slots: Vec<(Slot, Atom<'js>)>,
    hooks: Object<'js>,
}

unsafe impl<'js> JsLifetime<'js> for CompactKeys<'js> {
    type Changed<'to> = CompactKeys<'to>;
}

impl<'js> Trace<'js> for CompactKeys<'js> {
    fn trace<'a>(&self, tracer: Tracer<'a, 'js>) {
        for atom in &self.atoms {
            atom.trace(tracer);
        }
        for (_, atom) in &self.public_slots {
            atom.trace(tracer);
        }
        self.hooks.trace(tracer);
    }
}

impl<'js> JsClass<'js> for CompactKeys<'js> {
    const NAME: &'static str = "CompactValueKeys";
    type Mutable = Readable;

    fn constructor(_: &Ctx<'js>) -> Result<Option<Constructor<'js>>> {
        Ok(None)
    }
}

pub(super) struct CompactValue<'js> {
    backing: Backing,
    tid: f64,
    has_tid: bool,
    inherit_tid: bool,
    type_descriptor: Value<'js>,
    info: Value<'js>,
    keys: Class<'js, CompactKeys<'js>>,
    extra: Box<[(Slot, Value<'js>)]>,
}

unsafe impl<'js> JsLifetime<'js> for CompactValue<'js> {
    type Changed<'to> = CompactValue<'to>;
}

impl<'js> Trace<'js> for CompactValue<'js> {
    fn trace<'a>(&self, tracer: Tracer<'a, 'js>) {
        self.type_descriptor.trace(tracer);
        self.info.trace(tracer);
        self.keys.trace(tracer);
        for (_, value) in &self.extra {
            value.trace(tracer);
        }
    }
}

impl<'js> CompactValue<'js> {
    fn slot(&self, key: &Atom<'js>) -> Option<Slot> {
        self.keys
            .borrow()
            .atoms
            .iter()
            .position(|atom| atom == key)
            .map(|index| PRIVATE_SLOTS[index].0)
    }

    fn extra_value(&self, slot: Slot) -> Option<&Value<'js>> {
        self.extra
            .iter()
            .find(|(key, _)| *key == slot)
            .map(|(_, value)| value)
    }

    fn cache_method(&mut self, slot: Slot, value: Value<'js>) {
        if let Some((_, cached)) = self.extra.iter_mut().find(|(key, _)| *key == slot) {
            *cached = value;
        } else {
            let mut extra = std::mem::take(&mut self.extra).into_vec();
            extra.reserve_exact(1);
            extra.push((slot, value));
            self.extra = extra.into_boxed_slice();
        }
    }

    fn get_slot(&self, ctx: &Ctx<'js>, slot: Slot, receiver: Value<'js>) -> Result<Value<'js>> {
        let value = match slot {
            Slot::Address => match self.backing {
                Backing::Target { address, .. } => {
                    Some(BigInt::from_u64(ctx.clone(), address)?.into_value())
                }
                Backing::Inline { .. } => None,
            },
            Slot::Bytes => match self.backing {
                Backing::Inline { bytes, len } => {
                    Some(TypedArray::<u8>::new_copy(ctx.clone(), &bytes[..len])?.into_value())
                }
                Backing::Target { .. } => None,
            },
            Slot::Root => match self.backing {
                Backing::Target { root, .. } => Some(root.into_js(ctx)?),
                Backing::Inline { .. } => None,
            },
            Slot::Tid if self.has_tid => Some(self.tid.into_js(ctx)?),
            Slot::Tid => None,
            Slot::InheritTid => Some(Value::new_bool(ctx.clone(), self.inherit_tid)),
            Slot::Type => Some(self.type_descriptor.clone()),
            Slot::Info => Some(self.info.clone()),
            Slot::Value => Some(receiver),
            Slot::Inline => Some(Value::new_bool(
                ctx.clone(),
                matches!(self.backing, Backing::Inline { .. }),
            )),
            Slot::Parent
            | Slot::SelfType
            | Slot::TerminatedElement
            | Slot::ReadBytes
            | Slot::WriteBytes
            | Slot::Read => self.extra_value(slot).cloned(),
        };
        Ok(value.unwrap_or_else(|| Value::new_undefined(ctx.clone())))
    }
}

impl<'js> JsClass<'js> for CompactValue<'js> {
    const NAME: &'static str = "CompactValue";
    const KIND: ClassKind = ClassKind::Exotic;
    type Mutable = Writable;

    fn prototype(_: &Ctx<'js>) -> Result<Option<Object<'js>>> {
        Ok(None)
    }

    fn constructor(_: &Ctx<'js>) -> Result<Option<Constructor<'js>>> {
        Ok(None)
    }

    fn exotic_get_property(
        this: &JsCell<'js, Self>,
        ctx: &Ctx<'js>,
        key: Atom<'js>,
        receiver: Value<'js>,
    ) -> Result<Value<'js>> {
        let hooks = {
            let state = this.borrow();
            if let Some(slot) = state.slot(&key) {
                return state.get_slot(ctx, slot, receiver);
            }
            let keys = state.keys.borrow();
            if let Some((slot, _)) = keys.public_slots.iter().find(|(_, atom)| *atom == key) {
                match slot {
                    Slot::Type | Slot::Parent => return state.get_slot(ctx, *slot, receiver),
                    _ => {
                        if let Some(method) = state.extra_value(*slot) {
                            return Ok(method.clone());
                        }
                    }
                }
            }
            keys.hooks.clone()
        };
        hooks
            .get::<_, Function>("get")?
            .call((receiver, key.to_value()?))
    }

    fn exotic_set_property(
        this: &JsCell<'js, Self>,
        ctx: &Ctx<'js>,
        key: Atom<'js>,
        receiver: Value<'js>,
        value: Value<'js>,
    ) -> Result<bool> {
        retain_set_argument(ctx, &value);
        let slot = this.borrow().slot(&key);
        if let Some(slot) = slot {
            let mut state = this.borrow_mut();
            match slot {
                Slot::Tid => {
                    let tid = value.as_number();
                    state.tid = tid.unwrap_or_default();
                    state.has_tid = tid.is_some();
                }
                Slot::InheritTid => state.inherit_tid = value.as_bool().unwrap_or(false),
                Slot::Bytes => {
                    let typed = TypedArray::<u8>::from_value(value)?;
                    let data = typed.as_bytes().ok_or(Error::Unknown)?;
                    if let Backing::Inline { bytes, len } = &mut state.backing {
                        if data.len() != *len {
                            return Err(Error::Unknown);
                        }
                        bytes[..*len].copy_from_slice(data);
                    }
                }
                Slot::ReadBytes | Slot::WriteBytes | Slot::Read => {
                    state.cache_method(slot, value);
                }
                _ => return Ok(false),
            }
            return Ok(true);
        }
        let hooks = this.borrow().keys.borrow().hooks.clone();
        hooks
            .get::<_, Function>("set")?
            .call((receiver, key.to_value()?, value))
    }

    fn exotic_delete_property(_: &JsCell<'js, Self>, _: &Ctx<'js>, _: Atom<'js>) -> Result<bool> {
        Ok(true)
    }
}

fn retain_set_argument(ctx: &Ctx<'_>, value: &Value<'_>) {
    // QuickJS frees the setter argument after the callback, but the rquickjs
    // 0.12.2 trampoline wraps it as an owned Value and drops it too.
    // Supply the trampoline's reference here. Recheck this on dependency upgrades.
    unsafe { rquickjs::qjs::JS_DupValue(ctx.as_raw().as_ptr(), value.as_raw()) };
}

pub(super) fn install<'js>(ctx: &Ctx<'js>, api: &Object<'js>) -> Result<()> {
    let symbols: Object = api.get("nativeValueKeys")?;
    let atoms = PRIVATE_SLOTS
        .into_iter()
        .map(|(_, name)| Atom::from_value(ctx.clone(), &symbols.get(name)?))
        .collect::<Result<Vec<_>>>()?;
    let public_slots = PUBLIC_SLOTS
        .into_iter()
        .map(|(slot, name)| Ok((slot, Atom::from_str(ctx.clone(), name)?)))
        .collect::<Result<Vec<_>>>()?;
    let keys = Class::instance(
        ctx.clone(),
        CompactKeys {
            atoms,
            public_slots,
            hooks: api.get("nativeValueHooks")?,
        },
    )?;
    let create = Function::new(
        ctx.clone(),
        |store: Object<'js>,
         type_descriptor: Value<'js>,
         info: Value<'js>,
         terminated_element: Option<Value<'js>>,
         keys: Class<'js, CompactKeys<'js>>| {
            let key = |slot: Slot| keys.borrow().atoms[slot as usize].clone();
            let backing =
                if let Some(typed) = store.get::<_, Option<TypedArray<u8>>>(key(Slot::Bytes))? {
                    let data = typed.as_bytes().ok_or(Error::Unknown)?;
                    let mut bytes = [0; 8];
                    bytes
                        .get_mut(..data.len())
                        .ok_or(Error::Unknown)?
                        .copy_from_slice(data);
                    Backing::Inline {
                        bytes,
                        len: data.len(),
                    }
                } else {
                    Backing::Target {
                        address: store.get::<_, BigInt>(key(Slot::Address))?.to_i64()? as u64,
                        root: store.get(key(Slot::Root))?,
                    }
                };
            let parent = store.get::<_, Option<Value>>(key(Slot::Parent))?;
            let self_type = store.get::<_, Option<Value>>(key(Slot::SelfType))?;
            let extra = [
                (Slot::Parent, parent),
                (Slot::SelfType, self_type),
                (Slot::TerminatedElement, terminated_element),
            ]
            .into_iter()
            .filter_map(|(slot, value)| Some((slot, value?)))
            .collect();
            let tid = store.get::<_, Value>(key(Slot::Tid))?.as_number();
            Class::instance(
                store.ctx().clone(),
                CompactValue {
                    backing,
                    tid: tid.unwrap_or_default(),
                    has_tid: tid.is_some(),
                    inherit_tid: store
                        .get::<_, Option<bool>>(key(Slot::InheritTid))?
                        .unwrap_or(false),
                    type_descriptor,
                    info,
                    keys: keys.clone(),
                    extra,
                },
            )
        },
    )?;
    let lookup = Function::new(ctx.clone(), |value: Value<'js>| {
        Class::<CompactValue>::from_value(&value)
            .is_ok()
            .then_some(value)
    })?;
    api.get::<_, Function>("installCompactValue")?
        .call((create, lookup, keys))
}

#[cfg(test)]
pub(super) fn extra_bytes(value: &Value<'_>) -> usize {
    Class::<CompactValue>::from_value(value)
        .ok()
        .map_or(0, |native| size_of_val(native.borrow().extra.as_ref()))
}

#[cfg(test)]
mod tests;

//! Secret-holding types implement no `Debug`, `Display`, `Clone` or `Serialize` (SPEC.md 20, 21).
//!
//! The check uses inherent associated constants, which win over the blanket trait constant
//! only when the type implements the trait, so it is decided at compile time per type.
#![allow(dead_code)]

use std::marker::PhantomData;

struct Probe<T>(PhantomData<T>);

trait No {
    const DEBUG: bool = false;
    const DISPLAY: bool = false;
    const CLONE: bool = false;
    const SERIALIZE: bool = false;
}
impl<T> No for Probe<T> {}

struct D<T>(PhantomData<T>);
impl<T> No for D<T> {}
impl<T: std::fmt::Debug> D<T> {
    const DEBUG: bool = true;
}
struct S<T>(PhantomData<T>);
impl<T> No for S<T> {}
impl<T: std::fmt::Display> S<T> {
    const DISPLAY: bool = true;
}
struct C<T>(PhantomData<T>);
impl<T> No for C<T> {}
impl<T: Clone> C<T> {
    const CLONE: bool = true;
}
struct Z<T>(PhantomData<T>);
impl<T> No for Z<T> {}
impl<T: serde::Serialize> Z<T> {
    const SERIALIZE: bool = true;
}

macro_rules! no_leaks {
    ($($t:ty),* $(,)?) => {{
        let mut bad = Vec::new();
        $(
            if <D<$t>>::DEBUG { bad.push(concat!(stringify!($t), ": Debug")); }
            if <S<$t>>::DISPLAY { bad.push(concat!(stringify!($t), ": Display")); }
            if <C<$t>>::CLONE { bad.push(concat!(stringify!($t), ": Clone")); }
            if <Z<$t>>::SERIALIZE { bad.push(concat!(stringify!($t), ": Serialize")); }
        )*
        bad
    }};
}

#[test]
fn secret_types_cannot_leak() {
    let _ = Probe::<()>(PhantomData);
    let bad = no_leaks!(
        crate::Words,
        crate::Root,
        crate::PhoneKeys,
        crate::ObjectKey,
        crate::MachineKeys,
        crate::Request,
        crate::PairingOffer,
        crate::BackupItem,
        crate::request::OneTimeKey,
        crate::request::SealedRequest,
    );
    assert!(bad.is_empty(), "{bad:?}");
    // Reply bodies carry keys: they serialise (they are the wire format) but never print or copy.
    let reply = no_leaks!(crate::wire::ReplyBody, crate::wire::ReplyKey);
    assert_eq!(
        reply,
        [
            "crate::wire::ReplyBody: Serialize",
            "crate::wire::ReplyKey: Serialize"
        ]
    );
}

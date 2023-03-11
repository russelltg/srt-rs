#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::large_enum_variant)]

#[cfg(not(target_os = "windows"))]
mod c_api;
#[cfg(not(target_os = "windows"))]
mod epoll;
#[cfg(not(target_os = "windows"))]
mod errors;
#[cfg(not(target_os = "windows"))]
mod socket;

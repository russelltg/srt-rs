#[cfg(not(target_os = "windows"))]
mod c_api;
#[cfg(not(target_os = "windows"))]
mod epoll;
#[cfg(not(target_os = "windows"))]
mod errors;
#[cfg(not(target_os = "windows"))]
mod socket;

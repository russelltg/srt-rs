use std::{
    error::Error,
    fmt::{self, Display},
    marker::PhantomData,
    net::SocketAddr,
    str::FromStr,
};

#[derive(Debug, PartialEq, Eq)]
pub struct AccessControlList(pub Vec<AccessControlEntry>);

#[derive(Debug, PartialEq, Eq)]
pub struct AccessControlEntry {
    pub key: String,
    pub value: String,
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConnectionType {
    Stream,
    File,
    Auth,
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConnectionMode {
    Request,
    Publish,
    Bidirectional,
}

#[derive(Debug, Clone)]
pub enum StandardAccessControlEntry {
    UserName(String),
    ResourceName(String),
    HostName(String),
    SessionID(String),
    Type(ConnectionType),
    Mode(ConnectionMode),
}

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseAccessControlEntryError {
    /// key was found with no value
    NoValue,
    /// doesn't start with #!::
    WrongStart,
}

impl Display for AccessControlList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.iter().fuse();
        if let Some(item) = iter.next() {
            write!(f, "#!::{}", item)?;
        }

        for item in iter {
            write!(f, ",{}", item)?;
        }
        Ok(())
    }
}

impl FromStr for AccessControlList {
    type Err = ParseAccessControlEntryError;
    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("#!::") {
            return Err(ParseAccessControlEntryError::WrongStart);
        }
        s = &s[4..]; // skip start

        Ok(AccessControlList(
            s.split(",")
                .map(str::parse)
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

impl AccessControlEntry {
    fn new(key: impl Into<String>, value: impl Into<String>) -> AccessControlEntry {
        AccessControlEntry {
            key: key.into(),
            value: value.into(),
        }
    }
}

impl Display for AccessControlEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

impl FromStr for AccessControlEntry {
    type Err = ParseAccessControlEntryError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let eq = s.find('=').ok_or(ParseAccessControlEntryError::NoValue)?;
        let (k, v) = s.split_at(eq);

        Ok(AccessControlEntry::new(k, &v[1..])) // skip =, which is a one bye char
    }
}

impl Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectionType::Stream => write!(f, "stream"),
            ConnectionType::File => write!(f, "file"),
            ConnectionType::Auth => write!(f, "auth"),
        }
    }
}

impl Display for ConnectionMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectionMode::Request => write!(f, "request"),
            ConnectionMode::Publish => write!(f, "publish"),
            ConnectionMode::Bidirectional => write!(f, "bidirectional"),
        }
    }
}

impl From<StandardAccessControlEntry> for AccessControlEntry {
    fn from(sace: StandardAccessControlEntry) -> Self {
        match sace {
            StandardAccessControlEntry::UserName(un) => AccessControlEntry::new("u", un),
            StandardAccessControlEntry::ResourceName(rn) => AccessControlEntry::new("r", rn),
            StandardAccessControlEntry::HostName(hn) => AccessControlEntry::new("h", hn),
            StandardAccessControlEntry::SessionID(sid) => AccessControlEntry::new("s", sid),
            StandardAccessControlEntry::Type(ty) => AccessControlEntry::new("t", format!("{}", ty)),
            StandardAccessControlEntry::Mode(m) => AccessControlEntry::new("m", format!("{}", m)),
        }
    }
}

impl Display for StandardAccessControlEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        AccessControlEntry::from(self.clone()).fmt(f)
    }
}

pub struct AcceptParameters {
    password: Option<String>,
}

impl AcceptParameters {
    pub fn new() -> AcceptParameters {
        AcceptParameters { password: None }
    }

    pub fn set_password(&mut self, password: impl Into<String>) -> &mut Self {
        self.password = Some(password.into());
        self
    }

    pub(crate) fn take_password(&mut self) -> Option<String> {
        self.password.take()
    }
}

impl Default for AcceptParameters {
    fn default() -> Self {
        AcceptParameters::new()
    }
}

impl Display for ParseAccessControlEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseAccessControlEntryError::NoValue => write!(f, "No value to corresponding key"),
            ParseAccessControlEntryError::WrongStart => {
                write!(f, "Access control entry did not start with #!::")
            }
        }
    }
}

impl Error for ParseAccessControlEntryError {}

pub trait StreamAcceptor {
    fn accept(
        &mut self,
        streamid: Option<&str>,
        ip: SocketAddr,
    ) -> Result<AcceptParameters, RejectReason>;
}

#[derive(Default, Clone, Copy)]
pub struct AllowAllStreamAcceptor {
    _hidden: PhantomData<()>,
}

impl StreamAcceptor for AllowAllStreamAcceptor {
    fn accept(
        &mut self,
        _streamid: Option<&str>,
        _ip: SocketAddr,
    ) -> Result<AcceptParameters, RejectReason> {
        Ok(AcceptParameters::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ace() {
        let ace_str = "#!::u=admin,r=bluesbrothers1_hi";
        let ace = ace_str.parse::<AccessControlList>().unwrap();

        assert_eq!(
            ace,
            AccessControlList(vec![
                AccessControlEntry::new("u", "admin"),
                AccessControlEntry::new("r", "bluesbrothers1_hi")
            ])
        );

        assert_eq!(ace_str, format!("{}", ace))
    }
}

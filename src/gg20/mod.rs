use std::fmt;

mod blame;
pub mod keygen;
pub mod mta;
mod party_i;
pub mod presignature;
pub mod signing;
pub mod state_machine;
pub mod zk_pdl;
pub mod zk_pdl_with_slack;

#[cfg(test)]
mod test;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
    Phase5BadSum,
    Phase6Error,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match *self {
            InvalidKey => write!(f, "InvalidKey"),
            InvalidSS => write!(f, "InvalidSS"),
            InvalidCom => write!(f, "InvalidCom"),
            InvalidSig => write!(f, "InvalidSig"),
            Phase5BadSum => write!(f, "Phase5BadSum"),
            Phase6Error => write!(f, "Phase6Error"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ErrorType {
    error_type: String,
    bad_actors: Vec<usize>,
}

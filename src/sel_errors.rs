use serde::{Serialize,Deserialize};

#[derive(Serialize,Deserialize,Debug,Clone,Copy,Hash,PartialEq,PartialOrd)]
pub enum SeleniteErrors {
    BLSAggregationFailed,
    DecodingFromHexFailed,
    FailedToGetFile,
    FileDoesNotExist,
}
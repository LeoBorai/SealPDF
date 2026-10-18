use crate::{Transport, TsaClient, TsaError};
use std::{cell::RefCell, collections::VecDeque};

/// Replays stored TSA answers and keeps the requests it was sent.
///
/// Answers go through the same checks as a live TSA's, so a recorded failure, a replayed token
/// for other data or a recorded HTTP error all exercise the real code path.
#[derive(Debug, Default)]
pub struct RecordedTransport {
    name: String,
    answers: RefCell<VecDeque<Result<Vec<u8>, TsaError>>>,
    requests: RefCell<Vec<Vec<u8>>>,
}

impl RecordedTransport {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// Queues a DER `TimeStampResp` as the next answer.
    pub fn respond(self, resp_der: Vec<u8>) -> Self {
        self.answers.borrow_mut().push_back(Ok(resp_der));
        self
    }

    /// Queues a transport failure as the next answer.
    pub fn fail(self, error: TsaError) -> Self {
        self.answers.borrow_mut().push_back(Err(error));
        self
    }

    /// The DER `TimeStampReq`s received so far.
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.borrow().clone()
    }
}

impl Transport for RecordedTransport {
    fn send(&self, request_der: &[u8]) -> Result<Vec<u8>, TsaError> {
        self.requests.borrow_mut().push(request_der.to_vec());
        self.answers.borrow_mut().pop_front().unwrap_or_else(|| {
            Err(TsaError::Unreachable {
                url: self.name.clone(),
                reason: "no recorded answer left".into(),
            })
        })
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

/// A [`crate::Tsa`] that replays recorded answers.
pub type RecordedTsa = TsaClient<RecordedTransport>;

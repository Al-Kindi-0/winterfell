use crate::sum_check::SumCheckProverError;

#[derive(Debug, thiserror::Error)]
pub enum GkrProverError {
    #[error("failed to generate the sum-check proof")]
    FailedToProveSumCheck(#[from] SumCheckProverError),
    #[error("failed to generate the random challenge")]
    FailedToGenerateChallenge,
}

use bitcoin::blockdata::script;

/// Error of a script execution.
///
/// Equivalent to Bitcoin Core's `ScriptError_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    DisabledOpcode,
    OpCodeseparator,
    BadOpcode,
    OpCount,
    PushSize,
    MinimalData,
    InvalidStackOperation,
    NegativeLocktime,
    UnsatisfiedLocktime,
    UnbalancedConditional,
    TapscriptMinimalIf,
    Verify,
    OpReturn,
    EqualVerify,
    NumEqualVerify,
    CheckSigVerify,
    TapscriptValidationWeight,
    PubkeyType,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TapscriptCheckMultiSig,
    PubkeyCount,
    StackSize,
    WitnessPubkeyType,

    // new ones for us
    ScriptIntNumericOverflow,
    Debug,

    DivByZero,

    // tapscript v2 (BIP 440/441)
    VaropCount,
    SubUnderflow,
    StackElementSize,
    TotalStackSize,
    HashOperandSize,
    CleanStack,
    EvalFalse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Exec(ExecError),
    InvalidScript(script::Error),
    Other(&'static str),
}

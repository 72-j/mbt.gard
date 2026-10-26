// derive_extends.mbt — derive(Eq, Debug) 的显式晋升([0079] 标准动作:
// 只晋升需要的;不补则隐式提升被弃用告警)

///|
pub extend TokenType with Eq::{not_equal, equal}

///|
pub extend TokenType with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Claims with Eq::{not_equal, equal}

///|
pub extend Claims with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend GuardConfig with Eq::{not_equal, equal}

///|
pub extend GuardConfig with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Issued with Eq::{not_equal, equal}

///|
pub extend Issued with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend VerifyErr with Eq::{not_equal, equal}

///|
pub extend VerifyErr with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RefreshRecord with Eq::{not_equal, equal}

///|
pub extend RefreshRecord with @moonbitlang/core/debug.Debug::{to_repr}

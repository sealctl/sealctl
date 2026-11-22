//! Test only: an in-process sealctl relay (`relay`) and a scripted phone built on
//! `sealctl-core` (`phone`). The phone also works against a live relay (staging), which the
//! integration tests use when `SEALCTL_TEST_RELAY` is set.

pub mod phone;
pub mod relay;

pub use phone::{Answer, Background, Incoming, Machine, Phone};
pub use relay::{FakeRelay, Options};

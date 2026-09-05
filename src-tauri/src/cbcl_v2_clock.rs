//! SPEC079 CON-003: real elapsed time includes suspension; failures never renew custody.
use crate::commands::UiError;
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, UiError>;
fn refused() -> UiError {
    UiError::from("PairingClockUnavailable")
}

#[derive(Clone, Copy)]
pub(crate) struct Snapshot {
    pub utc: u64,
    pub continuous_ns: u64,
}

pub(crate) fn snapshot() -> Result<Snapshot> {
    Ok(Snapshot {
        utc: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refused())?
            .as_secs(),
        continuous_ns: continuous_ns()?,
    })
}

// u128 avoids truncating intermediate products; the final u64 conversion is checked.
#[cfg(any(target_vendor = "apple", target_os = "windows", test))]
fn scale(ticks: u64, numer: u32, denom: u32) -> Result<u64> {
    if numer == 0 || denom == 0 {
        return Err(refused());
    }
    u64::try_from(u128::from(ticks) * u128::from(numer) / u128::from(denom)).map_err(|_| refused())
}

#[cfg(target_vendor = "apple")]
fn continuous_ns() -> Result<u64> {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }
    let mut info = Timebase { numer: 0, denom: 0 };
    // SAFETY: the OS writes exactly one initialized ABI timebase structure.
    if unsafe { mach_timebase_info(&mut info) } != 0 {
        return Err(refused());
    }
    // SAFETY: this clock has no arguments or caller-owned memory.
    scale(unsafe { mach_continuous_time() }, info.numer, info.denom)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn continuous_ns() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the OS writes one ABI timespec; CLOCK_BOOTTIME includes suspend.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(refused());
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| refused())?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| refused())?;
    if nanos >= 1_000_000_000 {
        return Err(refused());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(refused)
}

#[cfg(target_os = "windows")]
fn continuous_ns() -> Result<u64> {
    #[link(name = "kernel32")]
    extern "system" {
        fn QueryInterruptTime(interrupt_time: *mut u64);
    }
    let mut ticks = 0;
    // SAFETY: QueryInterruptTime writes one u64, in sleep-inclusive 100ns units.
    // Unlike QueryUnbiasedInterruptTime this API includes time spent asleep.
    unsafe { QueryInterruptTime(&mut ticks) };
    scale(ticks, 100, 1)
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
)))]
fn continuous_ns() -> Result<u64> {
    Err(refused())
}

pub(crate) struct Deadline {
    cutoff_ns: u64,
    last_ns: u64,
    offer: u64,
    relay: u64,
}
impl Deadline {
    pub(crate) fn new(start: Snapshot, offer: u64, relay: u64) -> Result<Self> {
        let seconds = offer
            .checked_sub(start.utc)
            .zip(relay.checked_sub(start.utc))
            .map(|(o, r)| 120_u64.min(o).min(r))
            .filter(|s| *s > 0)
            .ok_or_else(|| UiError::from("PairingExpired"))?;
        let cutoff_ns = seconds
            .checked_mul(1_000_000_000)
            .and_then(|n| start.continuous_ns.checked_add(n))
            .ok_or_else(refused)?;
        Ok(Self {
            cutoff_ns,
            last_ns: start.continuous_ns,
            offer,
            relay,
        })
    }
    pub(crate) fn check(&mut self, now: Snapshot) -> Result<()> {
        if now.continuous_ns < self.last_ns {
            return Err(refused());
        }
        if now.continuous_ns >= self.cutoff_ns || now.utc >= self.offer || now.utc >= self.relay {
            return Err(UiError::from("PairingExpired"));
        }
        self.last_ns = now.continuous_ns;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn single_link_clock_adapter_executes_checked_native_clock() {
        let a = snapshot().unwrap();
        let b = snapshot().unwrap();
        assert!(b.continuous_ns >= a.continuous_ns);
        assert_eq!(scale(3, 125, 3).unwrap(), 125);
        assert!(scale(1, 1, 0).is_err());
        assert!(scale(u64::MAX, 100, 1).is_err());
    }
    #[test]
    fn single_link_deadlines_exclusive_suspend_rollback_and_overflow() {
        let start = Snapshot {
            utc: 1000,
            continuous_ns: 100,
        };
        for (offer, relay, duration) in [(2000, 2000, 120), (1003, 2000, 3), (2000, 1005, 5)] {
            let mut bound = Deadline::new(start, offer, relay).unwrap();
            // The ordinary monotonic clock may stay paused; only continuous time governs.
            let cutoff = 100 + duration * 1_000_000_000;
            assert!(bound
                .check(Snapshot {
                    utc: 900,
                    continuous_ns: cutoff - 1
                })
                .is_ok());
            assert!(bound
                .check(Snapshot {
                    utc: 900,
                    continuous_ns: cutoff
                })
                .is_err());
            assert!(bound
                .check(Snapshot {
                    utc: 900,
                    continuous_ns: cutoff + 1
                })
                .is_err());
        }
        for utc in [1100, 1200] {
            let mut bound = Deadline::new(start, 1100, 1200).unwrap();
            assert!(bound
                .check(Snapshot {
                    utc,
                    continuous_ns: 101
                })
                .is_err());
        }
        assert!(Deadline::new(start, 1000, 2000).is_err());
        assert!(Deadline::new(
            Snapshot {
                continuous_ns: u64::MAX,
                ..start
            },
            2000,
            2000
        )
        .is_err());
        let mut bound = Deadline::new(start, 2000, 2000).unwrap();
        assert!(bound
            .check(Snapshot {
                continuous_ns: 99,
                ..start
            })
            .is_err());
    }
}

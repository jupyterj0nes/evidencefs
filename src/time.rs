//! Timestamps: one type for every file system, written the way the c00pr timelines
//! write them (`YYYY-MM-DDTHH:MM:SS.ffffffZ`, UTC, fixed width).

pub mod code {
    crate::codes! {
        TIME_OUT_OF_RANGE = 750, "a timestamp is before year 1601 or after year 9999 and was clamped; the on-disk value was damaged or never set, read the raw value when it matters";
        TIME_UNSET = 751, "a timestamp field is zero (never set); the column is left empty rather than shown as the epoch";
    }
}

/// Seconds between 1601-01-01 (Windows FILETIME epoch) and 1970-01-01.
pub const NT_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;
/// Seconds between 1970-01-01 and 2001-01-01 (Apple Cocoa epoch).
pub const COCOA_EPOCH_OFFSET_SECS: i64 = 978_307_200;

/// A point in time, UTC, with sub-second precision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Seconds since 1970-01-01T00:00:00Z (negative before it).
    pub secs: i64,
    /// Nanoseconds within the second (0..1e9).
    pub nanos: u32,
}

impl Timestamp {
    /// From Unix seconds and nanoseconds.
    pub fn from_unix(secs: i64, nanos: u32) -> Self {
        let extra = (nanos / 1_000_000_000) as i64;
        Timestamp { secs: secs + extra, nanos: nanos % 1_000_000_000 }
    }

    /// From a Windows FILETIME (100 ns ticks since 1601). Zero means unset.
    pub fn from_nt(ticks: u64) -> Option<Self> {
        if ticks == 0 {
            return None;
        }
        let secs = (ticks / 10_000_000) as i64 - NT_EPOCH_OFFSET_SECS;
        let nanos = ((ticks % 10_000_000) * 100) as u32;
        Some(Timestamp { secs, nanos })
    }

    /// From WebKit / Chromium microseconds since 1601. Zero means unset.
    pub fn from_webkit_micros(us: u64) -> Option<Self> {
        if us == 0 {
            return None;
        }
        Some(Timestamp { secs: (us / 1_000_000) as i64 - NT_EPOCH_OFFSET_SECS, nanos: ((us % 1_000_000) * 1000) as u32 })
    }

    /// From Unix microseconds (Firefox). Zero means unset.
    pub fn from_unix_micros(us: i64) -> Option<Self> {
        if us == 0 {
            return None;
        }
        Some(Timestamp { secs: us.div_euclid(1_000_000), nanos: (us.rem_euclid(1_000_000) * 1000) as u32 })
    }

    /// From Apple Cocoa seconds since 2001 (Safari). Zero means unset.
    pub fn from_cocoa(secs: f64) -> Option<Self> {
        if secs == 0.0 || !secs.is_finite() {
            return None;
        }
        let whole = secs.floor();
        Some(Timestamp { secs: whole as i64 + COCOA_EPOCH_OFFSET_SECS, nanos: ((secs - whole) * 1e9) as u32 })
    }

    /// From a FAT / zip local date-time (taken as UTC: the archive does not say the zone).
    pub fn from_civil(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<Self> {
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        Some(Timestamp { secs: days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64, nanos: 0 })
    }

    /// `YYYY-MM-DDTHH:MM:SS.ffffffZ`, 27 characters, sorting as text sorts the time.
    /// Years outside 0001..9999 are clamped and recorded.
    pub fn to_rfc3339_micros(&self) -> String {
        let (y, m, d, hh, mm, ss) = self.civil();
        let (y, m, d, hh, mm, ss, micros) = if !(1..=9999).contains(&y) {
            crate::diag::info(code::TIME_OUT_OF_RANGE, format!("{} s since 1970 is year {y}", self.secs));
            if y < 1 {
                (1, 1, 1, 0, 0, 0, 0)
            } else {
                (9999, 12, 31, 23, 59, 59, 999_999)
            }
        } else {
            (y, m, d, hh, mm, ss, self.nanos / 1000)
        };
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{micros:06}Z")
    }

    /// `YYYY-MM-DD HH:MM:SS` without fractions, for labels.
    pub fn to_human(&self) -> String {
        let (y, m, d, hh, mm, ss) = self.civil();
        format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
    }

    /// Year, month, day, hour, minute, second in UTC.
    pub fn civil(&self) -> (i64, u32, u32, u32, u32, u32) {
        let days = self.secs.div_euclid(86_400);
        let rem = self.secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
    }

    /// As a `SystemTime`, for setting file times on extracted copies. None before 1970
    /// on platforms whose `SystemTime` cannot go there.
    pub fn to_system_time(&self) -> Option<std::time::SystemTime> {
        let d = std::time::Duration::new(self.secs.unsigned_abs(), self.nanos);
        if self.secs >= 0 {
            std::time::UNIX_EPOCH.checked_add(d)
        } else {
            std::time::UNIX_EPOCH.checked_sub(d)
        }
    }

    /// Windows FILETIME ticks (100 ns since 1601), saturating at zero.
    pub fn to_nt(&self) -> u64 {
        let secs = self.secs + NT_EPOCH_OFFSET_SECS;
        if secs < 0 {
            return 0;
        }
        secs as u64 * 10_000_000 + (self.nanos / 100) as u64
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_rfc3339_micros())
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Year, month, day from days since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The four timestamps a file system keeps about a file. Any of them may be unknown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Timestamps {
    /// Birth / creation time (`$SI` created, ext4 `crtime`, XFS v3 `crtime`).
    pub created: Option<Timestamp>,
    /// Content last modified.
    pub modified: Option<Timestamp>,
    /// Last access.
    pub accessed: Option<Timestamp>,
    /// Metadata change (`$MFT` record modified on NTFS, `ctime` on Unix).
    pub changed: Option<Timestamp>,
}

impl Timestamps {
    /// `M`, `A`, `C`, `B` letters in mactime order for the times that are set.
    pub fn macb(&self) -> String {
        let mut s = String::with_capacity(4);
        s.push(if self.modified.is_some() { 'M' } else { '.' });
        s.push(if self.accessed.is_some() { 'A' } else { '.' });
        s.push(if self.changed.is_some() { 'C' } else { '.' });
        s.push(if self.created.is_some() { 'B' } else { '.' });
        s
    }

    /// The most recent of the four, if any is set.
    pub fn latest(&self) -> Option<Timestamp> {
        [self.created, self.modified, self.accessed, self.changed].into_iter().flatten().max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(Timestamp::from_unix(0, 0).to_rfc3339_micros(), "1970-01-01T00:00:00.000000Z");
        // 2016-09-21T03:41:02.560546Z is 1474429262.560546
        let t = Timestamp::from_unix(1_474_429_262, 560_546_000);
        assert_eq!(t.to_rfc3339_micros(), "2016-09-21T03:41:02.560546Z");
        assert_eq!(t.to_human(), "2016-09-21 03:41:02");
        assert_eq!(t.to_string().len(), 27);
    }

    #[test]
    fn nt_round_trip() {
        // 2026-10-28T22:01:03Z
        let t = Timestamp::from_civil(2026, 10, 28, 22, 1, 3).unwrap();
        let ticks = t.to_nt();
        assert_eq!(Timestamp::from_nt(ticks), Some(t));
        assert_eq!(Timestamp::from_nt(0), None);
        // The NT epoch itself.
        assert_eq!(Timestamp::from_nt(1).unwrap().to_rfc3339_micros(), "1601-01-01T00:00:00.000000Z");
        // 132_223_104_000_000_000 ticks = 2020-01-01T00:00:00Z
        assert_eq!(Timestamp::from_nt(132_223_104_000_000_000).unwrap().to_rfc3339_micros(), "2020-01-01T00:00:00.000000Z");
    }

    #[test]
    fn browser_epochs() {
        // WebKit: 13_244_817_600_000_000 µs = 1_600_344_000 s after 1970 = 2020-09-17T12:00:00Z
        assert_eq!(Timestamp::from_webkit_micros(13_244_817_600_000_000).unwrap().to_rfc3339_micros(), "2020-09-17T12:00:00.000000Z");
        assert_eq!(Timestamp::from_webkit_micros(0), None);
        assert_eq!(Timestamp::from_unix_micros(1_600_000_000_123_456).unwrap().to_rfc3339_micros(), "2020-09-13T12:26:40.123456Z");
        assert_eq!(Timestamp::from_unix_micros(0), None);
        // 600_000_000 s after 2001-01-01 = 1_578_307_200 s after 1970 = 2020-01-06T10:40:00Z
        assert_eq!(Timestamp::from_cocoa(600_000_000.5).unwrap().to_rfc3339_micros(), "2020-01-06T10:40:00.500000Z");
        assert_eq!(Timestamp::from_cocoa(0.0), None);
        assert_eq!(Timestamp::from_cocoa(f64::NAN), None);
    }

    #[test]
    fn civil_round_trip_across_centuries() {
        for (y, m, d) in [(1601, 1, 1), (1899, 12, 31), (1970, 1, 1), (2000, 2, 29), (2024, 2, 29), (2100, 3, 1), (9999, 12, 31)] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y as i64, m, d), "{y}-{m}-{d}");
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn invalid_civil_is_none() {
        assert!(Timestamp::from_civil(2020, 13, 1, 0, 0, 0).is_none());
        assert!(Timestamp::from_civil(2020, 0, 1, 0, 0, 0).is_none());
        assert!(Timestamp::from_civil(2020, 1, 32, 0, 0, 0).is_none());
        assert!(Timestamp::from_civil(2020, 1, 1, 24, 0, 0).is_none());
        assert!(Timestamp::from_civil(2020, 1, 1, 0, 60, 0).is_none());
    }

    #[test]
    fn out_of_range_is_clamped_and_recorded() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let t = Timestamp::from_unix(i64::MAX / 4, 0);
        assert_eq!(t.to_rfc3339_micros(), "9999-12-31T23:59:59.999999Z");
        assert!(crate::diag::has(code::TIME_OUT_OF_RANGE));
        crate::diag::drain();
        let t = Timestamp::from_unix(-70_000_000_000, 0);
        assert_eq!(t.to_rfc3339_micros(), "0001-01-01T00:00:00.000000Z");
        crate::diag::drain();
    }

    #[test]
    fn nanos_overflow_carries() {
        let t = Timestamp::from_unix(10, 2_500_000_000);
        assert_eq!(t.secs, 12);
        assert_eq!(t.nanos, 500_000_000);
    }

    #[test]
    fn system_time_both_sides_of_1970() {
        let t = Timestamp::from_unix(100, 5);
        assert_eq!(t.to_system_time(), Some(std::time::UNIX_EPOCH + std::time::Duration::new(100, 5)));
        let t = Timestamp::from_unix(-100, 0);
        assert_eq!(t.to_system_time(), std::time::UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(100)));
        assert_eq!(Timestamp::from_unix(-NT_EPOCH_OFFSET_SECS - 1, 0).to_nt(), 0);
    }

    #[test]
    fn macb_and_latest() {
        let a = Timestamp::from_unix(1, 0);
        let b = Timestamp::from_unix(2, 0);
        let ts = Timestamps { created: Some(a), modified: Some(b), accessed: None, changed: None };
        assert_eq!(ts.macb(), "M..B");
        assert_eq!(ts.latest(), Some(b));
        assert_eq!(Timestamps::default().macb(), "....");
        assert_eq!(Timestamps::default().latest(), None);
    }

    #[test]
    fn ordering_follows_time() {
        let a = Timestamp::from_unix(5, 10);
        let b = Timestamp::from_unix(5, 11);
        let c = Timestamp::from_unix(6, 0);
        assert!(a < b && b < c);
    }
}

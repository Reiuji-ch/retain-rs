#[macro_export]
macro_rules! retry_forever {
    ($timings:expr, $result:ident, $call:tt, $success:tt, $fail:tt) => {
        use std::time::Duration;
        let mut attempts = 0;
        let backoff = $timings;
        loop {
            match $call {
                Ok(result) => {
                    let $result = result;
                    attempts = 0;
                    // silence unused assignment warning
                    let _ = &attempts;
                    let _ = &$result;
                    $success
                },
                Err(err) => {
                    let $result = err;
                    $fail
                    tokio::time::sleep(Duration::from_secs(backoff[attempts])).await;
                    attempts = (backoff.len()-1).min(attempts + 1);
                }
            }
        }
    }
}

#[macro_export]
macro_rules! retry_limited {
    ($timings:expr, $result:ident, $call:tt, $success:tt, $fail:tt) => {
        let mut attempts = 0;
        let backoff = $timings;
        loop {
            match $call {
                Ok(result) => {
                    let $result = result;
                    attempts = 0;
                    // silence unused assignment warning
                    let _ = &attempts;
                    let _ = &$result;
                    $success
                },
                Err(err) => {
                    let $result = err;
                    $fail
                    if attempts == backoff.len()-1 {
                        eprintln!("Retries exceeded");
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(backoff[attempts])).await;
                    attempts = (backoff.len()-1).min(attempts + 1);
                }
            }
        }
    }
}
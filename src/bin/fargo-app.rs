#![deny(warnings)]

use {
    anyhow::{anyhow, Error, Result},
    fluvio_wasm_timer::Delay,
    futures::TryFutureExt,
    reqwest::Client,
    std::{ops::Deref, panic, time::Duration},
    sycamore::prelude::{template, Signal},
    wasm_bindgen::JsCast,
    web_sys::{Event, KeyboardEvent},
};

const URL: &str = "https://raw.githubusercontent.com/dicej/dicej/master/fargo.bin";

const TIMEOUT: Duration = Duration::from_secs(5 * 60);

fn main() -> Result<()> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER)
        .map_err(|e| anyhow!("{:?}", e))?;

    let client = Client::new();

    let error = Signal::new(String::new());
    let plaintext = Signal::new(String::new());
    let password = Signal::new(String::new());

    let on_key = {
        let error = error.clone();
        let plaintext = plaintext.clone();
        let password = password.clone();

        move |event: Event| {
            if let Ok(event) = event.dyn_into::<KeyboardEvent>() {
                if event.key().deref() == "Enter" {
                    wasm_bindgen_futures::spawn_local(
                        {
                            let error = error.clone();
                            let client = client.clone();
                            let plaintext = plaintext.clone();
                            let password = password.clone();

                            async move {
                                plaintext.set(fargo::decrypt(
                                    &client
                                        .get(URL)
                                        .send()
                                        .await?
                                        .error_for_status()?
                                        .bytes()
                                        .await?,
                                    password.get_untracked().deref(),
                                )?);

                                password.set(String::new());
                                error.set(String::new());

                                Delay::new(TIMEOUT).await?;

                                plaintext.set(String::new());

                                Ok::<_, Error>(())
                            }
                        }
                        .unwrap_or_else({
                            let error = error.clone();
                            let plaintext = plaintext.clone();

                            move |e| {
                                let message =
                                    format!("error retrieving or decrypting secret: {:?}", e);

                                log::error!("{}", message);

                                plaintext.set(String::new());
                                error.set(message);
                            }
                        }),
                    );
                }
            }
        }
    };

    sycamore::render(move || {
        template! {
            div(style="color: #f54")
            {
                (error.get())
            }

            input(type="password",
                  on:keyup=on_key.clone(),
                  bind:value=password.clone()) {}

            pre {
                (plaintext.get())
            }
        }
    });

    Ok(())
}

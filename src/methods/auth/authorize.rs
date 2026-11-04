use std::io::{self, BufRead, IsTerminal, Write};

use crate::Client;
use crate::client::Login;
use crate::errors::Result;
use crate::raw::{base, functions};

async fn ask(prompt: &'static str, hidden: bool) -> Result<String> {
    let answer = tokio::task::spawn_blocking(move || {
        if hidden && io::stdin().is_terminal() {
            return rpassword::prompt_password(prompt);
        }
        print!("{prompt}");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no input to log in with"));
        }
        Ok(line)
    })
    .await
    .map_err(io::Error::other)??;
    Ok(if hidden { answer.trim_end_matches(['\r', '\n']).to_owned() } else { answer.trim().to_owned() })
}

impl Client {
    pub(crate) async fn authorize(&self, login: Login) -> Result<()> {
        let value = match (login.bot_token, login.phone_number) {
            (Some(token), _) => token,
            (None, Some(phone)) => phone,
            (None, None) => loop {
                let value = ask("Enter phone number or bot token: ", false).await?;
                if !value.is_empty() {
                    break value;
                }
            },
        };
        if value.contains(':') {
            return self.sign_in_bot(&value).await.map(drop);
        }

        let phone = value.trim_matches(|c| c == ' ' || c == '+').to_owned();
        let sent = self.send_code(&phone).await?;
        println!("The confirmation code has been sent via {}", sent.kind);

        let mut code = login.phone_code;
        loop {
            let c = match code.take() {
                Some(c) => c,
                None => ask("Enter confirmation code: ", false).await?,
            };
            match self.sign_in_raw(&phone, &sent.phone_code_hash, &c).await {
                Ok(base::auth::Authorization::AuthorizationSignUpRequired(required)) => {
                    let first_name = ask("Enter first name: ", false).await?;
                    let last_name = ask("Enter last name (optional): ", false).await?;
                    let terms = required.terms_of_service;
                    return self.finish_sign_up(&phone, &sent.phone_code_hash, &first_name, &last_name, terms).await;
                }
                Ok(auth) => return self.authorized(auth).await.map(drop),
                Err(e) if e.is("PHONE_CODE_INVALID") => println!("Wrong code, try again"),
                Err(e) if e.is("SESSION_PASSWORD_NEEDED") => break,
                Err(e) => return Err(e),
            }
        }

        let mut password = login.password;
        loop {
            let p = match password.take() {
                Some(p) => p,
                None => {
                    let base::account::Password::Password(p) = self.invoke(&functions::account::GetPassword {}).await?;
                    if let Some(hint) = p.hint.filter(|h| !h.is_empty()) {
                        println!("Password hint: {hint}");
                    }
                    ask("Enter password: ", true).await?
                }
            };
            match self.check_password(&p).await {
                Ok(_) => return Ok(()),
                Err(e) if e.is("PASSWORD_HASH_INVALID") => println!("Wrong password, try again"),
                Err(e) => return Err(e),
            }
        }
    }

    async fn finish_sign_up(
        &self,
        phone: &str,
        phone_code_hash: &str,
        first_name: &str,
        last_name: &str,
        terms: Option<base::help::TermsOfService>,
    ) -> Result<()> {
        self.sign_up(phone, phone_code_hash, first_name, last_name).await?;
        self.accept_shown_terms(terms).await
    }

    /// A new account starts by agreeing to the terms Telegram sent with the sign-up request: show them, then accept.
    async fn accept_shown_terms(&self, terms: Option<base::help::TermsOfService>) -> Result<()> {
        let Some(base::help::TermsOfService::TermsOfService(terms)) = terms else { return Ok(()) };
        println!("\n{}\n", terms.text);
        let base::DataJSON::DataJSON(id) = terms.id;
        self.accept_terms_of_service(id.data).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::methods::auth::send_code::tests::user;
    use crate::raw::{Serializable, base, functions, types};

    fn signed_up() -> Vec<u8> {
        let auth = types::auth::Authorization {
            setup_password_required: false,
            otherwise_relogin_days: None,
            tmp_sessions: None,
            future_auth_token: None,
            user: user(7),
        };
        base::auth::Authorization::Authorization(Box::new(auth)).to_bytes()
    }

    fn id() -> base::DataJSON {
        base::DataJSON::DataJSON(Box::new(types::DataJSON { data: "{\"id\":\"tos-1\"}".into() }))
    }

    fn sign_up() -> Vec<u8> {
        let request = functions::auth::SignUp {
            no_joined_notifications: false,
            phone_number: "8801".into(),
            phone_code_hash: "hash".into(),
            first_name: "Ada".into(),
            last_name: String::new(),
        };
        request.to_bytes()
    }

    #[tokio::test]
    async fn sign_up_accepts_the_terms_it_was_shown() {
        let terms = types::help::TermsOfService {
            popup: true,
            id: id(),
            text: "Be nice.".into(),
            entities: Vec::new(),
            min_age_confirm: None,
        };
        let terms = Some(base::help::TermsOfService::TermsOfService(Box::new(terms)));
        let (client, mut sent) = Client::scripted(vec![Ok(signed_up()), Ok(true.to_bytes())]);
        client.finish_sign_up("8801", "hash", "Ada", "", terms).await.unwrap();

        let sent: Vec<_> = std::iter::from_fn(|| sent.try_recv().ok()).collect();
        assert_eq!(sent, [sign_up(), functions::help::AcceptTermsOfService { id: id() }.to_bytes()]);
        assert_eq!(client.0.me.lock().unwrap().id, 7);
    }

    #[tokio::test]
    async fn no_terms_no_accept() {
        let (client, mut sent) = Client::scripted(vec![Ok(signed_up())]);
        client.finish_sign_up("8801", "hash", "Ada", "", None).await.unwrap();
        let sent: Vec<_> = std::iter::from_fn(|| sent.try_recv().ok()).collect();
        assert_eq!(sent, [sign_up()]);
    }
}

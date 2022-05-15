use std::{convert::Infallible, env, sync::Arc};

use log::{error, info};
use openid::{Client, Discovered, DiscoveredClient, Options, StandardClaims, Token, Userinfo};
use openid_examples::{
    entity::{LoginQuery, Sessions, User},
    INDEX_HTML,
};
use tokio::sync::RwLock;
use warp::{
    http::{Response, StatusCode},
    reject, Filter, Rejection, Reply,
};

type OpenIDClient = Client<Discovered, StandardClaims>;

const EXAMPLE_COOKIE: &str = "openid_warp_example";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=openid_warp_example=debug` to see debug logs,
        // this only shows access logs.
        env::set_var("RUST_LOG", "openid_warp_example=info");
    }
    pretty_env_logger::init();

    let client_id = env::var("CLIENT_ID").expect("<client id> for your provider");
    let client_secret = env::var("CLIENT_SECRET").expect("<client secret> for your provider");
    let issuer_url =
        env::var("ISSUER").unwrap_or_else(|_| "https://accounts.google.com".to_string());
    let redirect = Some(host("/login/oauth2/code/oidc"));
    let issuer = reqwest::Url::parse(&issuer_url)?;

    eprintln!("redirect: {:?}", redirect);
    eprintln!("issuer: {}", issuer);

    let client =
        Arc::new(DiscoveredClient::discover(client_id, client_secret, redirect, issuer).await?);

    eprintln!("discovered config: {:?}", client.config());

    let with_client = |client: Arc<Client<_>>| warp::any().map(move || client.clone());

    let sessions = Arc::new(RwLock::new(Sessions::default()));

    let with_sessions = |sessions: Arc<RwLock<Sessions>>| warp::any().map(move || sessions.clone());

    let index = warp::path::end()
        .and(warp::get())
        .map(|| warp::reply::html(INDEX_HTML));

    let authorize = warp::path!("oauth2" / "authorization" / "oidc")
        .and(warp::get())
        .and(with_client(client.clone()))
        .and_then(reply_authorize);

    let login = warp::path!("login" / "oauth2" / "code" / "oidc")
        .and(warp::get())
        .and(with_client(client.clone()))
        .and(warp::query::<LoginQuery>())
        .and(with_sessions(sessions.clone()))
        .and_then(reply_login);

    let api_account = warp::path!("api" / "account")
        .and(warp::get())
        .and(with_user(sessions))
        .map(|user: User| warp::reply::json(&user));

    let routes = index
        .or(authorize)
        .or(login)
        .or(api_account)
        .recover(handle_rejections);

    let logged_routes = routes.with(warp::log("openid_warp_example"));

    warp::serve(logged_routes).run(([127, 0, 0, 1], 8080)).await;

    Ok(())
}

async fn request_token(
    oidc_client: Arc<OpenIDClient>,
    login_query: &LoginQuery,
) -> anyhow::Result<Option<(Token, Userinfo)>> {
    let mut token: Token = oidc_client.request_token(&login_query.code).await?.into();

    if let Some(id_token) = token.id_token.as_mut() {
        oidc_client.decode_token(id_token)?;
        oidc_client.validate_token(id_token, None, None)?;
        info!("token: {:?}", id_token);
    } else {
        return Ok(None);
    }

    let userinfo = oidc_client.request_userinfo(&token).await?;

    info!("user info: {:?}", userinfo);

    Ok(Some((token, userinfo)))
}

async fn reply_login(
    oidc_client: Arc<OpenIDClient>,
    login_query: LoginQuery,
    sessions: Arc<RwLock<Sessions>>,
) -> Result<impl warp::Reply, Infallible> {
    let request_token = request_token(oidc_client, &login_query).await;
    match request_token {
        Ok(Some((token, user_info))) => {
            let id = uuid::Uuid::new_v4().to_string();

            let login = user_info.preferred_username.clone();
            let email = user_info.email.clone();

            let user = User {
                id: user_info.sub.clone().unwrap_or_default(),
                login,
                last_name: user_info.family_name.clone(),
                first_name: user_info.name.clone(),
                email,
                activated: user_info.email_verified,
                image_url: user_info.picture.clone().map(|x| x.to_string()),
                lang_key: Some("en".to_string()),
                authorities: vec!["ROLE_USER".to_string()],
            };

            let authorization_cookie = ::cookie::Cookie::build(EXAMPLE_COOKIE, &id)
                .path("/")
                .http_only(true)
                .finish()
                .to_string();

            sessions
                .write()
                .await
                .map
                .insert(id, (user, token, user_info));

            let redirect_url = login_query.state.clone().unwrap_or_else(|| host("/"));

            Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(warp::http::header::LOCATION, redirect_url)
                .header(warp::http::header::SET_COOKIE, authorization_cookie)
                .body("")
                .unwrap())
        }
        Ok(None) => {
            error!("login error in call: no id_token found");

            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("")
                .unwrap())
        }
        Err(err) => {
            error!("login error in call: {:?}", err);

            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("")
                .unwrap())
        }
    }
}

async fn reply_authorize(oidc_client: Arc<OpenIDClient>) -> Result<impl warp::Reply, Infallible> {
    let origin_url = env::var("ORIGIN").unwrap_or_else(|_| host(""));

    let auth_url = oidc_client.auth_url(&Options {
        scope: Some("openid email profile".into()),
        state: Some(origin_url),
        ..Default::default()
    });

    info!("authorize: {}", auth_url);

    let url: String = auth_url.into();

    Ok(warp::reply::with_header(
        StatusCode::FOUND,
        warp::http::header::LOCATION,
        url,
    ))
}

#[derive(Debug)]
struct Unauthorized;

impl reject::Reject for Unauthorized {}

async fn extract_user(
    session_id: Option<String>,
    sessions: Arc<RwLock<Sessions>>,
) -> Result<User, Rejection> {
    if let Some(session_id) = session_id {
        if let Some((user, _, _)) = sessions.read().await.map.get(&session_id) {
            Ok(user.clone())
        } else {
            Err(warp::reject::custom(Unauthorized))
        }
    } else {
        Err(warp::reject::custom(Unauthorized))
    }
}

fn with_user(
    sessions: Arc<RwLock<Sessions>>,
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    warp::cookie::optional(EXAMPLE_COOKIE)
        .and(warp::any().map(move || sessions.clone()))
        .and_then(extract_user)
}

async fn handle_rejections(err: Rejection) -> Result<impl Reply, Infallible> {
    let code = if err.is_not_found() {
        StatusCode::NOT_FOUND
    } else if let Some(Unauthorized) = err.find() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    Ok(warp::reply::with_status(warp::reply(), code))
}

/// This host is the address, where user would be redirected after initial authorization.
/// For DEV environment with WebPack this is usually something like `http://localhost:9000`.
/// We are using `http://localhost:8080` in all-in-one example.
pub fn host(path: &str) -> String {
    env::var("REDIRECT_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()) + path
}

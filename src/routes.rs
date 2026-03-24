use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use openidconnect::core::{CoreAuthenticationFlow, CoreGenderClaim};
use openidconnect::{
  AccessTokenHash, AuthorizationCode, ConfigurationError, CsrfToken, IdTokenClaims, Nonce,
  OAuth2TokenResponse, PkceCodeChallenge, Scope, TokenResponse,
};
use serde::{self, Serializer};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::AppError::{AuthenticationContextWasNotFulfilled, IdTokenRequired};
use crate::{
  AppError, Cfg, InternalServerError, InvalidAccessToken, InvalidCode, InvalidIdTokenNonce,
  InvalidSession, InvalidState, JitsiState, MissingAccessTokenHash,
  MissingIdTokenAndUserInfoEndpoint, MyClaims, MyClient, MyTokenResponse, MyUserInfoClaims,
  Session, UnableToQueryUserInfo, UnsupportedSigningAlgorithm,
};

const COOKIE_NAME: &str = "JITSI_OPENID_SESSION";
const AUTH_CACHE_COOKIE: &str = "JITSI_AUTH_CACHE";

pub(crate) fn build_routes() -> Router<JitsiState> {
  Router::new()
    .route("/room/{name}", get(room))
    .route("/callback", get(callback))
}

async fn room(
  Path(room): Path<String>,
  State(state): State<JitsiState>,
  jar: CookieJar,
) -> impl IntoResponse {
  // Fix #4: Sanitize room name — only allow alphanumeric, hyphens, underscores
  if !room.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
    warn!("Invalid room name rejected: {}", room);
    return (jar, Redirect::to(state.config.jitsi_url.as_str())).into_response();
  }

  // Check for cached auth cookie — skip OIDC if valid JWT exists
  if let Some(cached_jwt) = jar.get(AUTH_CACHE_COOKIE).map(|c| c.value().to_string()) {
    // Fix #2+#3: Full JWT validation (signature, expiry, issuer, nbf, audience)
    let mut validation = Validation::default();
    validation.set_audience(&["jitsi"]);
    validation.set_issuer(&["jitsi"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "nbf"]);
    validation.leeway = 60; // 60s clock skew tolerance

    match jsonwebtoken::decode::<JitsiClaims>(
      &cached_jwt,
      &DecodingKey::from_secret(state.jitsi_secret.0.as_bytes()),
      &validation,
    ) {
      Ok(_claims) => {
        // JWT is valid — redirect directly to Jitsi with cached JWT
        let mut url = state.config.jitsi_url.join(&room).unwrap();
        url.query_pairs_mut().append_pair("jwt", &cached_jwt);

        if state.config.skip_prejoin_screen.unwrap_or(true) {
          url.set_fragment(Some("config.prejoinConfig.enabled=false"));
        }

        info!("Auth cache hit — skipping OIDC for room: {}", room);
        return (jar, Redirect::to(url.as_str())).into_response();
      }
      Err(err) => {
        // Invalid or expired JWT — remove cache cookie, proceed with OIDC
        // Fix #1: All cookie attributes must match for browser to delete it
        info!("Auth cache expired/invalid ({}), starting OIDC flow", err);
        let remove_cookie = Cookie::build((AUTH_CACHE_COOKIE, ""))
          .domain(
            state
              .config
              .base_url
              .host()
              .expect("Missing host in base url")
              .to_string(),
          )
          .path("/oidc/".to_string())
          .secure(state.config.base_url.scheme() == "https")
          .http_only(true)
          .same_site(axum_extra::extract::cookie::SameSite::Lax)
          .max_age(Duration::ZERO);
        let jar = jar.add(remove_cookie);
        return start_oidc_flow(room, state, jar).await.into_response();
      }
    }
  }

  // No cache cookie — start normal OIDC flow
  start_oidc_flow(room, state, jar).await.into_response()
}

async fn start_oidc_flow(
  room: String,
  state: JitsiState,
  jar: CookieJar,
) -> impl IntoResponse {
  let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

  let mut request = state
    .client
    .authorize_url(
      CoreAuthenticationFlow::AuthorizationCode,
      CsrfToken::new_random,
      Nonce::new_random,
    )
    .set_pkce_challenge(pkce_challenge);

  match state.config.scopes {
    None => {
      request = request
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
    }
    Some(scopes) => {
      for scope in &scopes {
        request = request.add_scope(Scope::new(scope.to_string()));
      }
    }
  };

  if let Some(acr_values) = state.config.acr_values {
    for class in acr_values {
      request = request.add_auth_context_value(class);
    }
  }

  let (auth_url, csrf_token, nonce) = request.url();

  let session_id = Uuid::new_v4();
  state.store.write().await.insert(
    session_id,
    Session {
      room,
      csrf_token,
      nonce,
      pkce_verifier,
    },
  );

  // Build the OIDC state cookie
  let cookie = Cookie::build((COOKIE_NAME, session_id.to_string()))
    .domain(
      state
        .config
        .base_url
        .host()
        .expect("Missing host in base url")
        .to_string(),
    )
    .path(state.config.base_url.path().to_string())
    .secure(state.config.base_url.scheme() == "https")
    .http_only(true)
    .max_age(Duration::minutes(30));

  (jar.add(cookie), Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct Callback {
  state: String,
  // session_state: String,
  code: AuthorizationCode,
}

async fn callback(
  jar: CookieJar,
  Query(callback): Query<Callback>,
  State(state): State<JitsiState>,
) -> Result<impl IntoResponse, AppError> {
  let session_id = match jar
    .get(COOKIE_NAME)
    .map(|cookie| Uuid::parse_str(cookie.value()))
  {
    Some(Ok(session_id)) => session_id,
    Some(Err(_)) => return Err(InvalidSession),
    None => return Err(InvalidSession),
  };

  let session = match state.store.write().await.remove(&session_id) {
    Some(session) => session,
    None => return Err(InvalidSession),
  };

  if &callback.state != session.csrf_token.secret() {
    return Err(InvalidState);
  }

  let response = state
    .client
    .exchange_code(callback.code)
    .map_err(|err| {
      error!("Configuration error: {:?}", err);
      AppError::ConfigurationError
    })?
    .set_pkce_verifier(session.pkce_verifier)
    .request_async(&state.http_client)
    .await
    .map_err(|err| {
      warn!("Authentication failed, Invalid Code: {:?}", err);
      InvalidCode
    })?;

  let jitsi_user = match id_token_claims(&state.config, &state.client, &response, &session.nonce)? {
    None => match user_info_claims(&state.client, &state.http_client, &response).await? {
      None => return Err(MissingIdTokenAndUserInfoEndpoint),
      Some(user) => user,
    },
    Some(user) => user,
  };

  let jwt = create_jitsi_jwt(
    jitsi_user,
    "jitsi".to_string(),
    "jitsi".to_string(),
    state.config.jitsi_sub,
    "*".to_string(),
    state.jitsi_secret.0,
    state.config.group,
    state.config.session_ttl_hours,
  )
  .map_err(|err| {
    error!("Unable to create jwt: {}", err);
    InternalServerError
  })?;

  let mut url = state.config.jitsi_url.join(&session.room).unwrap();
  url.query_pairs_mut().append_pair("jwt", &jwt);

  if state.config.skip_prejoin_screen.unwrap_or(true) {
    url.set_fragment(Some("config.prejoinConfig.enabled=false"));
  }

  // Set auth cache cookie — next room join skips OIDC flow
  // Cookie is first-party (jitsi.amijaki.de), SameSite=Lax works in iFrames
  let ttl_hours = state.config.session_ttl_hours.unwrap_or(2);
  let host = state
    .config
    .base_url
    .host()
    .expect("Missing host in base url")
    .to_string();
  let cache_cookie = Cookie::build((AUTH_CACHE_COOKIE, jwt.clone()))
    .domain(host)
    .path("/oidc/".to_string())
    .secure(state.config.base_url.scheme() == "https")
    .http_only(true)
    .same_site(axum_extra::extract::cookie::SameSite::Lax)
    .max_age(Duration::hours(ttl_hours));

  info!("Auth cache set (TTL: {}h)", ttl_hours);

  Ok((jar.add(cache_cookie), Redirect::to(url.as_str())))
}

fn id_token_claims(
  config: &Cfg,
  client: &MyClient,
  response: &MyTokenResponse,
  nonce: &Nonce,
) -> Result<Option<JitsiUser>, AppError> {
  let id_token = match response.id_token() {
    Some(id_token) => id_token,
    None => {
      return if config.acr_values.is_none() {
        Ok(None)
      } else {
        Err(IdTokenRequired)
      };
    }
  };

  let id_token_verifier = client
    .id_token_verifier()
    .set_other_audience_verifier_fn(|_aud| true);
  let claims = id_token
    .claims(&id_token_verifier, nonce)
    .map_err(InvalidIdTokenNonce)?;

  if let Some(acr_values) = &config.acr_values {
    if let Some(auth_context) = claims.auth_context_ref() {
      if !acr_values.contains(auth_context) {
        return Err(AuthenticationContextWasNotFulfilled);
      }
    } else {
      return Err(AuthenticationContextWasNotFulfilled);
    }
  }

  if config.verify_access_token_hash.unwrap_or(true) {
    match claims.access_token_hash() {
      Some(expected_access_token_hash) => {
        let algorithm = id_token.signing_alg().map_err(|err| {
          warn!(
            "Authentication failed, UnsupportedSigningAlgorithm: {:?}",
            err
          );
          UnsupportedSigningAlgorithm
        })?;

        let actual_access_token_hash = AccessTokenHash::from_token(
          response.access_token(),
          algorithm,
          id_token
            .signing_key(&client.id_token_verifier())
            .map_err(|err| {
              error!("Invalid Signing Key: {:?}", err);
              AppError::InvalidSigningKey
            })?,
        )
        .map_err(|err| {
          warn!(
            "Authentication failed, UnsupportedSigningAlgorithm: {:?}",
            err
          );
          UnsupportedSigningAlgorithm
        })?;

        if &actual_access_token_hash != expected_access_token_hash {
          return Err(InvalidAccessToken);
        }
      }
      None => return Err(MissingAccessTokenHash),
    };
  }

  let uid = match claims.preferred_username() {
    Some(name) => name.to_string(),
    None => claims.subject().to_string(),
  };

  Ok(Some(JitsiUser {
    id: uid,
    email: claims.email().map(|email| email.to_string()),
    affiliation: claims.additional_claims().affiliation.clone(),
    name: get_display_name_id_token(claims),
    avatar: claims
      .picture()
      .and_then(|x| x.get(None))
      .map(|x| x.to_string()),
    moderator: claims.additional_claims().moderator,
  }))
}

async fn user_info_claims(
  client: &MyClient,
  http_client: &reqwest::Client,
  response: &MyTokenResponse,
) -> Result<Option<JitsiUser>, AppError> {
  match client.user_info(response.access_token().clone(), None) {
    Ok(request) => {
      let claims: MyUserInfoClaims = request.request_async(http_client).await.map_err(|err| {
        warn!("Authentication failed, UnableToQueryUserInfo: {:?}", err);
        UnableToQueryUserInfo
      })?;

      Ok(Some(JitsiUser {
        id: match claims.preferred_username() {
          Some(name) => name.to_string(),
          None => claims.subject().to_string(),
        },
        email: claims.email().map(|email| email.to_string()),
        affiliation: claims.additional_claims().affiliation.clone(),
        name: get_display_name(&claims),
        avatar: claims
          .picture()
          .and_then(|x| x.get(None))
          .map(|x| x.to_string()),
        moderator: claims.additional_claims().moderator,
      }))
    }
    Err(ConfigurationError::MissingUrl(_)) => Ok(None),
    Err(err) => {
      error!("Unable to find user info url: {}", err);
      Err(InternalServerError)
    }
  }
}

#[derive(Serialize, Deserialize)]
struct JitsiClaims {
  context: JitsiContext,
  aud: String,
  iss: String,
  sub: String,
  room: String,
  #[serde(serialize_with = "jwt_numeric_date", deserialize_with = "jwt_from_numeric_date")]
  nbf: OffsetDateTime,
  #[serde(serialize_with = "jwt_numeric_date", deserialize_with = "jwt_from_numeric_date")]
  iat: OffsetDateTime,
  #[serde(serialize_with = "jwt_numeric_date", deserialize_with = "jwt_from_numeric_date")]
  exp: OffsetDateTime,
}

#[derive(Serialize, Deserialize)]
struct JitsiContext {
  user: JitsiUser,
  group: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct JitsiUser {
  id: String,
  email: Option<String>,
  affiliation: Option<String>,
  name: Option<String>,
  avatar: Option<String>,
  moderator: Option<bool>,
}

fn create_jitsi_jwt(
  user: JitsiUser,
  aud: String,
  iss: String,
  sub: String,
  room: String,
  secret: String,
  group: String,
  session_ttl_hours: Option<i64>,
) -> anyhow::Result<String> {
  let iat = OffsetDateTime::now_utc();
  // Align JWT exp with session TTL (not 24h) to prevent stale tokens
  let ttl_hours = session_ttl_hours.unwrap_or(2);
  let exp = iat + Duration::hours(ttl_hours);

  let context = JitsiContext {
    user,
    group: Some(group),
  };

  let claims = JitsiClaims {
    context,
    aud,
    iss,
    sub,
    room,
    // nbf = not-before
    nbf: iat, // idk whey some jitsi configurations what this, its basically the same as iat
    iat,
    exp,
  };

  let token = jsonwebtoken::encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(secret.as_bytes()),
  )?;

  Ok(token)
}

/// Deserializes a Unix timestamp to an OffsetDateTime
pub fn jwt_from_numeric_date<'de, D: serde::Deserializer<'de>>(
  deserializer: D,
) -> Result<OffsetDateTime, D::Error> {
  let timestamp: i64 = serde::Deserialize::deserialize(deserializer)?;
  OffsetDateTime::from_unix_timestamp(timestamp).map_err(serde::de::Error::custom)
}

/// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
pub fn jwt_numeric_date<S: Serializer>(
  date: &OffsetDateTime,
  serializer: S,
) -> Result<S::Ok, S::Error> {
  let timestamp = date.unix_timestamp();
  serializer.serialize_i64(timestamp)
}

fn get_display_name_id_token(claims: &IdTokenClaims<MyClaims, CoreGenderClaim>) -> Option<String> {
  if let Some(name) = claims
    .name()
    .or_else(|| claims.name())
    .and_then(|name| name.get(None))
    .map(|name| name.to_string())
  {
    return Some(name);
  }

  let name = [
    claims
      .given_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .middle_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .family_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
  ];

  if !name.is_empty() {
    return Some(
      name
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" "),
    );
  }

  claims.preferred_username().map(|name| name.to_string())
}

fn get_display_name(claims: &MyUserInfoClaims) -> Option<String> {
  if let Some(name) = claims
    .name()
    .or_else(|| claims.name())
    .and_then(|name| name.get(None))
    .map(|name| name.to_string())
  {
    return Some(name);
  }

  let name = [
    claims
      .given_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .middle_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .family_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
  ];

  if !name.is_empty() {
    return Some(
      name
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" "),
    );
  }

  claims.preferred_username().map(|name| name.to_string())
}

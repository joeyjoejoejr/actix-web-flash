use crate::{FlashMessage, FlashMiddleware, FlashResponse, Responder};
use actix_web::http::{Cookie, StatusCode};
use actix_web::test::{self, TestRequest};
use actix_web::{http, web, App, FromRequest, HttpRequest, HttpResponse};

#[cfg(test)]

/// Ensure the response properly sets the `_flash` cookie.
#[actix_rt::test]
async fn sets_cookie() {
    let msg = "Test Message".to_owned();
    let responder = FlashResponse::new(Some(msg.clone()), HttpResponse::Ok().finish());

    let req = TestRequest::default().to_http_request();
    let resp = responder.respond_to(&req).await.unwrap();

    let cookies = resp
        .cookies()
        .filter(|c| c.name() == crate::FLASH_COOKIE_NAME)
        .collect::<Vec<Cookie>>();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name(), crate::FLASH_COOKIE_NAME);
    // JSON serialization means the string is in quotes
    assert_eq!(cookies[0].value(), format!("\"{}\"", msg));
}

#[actix_rt::test]
/// Ensure flash message is extracted from `_flash` cookie.
async fn get_cookie() {
    let req = TestRequest::with_header("Cookie", "_flash=\"Test Message\"").to_http_request();
    let msg = FlashMessage::<String>::extract(&req).await.unwrap();
    assert_eq!(msg.into_inner(), "Test Message");
}

#[actix_rt::test]
/// Ensure improper cookie contents lead to an error.
async fn bad_request() {
    let req = TestRequest::with_header("Cookie", "_flash=Missing quotes").to_http_request();
    let err = FlashMessage::<String>::extract(&req).await.unwrap_err();
    // Don't return raw serialization errors
    assert!(std::error::Error::downcast_ref::<serde_json::error::Error>(&err).is_none());
    let resp = HttpResponse::from(err);
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST)
}

async fn show_flash(flash: FlashMessage<String>) -> impl Responder {
    flash.into_inner()
}

async fn set_flash(_req: HttpRequest) -> FlashResponse<HttpResponse, String> {
    FlashResponse::new(
        Some("This is the message".to_owned()),
        HttpResponse::SeeOther()
            .header(http::header::LOCATION, "/show_flash")
            .finish(),
    )
}

#[actix_rt::test]
/// Integration test to assure the cookie is deleted on request
async fn cookie_is_set() {
    let mut srv = test::init_service(
        App::new()
            .wrap(FlashMiddleware::default())
            .route("/show_flash", web::get().to(show_flash))
            .route("/set_flash", web::get().to(set_flash)),
    ).await;

    let req = test::TestRequest::get().uri("/set_flash").to_request();
    let resp = test::call_service(&mut srv, req).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let cookie = resp.response().cookies().find(|cookie| cookie.name() == "_flash").unwrap();
    assert_eq!(cookie.value(), "\"This is the message\"");
}

#[actix_rt::test]
/// Integration test to assure the cookie is deleted on request
async fn cookie_is_unset() {
    let mut srv = test::init_service(
        App::new()
            .wrap(FlashMiddleware::default())
            .route("/show_flash", web::get().to(show_flash))
            .route("/set_flash", web::get().to(set_flash)),
    ).await;

    let req = test::TestRequest::get().uri("/").cookie(
        http::Cookie::build("_flash", "To be deleted")
            .path("/")
            .finish(),
    ).to_request();
    let resp = test::call_service(&mut srv, req).await;
    println!("{:?}", resp);

    let cookie = resp.response().cookies().find(|cookie| cookie.name() == "_flash").unwrap();
    println!("Cookie: {:?}", cookie);
    assert!(cookie.expires().unwrap() < time::now());
}

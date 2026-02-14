use actix_web::{App, HttpResponse, HttpServer, Result, middleware, web};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::{debug, error, info, warn};
use rcgen::{CertificateParams, DnType};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, gen_keypair};
use std::env;
use std::fs::{self, File};
use std::io::BufReader;
use std::time::{SystemTime, UNIX_EPOCH};

struct Config {
    license_type: i16,
    max_peers: u32,
    max_users: u32,
    max_conns: u32,
    expiry_secs: i64,
}

#[derive(Debug, Deserialize)]
struct CheckLicenseRequest {
    nonce: String,
    machine: Option<Machine>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Machine {
    hostname: String,
    mac: String,
}

#[derive(Debug, Serialize)]
struct LicenseResponsePayload {
    nonce: String,
    expiry: i64,
    #[serde(rename = "type")]
    license_type: i16,
    max_peers: u32,
    max_users: u32,
    max_conns: u32,
    next_check_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine: Option<Machine>,
}

#[derive(Debug, Serialize)]
struct Response {
    code: i32,
    version: String,
    payload_enc: String,
    error_msg: Option<String>,
}

// --- 密钥处理逻辑 ---

// 从 Base64 字符串读取密钥 (Load keys from Base64 strings)
fn load_keys_from_b64(priv_b64: &str, pub_b64: &str) -> (SecretKey, PublicKey) {
    debug!("开始加载Ed25519密钥对");
    let priv_bytes = BASE64
        .decode(priv_b64.trim())
        .expect("Invalid Base64 for SecretKey");
    let pub_bytes = BASE64
        .decode(pub_b64.trim())
        .expect("Invalid Base64 for PublicKey");

    let sk = SecretKey::from_slice(&priv_bytes).expect("SecretKey length must be 64 bytes");
    let pk = PublicKey::from_slice(&pub_bytes).expect("PublicKey length must be 32 bytes");
    info!("Ed25519密钥对加载成功");
    (sk, pk)
}

// 生成密钥对和证书 (Keygen Mode: Generate Ed25519 and HTTPS Certs)
fn run_keygen() {
    info!("执行密钥生成 (Running Keygen)...");

    // 1. 生成 Ed25519 密钥对 (Sodiumoxide)
    let (pk, sk) = gen_keypair();
    fs::write("id_ed25519", BASE64.encode(sk.as_ref())).unwrap();
    fs::write("id_ed25519.pub", BASE64.encode(pk.as_ref())).unwrap();
    info!("√ Ed25519 密钥已保存 (Raw Base64)");

    // 2. 生成 HTTPS 自签名证书 (rcgen)
    // 生成 CA
    let mut ca_params = CertificateParams::new(vec![]);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "RustDesk Self-Signed CA");
    let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

    // 生成服务器证书 (域名: rustdesk.com)
    let mut server_params =
        CertificateParams::new(vec!["rustdesk.com".to_string(), "localhost".to_string()]);
    server_params
        .distinguished_name
        .push(DnType::CommonName, "rustdesk.com");
    let server_cert = rcgen::Certificate::from_params(server_params).unwrap();

    // 导出文件
    fs::write("ca.crt", ca_cert.serialize_pem().unwrap()).unwrap();
    fs::write(
        "server.crt",
        server_cert.serialize_pem_with_signer(&ca_cert).unwrap(),
    )
    .unwrap();
    fs::write("server.key", server_cert.serialize_private_key_pem()).unwrap();
    info!("√ HTTPS 证书已生成 (Domain: rustdesk.com)");
}

// 修补 hbbs 二进制文件 (Patch Mode: Replace embedded public key)
fn run_patch() {
    info!("执行二进制文件修补 (Running Patch)...");

    let hbbs_path = env::var("HBBS_PATH").unwrap_or_else(|_| "/usr/bin/hbbs".to_string());
    let backup_path =
        env::var("HBBS_BACKUP_PATH").unwrap_or_else(|_| "/usr/bin/hbbs-official".to_string());
    let original_key_path =
        env::var("ORIGINAL_KEY_PATH").unwrap_or_else(|_| "./original_ed25519.pub".to_string());
    let new_key_path = env::var("NEW_KEY_PATH").unwrap_or_else(|_| "./id_ed25519.pub".to_string());

    info!(
        "配置路径: hbbs={}, backup={}, original_key={}, new_key={}",
        hbbs_path, backup_path, original_key_path, new_key_path
    );

    // 1. 备份原始文件
    info!("备份原始文件: {} -> {}", hbbs_path, backup_path);
    if let Err(e) = fs::copy(&hbbs_path, &backup_path) {
        error!("备份文件失败: {}", e);
        panic!("Failed to backup hbbs file");
    }
    info!("√ 原始文件备份完成");

    // 2. 读取原始公钥
    let original_key_b64 = fs::read_to_string(&original_key_path)
        .unwrap_or_else(|e| {
            error!("无法读取原始公钥文件 {}: {}", original_key_path, e);
            panic!("Missing original public key file");
        })
        .trim()
        .to_string();

    // 3. 读取新公钥
    let new_key_b64 = fs::read_to_string(&new_key_path)
        .unwrap_or_else(|e| {
            error!("无法读取新公钥文件 {}: {}", new_key_path, e);
            panic!("Missing new public key file");
        })
        .trim()
        .to_string();

    info!("原始公钥: {}", original_key_b64);
    info!("新公钥: {}", new_key_b64);

    // 4. 验证密钥格式（确保能正确解码）
    let original_key_bytes = BASE64
        .decode(&original_key_b64)
        .expect("Invalid Base64 for original public key");
    let new_key_bytes = BASE64
        .decode(&new_key_b64)
        .expect("Invalid Base64 for new public key");

    if original_key_bytes.len() != new_key_bytes.len() {
        error!(
            "公钥长度不匹配: 原始={}, 新={}",
            original_key_bytes.len(),
            new_key_bytes.len()
        );
        panic!("Key length mismatch");
    }

    // 5. 读取二进制文件内容
    let mut binary_data = fs::read(&hbbs_path).unwrap_or_else(|e| {
        error!("无法读取二进制文件 {}: {}", hbbs_path, e);
        panic!("Failed to read hbbs binary");
    });

    // 6. 将Base64字符串转为ASCII字节进行二进制搜索和替换
    let original_key_ascii = original_key_b64.as_bytes();
    let new_key_ascii = new_key_b64.as_bytes();

    if original_key_ascii.len() != new_key_ascii.len() {
        error!(
            "Base64字符串长度不匹配: 原始={}, 新={}",
            original_key_ascii.len(),
            new_key_ascii.len()
        );
        panic!("Base64 string length mismatch");
    }

    let mut replaced = false;
    let mut pos = 0;
    let mut replacement_count = 0;

    while pos <= binary_data.len().saturating_sub(original_key_ascii.len()) {
        if binary_data[pos..pos + original_key_ascii.len()] == *original_key_ascii {
            info!("找到原始公钥字符串，位置: 0x{:x}", pos);
            binary_data[pos..pos + new_key_ascii.len()].copy_from_slice(new_key_ascii);
            replaced = true;
            replacement_count += 1;
            info!("√ 公钥替换完成，位置: 0x{:x}", pos);

            // 跳过已替换的部分，继续搜索
            pos += original_key_ascii.len();
        } else {
            pos += 1;
        }
    }

    if !replaced {
        error!("在二进制文件中未找到原始公钥字符串: {}", original_key_b64);
        panic!("Original public key string not found in binary");
    }

    info!("找到并替换了 {} 处公钥出现位置", replacement_count);

    // 7. 写回修补后的文件
    fs::write(&hbbs_path, &binary_data).unwrap_or_else(|e| {
        error!("写入修补文件失败: {}", e);
        panic!("Failed to write patched binary");
    });

    info!("√ 二进制文件修补完成");

    // 8. 设置可执行权限 (Unix系统)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hbbs_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hbbs_path, perms).unwrap();
        info!("√ 设置可执行权限完成");
    }
}

// --- Web 服务逻辑 ---

// 404 处理器
async fn not_found(req: actix_web::HttpRequest) -> Result<HttpResponse> {
    let path = req.path();
    let method = req.method();
    let remote_addr = req
        .connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string();

    warn!("404 Not Found: {} {} from {}", method, path, remote_addr);

    Ok(HttpResponse::NotFound().json(serde_json::json!({
        "code": 404,
        "error_msg": "Resource not found",
        "path": path,
        "method": method.as_str()
    })))
}

async fn license_check(
    req: web::Json<CheckLicenseRequest>,
    config: web::Data<Config>,
    keys: web::Data<(SecretKey, PublicKey)>,
) -> HttpResponse {
    info!(
        "收到许可证验证请求: nonce={}, machine={:?}",
        req.nonce, req.machine
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let payload = LicenseResponsePayload {
        nonce: req.nonce.clone(),
        expiry: now + config.expiry_secs,
        license_type: config.license_type,
        max_peers: config.max_peers,
        max_users: config.max_users,
        max_conns: config.max_conns,
        next_check_time: 86400 * 30,
        machine: req.machine.clone(),
    };

    let payload_json = serde_json::to_string(&payload).unwrap();
    debug!("许可证载荷JSON: {}", payload_json);

    let signed = sign::sign(payload_json.as_bytes(), &keys.0);
    // 使用 NO_PAD 模式匹配客户端
    let payload_enc = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&signed);

    info!(
        "许可证验证成功: nonce={}, expiry={}, type={}",
        payload.nonce, payload.expiry, payload.license_type
    );

    HttpResponse::Ok().json(Response {
        code: 0,
        version: "1.7.5".to_string(),
        payload_enc,
        error_msg: None,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 初始化日志系统
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_secs()
        .init();

    info!("RustDesk License Server 正在启动...");

    sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    info!("Sodiumoxide 初始化成功");

    let args: Vec<String> = env::args().collect();
    if args.contains(&"--keygen".to_string()) {
        run_keygen();
        return Ok(());
    }

    if args.contains(&"--patch".to_string()) {
        run_patch();
        return Ok(());
    }

    // 从环境变量读取文件路径 (Read paths from ENV)
    let crt_path = env::var("LICENSE_SERVER_CRT").unwrap_or_else(|_| "server.crt".to_string());
    let key_path = env::var("LICENSE_SERVER_PRIV").unwrap_or_else(|_| "server.key".to_string());
    let sign_pub_path =
        env::var("LICENSE_SIGNKEY_PUB").unwrap_or_else(|_| "id_ed25519.pub".to_string());
    let sign_priv_path =
        env::var("LICENSE_SIGNKEY_PRIV").unwrap_or_else(|_| "id_ed25519".to_string());

    // 从文件读取 Base64 密钥内容 (Read Base64 content from files)
    info!(
        "加载签名密钥: 私钥={}, 公钥={}",
        sign_priv_path, sign_pub_path
    );
    let (sk, pk) = load_keys_from_b64(
        &fs::read_to_string(&sign_priv_path).unwrap_or_else(|e| {
            error!("无法读取私钥文件 {}: {}", sign_priv_path, e);
            panic!("Missing private key file")
        }),
        &fs::read_to_string(&sign_pub_path).unwrap_or_else(|e| {
            error!("无法读取公钥文件 {}: {}", sign_pub_path, e);
            panic!("Missing public key file")
        }),
    );

    // 读取业务配置 (Read business config from ENV)
    let license_type: i16 = env::var("LICENSE_TYPE")
        .unwrap_or("2".into())
        .parse()
        .unwrap();
    let max_peers: u32 = env::var("LICENSE_MAX_PEERS")
        .unwrap_or("999999999".into())
        .parse()
        .unwrap();
    let max_users: u32 = env::var("LICENSE_MAX_USERS")
        .unwrap_or("999999999".into())
        .parse()
        .unwrap();
    let max_conns: u32 = env::var("LICENSE_MAX_CONNS")
        .unwrap_or("999999999".into())
        .parse()
        .unwrap();
    let expiry_secs: i64 = env::var("LICENSE_EXPIRY_SECS")
        .unwrap_or("315360000".into())
        .parse()
        .unwrap(); // 默认10年

    info!(
        "业务配置加载完成: type={}, max_peers={}, max_users={}, max_conns={}, expiry_secs={}",
        license_type, max_peers, max_users, max_conns, expiry_secs
    );

    let config = web::Data::new(Config {
        license_type,
        max_peers,
        max_users,
        max_conns,
        expiry_secs,
    });

    let keys_data = web::Data::new((sk, pk));

    // 加载 TLS
    info!("加载TLS证书: cert={}, key={}", crt_path, key_path);
    let tls_config = {
        let cert_file = &mut BufReader::new(File::open(&crt_path).unwrap_or_else(|e| {
            error!("无法打开证书文件 {}: {}", crt_path, e);
            panic!("Failed to open certificate file")
        }));
        let key_file = &mut BufReader::new(File::open(&key_path).unwrap_or_else(|e| {
            error!("无法打开密钥文件 {}: {}", key_path, e);
            panic!("Failed to open private key file")
        }));
        let cert_chain = certs(cert_file)
            .unwrap()
            .into_iter()
            .map(Certificate)
            .collect();
        let mut keys = pkcs8_private_keys(key_file).unwrap();
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, PrivateKey(keys.remove(0)))
            .expect("TLS config error")
    };
    info!("TLS配置加载成功");

    info!("服务启动在 https://0.0.0.0");
    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .app_data(keys_data.clone())
            .wrap(
                middleware::Logger::new(
                    "%a \\\"%r\\\" %s %b \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\" %T",
                )
                .log_target("actix_web::middleware::logger"),
            )
            .route("/api/lic/license/check", web::post().to(license_check))
            .default_service(web::to(not_found))
    })
    .bind_rustls_021("0.0.0.0:443", tls_config)?
    .run()
    .await
}

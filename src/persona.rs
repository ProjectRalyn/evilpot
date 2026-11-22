use bytes::Bytes;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// An immutable snapshot of all pre-baked server personas for a single rotation epoch.
#[derive(Debug, Clone)]
pub struct PersonaSnapshot {
    pub epoch_id: u64,
    pub generated_at_unix: u64,
    pub personas: Vec<Arc<PrebakedPersona>>,
}

impl PersonaSnapshot {
    pub fn bake(
        master_seed: u64,
        epoch_id: u64,
        num_slots: usize,
        canary_webhook_url: &str,
    ) -> Self {
        let slots = num_slots.max(1);
        let generated_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut personas = Vec::with_capacity(slots);
        for slot_id in 0..slots {
            let persona =
                PrebakedPersona::bake(master_seed, epoch_id, slot_id, canary_webhook_url);
            personas.push(Arc::new(persona));
        }

        Self {
            epoch_id,
            generated_at_unix,
            personas,
        }
    }
}

/// A single pre-generated server persona with zero-copy `Bytes` HTTP payloads,
/// implanted canary tokens/paths for exploit verification, and an in-memory Linux VFS
/// for OS command injection (`FakeShellSession`).
#[derive(Debug, Clone)]
pub struct PrebakedPersona {
    pub epoch_id: u64,
    pub slot_id: usize,
    pub hostname: String,
    pub internal_ip: String,
    pub server_header: String,
    pub powered_by_header: String,
    pub admin_user: String,
    pub db_secret_row: String,

    // Implanted canary verification tokens & paths unique to this persona slot/epoch!
    // If an incoming request presents any of these, evilpot immediately verifies 100% real exploitation.
    pub canary_token_id: String,
    pub canary_api_key: String,
    pub canary_aws_access_key: String,
    pub canary_jwt_secret: String,
    pub canary_cookie_value: String,
    pub canary_endpoint_path: String,
    pub canary_url: String,

    // Deep WordPress pre-baked HTTP bodies
    pub wp_version: String,
    pub wp_cookie_hash: String,
    pub wp_login_html: Bytes,
    pub wp_login_error_html: Bytes,
    pub wp_json_index: Bytes,
    pub wp_users_json: Bytes,
    pub wp_posts_json: Bytes,
    pub wp_xmlrpc_fault_xml: Bytes,
    pub wp_xmlrpc_methods_xml: Bytes,
    pub wp_config_bak: Bytes,
    pub wp_debug_log: Bytes,
    pub wp_admin_ajax_json: Bytes,
    pub wp_readme_html: Bytes,

    // Secret leak & API pre-baked HTTP bodies
    pub dotenv_body: Bytes,
    pub git_config_body: Bytes,
    pub git_head_body: Bytes,
    pub actuator_env_json: Bytes,
    pub phpinfo_html: Bytes,
    pub graphql_introspection_json: Bytes,
    pub openapi_json: Bytes,
    pub api_debug_json: Bytes,
    pub canary_vault_export_json: Bytes,
    pub sqli_error_mysql_html: Bytes,
    pub sqli_error_postgres_html: Bytes,
    pub sqli_boolean_true_html: Bytes,
    pub sqli_boolean_false_html: Bytes,
    pub tarpit_gzip_chunk: Bytes,
    pub tarpit_hprof_chunk: Bytes,

    // Pre-baked payloads tailored for the 12 attack categories
    pub lfi_etc_passwd_body: Bytes,
    pub lfi_proc_environ_body: Bytes,
    pub ssrf_aws_imds_json: Bytes,
    pub ssti_eval_html: Bytes,
    pub nosql_dump_json: Bytes,
    pub xxe_response_xml: Bytes,
    pub deser_jndi_trace_html: Bytes,
    pub ldap_dump_ldif: Bytes,
    pub xss_bait_html: Bytes,
    pub crlf_proxy_debug_html: Bytes,

    // In-memory Linux VFS template for FakeShellSession (Command Injection RCE verification)
    pub shell_vfs: ShellVfsData,
}

#[derive(Debug, Clone)]
pub struct ShellVfsData {
    pub default_user: String,
    pub kernel_uname: String,
    pub kernel_release: String,
    pub motd: String,
    pub nvidia_smi_output: String,
    pub ps_aux_output: String,
    pub top_output: String,
    pub netstat_output: String,
    pub ip_addr_output: String,
    pub ip_route_output: String,
    pub lscpu_output: String,
    pub lspci_output: String,
    pub lsblk_output: String,
    pub mount_output: String,
    pub dmesg_output: String,
    pub systemctl_output: String,
    pub docker_ps_output: String,
    pub docker_images_output: String,
    pub kubectl_pods_output: String,
    pub kubectl_secrets_output: String,
    pub last_output: String,
    pub w_output: String,
    pub sudo_l_output: String,
    pub crontab_output: String,
    pub iptables_output: String,
    pub files: HashMap<String, String>,
    pub directories: HashMap<String, Vec<String>>,
}

impl PrebakedPersona {
    pub fn bake(
        master_seed: u64,
        epoch_id: u64,
        slot_id: usize,
        canary_webhook_url: &str,
    ) -> Self {
        let combined_seed = master_seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(epoch_id.wrapping_mul(0xBF58_476D_1CE4_E5B9))
            .wrapping_add((slot_id as u64).wrapping_mul(0x94D0_49BB_1331_11EB));
        let mut rng = StdRng::seed_from_u64(combined_seed);

        let host_prefixes = [
            "gpu-train-node",
            "fin-ledger-db",
            "k8s-vault-gw",
            "prod-wp-cms",
            "ai-infer-cluster",
            "pay-core-api",
            "erp-legacy-srv",
            "ci-artifact-hub",
        ];
        let prefix = host_prefixes[rng.gen_range(0..host_prefixes.len())];
        let node_num = rng.gen_range(1..=32);
        let hostname = format!("{prefix}-{node_num:02}");
        let internal_ip = format!("10.240.{}.{}", rng.gen_range(10..200), rng.gen_range(10..250));

        let server_headers = [
            ("Apache/2.4.49 (Ubuntu)", "PHP/7.4.21"),
            ("nginx/1.18.0 (Ubuntu)", "PHP/8.0.12"),
            ("openresty/1.19.9.1", "PHP/7.4.33"),
            ("Apache/2.4.50 (Debian)", "PHP/7.3.31-1~deb10u1"),
            ("nginx/1.20.1", "PHP/8.1.9"),
        ];
        let (server_header, powered_by) = server_headers[rng.gen_range(0..server_headers.len())];

        let aws_access_key = format!("AKIA{}", random_alnum(&mut rng, 16, true));
        let aws_secret_key = random_alnum(&mut rng, 40, false);
        let db_pass = format!("Pr0d_{}_{}!", random_alnum(&mut rng, 10, false), epoch_id % 997);
        let redis_pass = format!("Rds_{}_{}#", random_alnum(&mut rng, 10, false), epoch_id % 509);
        let jwt_secret = random_hex(&mut rng, 48);
        let stripe_key = format!("sk_live_51{}", random_alnum(&mut rng, 28, false));
        let wp_nonce = format!("epk_{}", random_hex(&mut rng, 16));
        let wp_cookie_hash = random_hex(&mut rng, 32);
        let admin_user = [
            "svc_deploy",
            "admin_ops",
            "gpu_scheduler",
            "db_maint",
            "release_bot",
        ][rng.gen_range(0..5)]
        .to_string();
        let fake_bcrypt = format!(
            "$2y$10${}.{}",
            random_alnum(&mut rng, 22, false),
            random_alnum(&mut rng, 31, false)
        );
        let fake_wp_phpass = format!("$P$B{}", random_alnum(&mut rng, 30, false));
        let db_secret_row = format!("{admin_user}:{fake_bcrypt}:role=superadmin:token={wp_nonce}");

        let canary_token_id = random_hex(&mut rng, 16);
        let canary_endpoint_path = format!("/api/v1/internal/vault-export/{canary_token_id}");
        let canary_url = format!(
            "{}/{}/epoch-{}/slot-{}",
            canary_webhook_url.trim_end_matches('/'),
            canary_token_id,
            epoch_id,
            slot_id
        );

        // ====================================================================
        // 1. Realistic WordPress Full Suite
        // ====================================================================
        let wp_version = ["5.8.1", "5.9.3", "6.0.2", "6.1.1"][rng.gen_range(0..4)].to_string();
        let wp_login_html = Bytes::from(format!(
            r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; {hostname} Enterprise CMS &#8212; WordPress</title>
<meta name="generator" content="WordPress {wp_version}" />
<link rel='dns-prefetch' href='//s.w.org' />
<link rel='stylesheet' id='dashicons-css' href='/wp-includes/css/dashicons.min.css?ver={wp_version}' media='all' />
<link rel='stylesheet' id='buttons-css' href='/wp-includes/css/buttons.min.css?ver={wp_version}' media='all' />
<link rel='stylesheet' id='login-css' href='/wp-admin/css/login.min.css?ver={wp_version}' media='all' />
<link rel="https://api.w.org/" href="http://{hostname}.internal/wp-json/" />
<!-- active-plugins: wp-file-manager/6.8, revslider/6.5.8, duplicator-pro/4.5.1, redis-cache/2.2.0 -->
</head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
<div id="login">
  <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p>
      <label for="user_login">Username or Email Address</label>
      <input type="text" name="log" id="user_login" class="input" value="{admin_user}" size="20" autocapitalize="off" autocomplete="username" />
    </p>
    <div class="user-pass-wrap">
      <label for="user_pass">Password</label>
      <div class="wp-pwd">
        <input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" />
      </div>
    </div>
    <p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> <label for="rememberme">Remember Me</label></p>
    <p class="submit">
      <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
      <input type="hidden" name="redirect_to" value="http://{hostname}.internal/wp-admin/" />
      <input type="hidden" name="testcookie" value="1" />
      <input type="hidden" name="_wpnonce" value="{wp_nonce}" />
    </p>
  </form>
  <p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>
"#
        ));

        let wp_login_error_html = Bytes::from(format!(
            r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; {hostname} Enterprise CMS &#8212; WordPress</title>
<meta name="generator" content="WordPress {wp_version}" />
</head>
<body class="login login-action-login wp-core-ui">
<div id="login">
  <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
  <div id="login_error">	<strong>Error:</strong> The password you entered for the username <strong>{admin_user}</strong> is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a><br /></div>
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p><label for="user_login">Username or Email Address</label>
    <input type="text" name="log" id="user_login" class="input" value="{admin_user}" size="20" /></p>
    <p><label for="user_pass">Password</label>
    <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></p>
    <input type="hidden" name="_wpnonce" value="{wp_nonce}" />
    <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In" /></p>
  </form>
</div>
</body>
</html>
"#
        ));

        let wp_json_index = Bytes::from(format!(
            r#"{{
  "name": "{hostname} Internal Operations Portal",
  "description": "Production Cluster Asset & Key Management CMS",
  "url": "http://{hostname}.internal",
  "home": "http://{hostname}.internal",
  "gmt_offset": "0",
  "timezone_string": "UTC",
  "namespaces": [
    "oembed/1.0",
    "wp/v2",
    "wp-site-health/v1",
    "wc/v3",
    "wp-file-manager/v1"
  ],
  "authentication": {{
    "application-passwords": {{
      "endpoints": {{
        "authorization": "http://{hostname}.internal/wp-admin/authorize-application.php"
      }}
    }}
  }},
  "routes": {{
    "/": {{"namespace": "", "methods": ["GET"]}},
    "/wp/v2/users": {{"namespace": "wp/v2", "methods": ["GET", "POST"]}},
    "/wp/v2/posts": {{"namespace": "wp/v2", "methods": ["GET", "POST"]}},
    "{canary_endpoint_path}": {{"namespace": "wp-site-health/v1", "methods": ["GET", "POST"]}}
  }}
}}
"#
        ));

        let wp_users_json = Bytes::from(format!(
            r#"[
  {{
    "id": 1,
    "name": "{admin_user}",
    "url": "http://{hostname}.internal",
    "description": "Cluster SuperAdmin (SSH & DB Vault Sync Account - MFA temporarily disabled for migration)",
    "link": "http://{hostname}.internal/author/{admin_user}/",
    "slug": "{admin_user}",
    "roles": ["administrator"],
    "avatar_urls": {{"24": "https://secure.gravatar.com/avatar/{}?s=24&d=mm&r=g", "96": "https://secure.gravatar.com/avatar/{}?s=96&d=mm&r=g"}},
    "meta": {{"persisted_preferences": [], "legacy_api_token": "{wp_nonce}", "vault_export_path": "{canary_endpoint_path}", "sso_verify_endpoint": "{canary_url}"}}
  }},
  {{
    "id": 2,
    "name": "wp_backup_cron",
    "url": "",
    "description": "Nightly mysqldump & pg_dump automation worker",
    "link": "http://{hostname}.internal/author/wp_backup_cron/",
    "slug": "wp_backup_cron",
    "roles": ["editor"],
    "avatar_urls": {{"24": "https://secure.gravatar.com/avatar/00000000000000000000000000000000?s=24&d=mm"}}
  }}
]
"#,
            &wp_cookie_hash[..32],
            &wp_cookie_hash[..32]
        ));

        let wp_posts_json = Bytes::from(format!(
            r#"[
  {{
    "id": 104,
    "date": "2026-11-18T09:14:22",
    "slug": "internal-db-redis-migration-notes",
    "status": "publish",
    "type": "post",
    "title": {{"rendered": "[INTERNAL] Q4 PostgreSQL &amp; Redis Cluster Failover Runbook ({hostname})"}},
    "content": {{"rendered": "<p>During maintenance window, export vault secrets via <code>{canary_endpoint_path}</code> with header <code>X-Api-Key: {wp_nonce}</code>. Emergency token validation webhook: <a href=\"{canary_url}\">{canary_url}</a></p>", "protected": false}},
    "author": 1
  }}
]
"#
        ));

        let wp_xmlrpc_fault_xml = Bytes::from(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member><name>faultCode</name><value><int>403</int></value></member>
        <member><name>faultString</name><value><string>Incorrect username or password. (user='{admin_user}', hash_prefix='{fake_wp_phpass:.12}', debug_token='{wp_nonce}', backend='{hostname}')</string></value></member>
      </struct>
    </value>
  </fault>
</methodResponse>
"#
        ));

        let wp_xmlrpc_methods_xml = Bytes::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>system.multicall</string></value>
            <value><string>system.listMethods</string></value>
            <value><string>wp.getUsersBlogs</string></value>
            <value><string>wp.getUsers</string></value>
            <value><string>wp.uploadFile</string></value>
            <value><string>pingback.ping</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>
"#,
        );

        let wp_config_bak = Bytes::from(format!(
            r#"<?php
/**
 * The base configuration for WordPress on node {hostname}
 * Backup created before Redis Object Cache migration.
 */
define( 'DB_NAME', 'wp_prod_enterprise' );
define( 'DB_USER', '{admin_user}' );
define( 'DB_PASSWORD', '{db_pass}' );
define( 'DB_HOST', '{internal_ip}:3306' );
define( 'DB_CHARSET', 'utf8mb4' );

/** Redis Object Cache & PostgreSQL Analytics Bridge */
define( 'WP_REDIS_HOST', '{internal_ip}' );
define( 'WP_REDIS_PORT', 6379 );
define( 'WP_REDIS_PASSWORD', '{redis_pass}' );
define( 'PG_ANALYTICS_DSN', 'pgsql:host={internal_ip};port=5432;dbname=prod_core_ledger;user={admin_user};password={db_pass}' );

/** Authentication Unique Keys and Salts. */
define( 'AUTH_KEY',         '{jwt_secret}' );
define( 'SECURE_AUTH_KEY',  '{aws_secret_key}' );
define( 'AWS_S3_UPLOADS_KEY', '{aws_access_key}' );
define( 'AWS_S3_UPLOADS_SECRET', '{aws_secret_key}' );
define( 'INTERNAL_API_BYPASS_TOKEN', '{wp_nonce}' );
define( 'INTERNAL_VAULT_EXPORT_PATH', '{canary_endpoint_path}' );
define( 'INTERNAL_CANARY_PING', '{canary_url}' );

$table_prefix = 'wp_prod_';
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
"#
        ));

        let wp_debug_log = Bytes::from(format!(
            r#"[22-Nov-2026 03:14:09 UTC] PHP Notice:  Undefined index: HTTP_X_FORWARDED_HOST in /var/www/html/wp-config.php on line 92
[22-Nov-2026 03:18:44 UTC] WordPress database error Deadlock found when trying to get lock for query UPDATE wp_prod_options SET option_value = '{aws_access_key}:{aws_secret_key}' WHERE option_name = 's3_backup_credentials' made by do_action_ref_array('wp_nightly_s3_sync')
[22-Nov-2026 04:02:11 UTC] PHP Warning:  Vault Export API triggered on {canary_endpoint_path} with X-Api-Key: {wp_nonce}
[22-Nov-2026 04:15:00 UTC] SSO Webhook Retry queued: curl -X POST -H "Authorization: Bearer {jwt_secret}" {canary_url}
"#
        ));

        let wp_admin_ajax_json = Bytes::from(format!(
            r#"{{"success":false,"data":{{"message":"Invalid security nonce for action. Expected nonce '{wp_nonce}' on node '{hostname}'","debug_user":"{admin_user}","vault_export":"{canary_endpoint_path}","plugin":"wp-file-manager-pro-6.8"}}}}"#
        ));

        let wp_readme_html = Bytes::from(format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8" /><title>WordPress &rsaquo; ReadMe</title></head>
<body><h1 id="logo"><a href="https://wordpress.org/">WordPress</a></h1>
<p style="text-align: center">Version {wp_version} (Enterprise Build - Node {hostname})</p>
<h2>Installation: Famous 5-Minute Install</h2></body></html>
"#
        ));

        // ====================================================================
        // 2. Secret Leaks, API Schemas, SQLi Payloads & Tarpit Chunks
        // ====================================================================
        let dotenv_body = Bytes::from(format!(
            r#"# Auto-generated production environment - DO NOT COMMIT
APP_NAME={hostname}
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:{}

DB_CONNECTION=pgsql
DB_HOST={internal_ip}
DB_PORT=5432
DB_DATABASE=prod_core_ledger
DB_USERNAME={admin_user}
DB_PASSWORD="{db_pass}"

REDIS_HOST={internal_ip}
REDIS_PORT=6379
REDIS_PASSWORD="{redis_pass}"

AWS_ACCESS_KEY_ID={aws_access_key}
AWS_SECRET_ACCESS_KEY={aws_secret_key}
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET={hostname}-db-backups-private

JWT_SECRET={jwt_secret}
ADMIN_BYPASS_TOKEN={wp_nonce}
INTERNAL_VAULT_EXPORT_ENDPOINT={canary_endpoint_path}
STRIPE_SECRET_KEY={stripe_key}
INTERNAL_SSO_VALIDATION_WEBHOOK={canary_url}
"#,
            random_alnum(&mut rng, 44, false)
        ));

        let git_token = random_alnum(&mut rng, 24, false);
        let git_config_body = Bytes::from(format!(
            r#"[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://oauth2:glpat-{git_token}@git.internal.corp/{hostname}/monorepo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "release/prod-hotfix"]
	remote = origin
	merge = refs/heads/release/prod-hotfix
[deploy]
	vaultExportPath = {canary_endpoint_path}
	apiToken = {wp_nonce}
"#
        ));
        let git_head_body = Bytes::from("ref: refs/heads/release/prod-hotfix\n");

        let actuator_env_json = Bytes::from(format!(
            r#"{{
  "activeProfiles": ["production", "legacy-auth-compat"],
  "propertySources": [
    {{
      "name": "systemEnvironment",
      "properties": {{
        "HOSTNAME": {{"value": "{hostname}"}},
        "SPRING_DATASOURCE_URL": {{"value": "jdbc:postgresql://{internal_ip}:5432/prod_core_ledger?user={admin_user}&password={db_pass}"}},
        "SPRING_REDIS_PASSWORD": {{"value": "{redis_pass}"}},
        "AWS_ACCESS_KEY_ID": {{"value": "{aws_access_key}"}},
        "AWS_SECRET_ACCESS_KEY": {{"value": "{aws_secret_key}"}},
        "INTERNAL_ADMIN_API_TOKEN": {{"value": "{wp_nonce}"}},
        "INTERNAL_VAULT_EXPORT_URI": {{"value": "{canary_endpoint_path}"}},
        "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE": {{"value": "env,heapdump,threaddump,mappings"}},
        "INTERNAL_CANARY_CALLBACK": {{"value": "{canary_url}"}}
      }}
    }}
  ]
}}
"#
        ));

        let phpinfo_html = Bytes::from(format!(
            r#"<!DOCTYPE html><html><head><title>phpinfo() - {hostname}</title></head>
<body><h1>PHP Version 7.4.21</h1>
<table>
<tr><td>System</td><td>Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64</td></tr>
<tr><td>Loaded Configuration File</td><td>/etc/php/7.4/fpm/php.ini</td></tr>
<tr><td>$_ENV['DB_PASSWORD']</td><td>{db_pass}</td></tr>
<tr><td>$_ENV['REDIS_PASSWORD']</td><td>{redis_pass}</td></tr>
<tr><td>$_ENV['AWS_ACCESS_KEY_ID']</td><td>{aws_access_key}</td></tr>
<tr><td>$_ENV['AWS_SECRET_ACCESS_KEY']</td><td>{aws_secret_key}</td></tr>
<tr><td>$_ENV['ADMIN_BYPASS_TOKEN']</td><td>{wp_nonce}</td></tr>
<tr><td>$_ENV['VAULT_EXPORT_URI']</td><td>{canary_endpoint_path}</td></tr>
<tr><td>$_ENV['SSO_TOKEN_VERIFY_URL']</td><td>{canary_url}</td></tr>
</table></body></html>
"#
        ));

        let graphql_introspection_json = Bytes::from(format!(
            r#"{{
  "data": {{
    "__schema": {{
      "queryType": {{"name": "Query"}},
      "mutationType": {{"name": "Mutation"}},
      "types": [
        {{
          "kind": "OBJECT",
          "name": "Query",
          "fields": [
            {{
              "name": "internalAdminUsers",
              "description": "DEPRECATED: Requires header Authorization: Bearer {wp_nonce} or endpoint {canary_endpoint_path}",
              "args": [{{"name": "rawWhereClause", "type": {{"name": "String"}}}}],
              "type": {{"name": "UserList"}}
            }},
            {{
              "name": "exportVaultCredentials",
              "description": "Cluster node {hostname} emergency key export",
              "args": [],
              "type": {{"name": "VaultExport"}}
            }}
          ]
        }}
      ]
    }}
  }}
}}
"#
        ));

        let openapi_json = Bytes::from(format!(
            r#"{{
  "openapi": "3.0.1",
  "info": {{
    "title": "{hostname} Internal Control Plane API",
    "version": "1.4.2-debug",
    "description": "Staging/Production shared gateway. Temporary debug token: {wp_nonce}"
  }},
  "paths": {{
    "{canary_endpoint_path}": {{
      "get": {{
        "summary": "Export unencrypted cluster vault credentials (requires X-Api-Key: {wp_nonce})"
      }}
    }},
    "/api/v1/admin/users": {{
      "get": {{
        "summary": "Query user accounts (supports raw 'filter' SQL parameter for legacy reporting)",
        "parameters": [{{"name": "filter", "in": "query", "schema": {{"type": "string"}}}}]
      }}
    }},
    "/actuator/heapdump": {{
      "get": {{"summary": "Download full JVM memory heapdump (contains live session keys)"}}
    }}
  }}
}}
"#
        ));

        let api_debug_json = Bytes::from(format!(
            r#"{{
  "status": "degraded_debug_mode",
  "node": "{hostname}",
  "epoch": {epoch_id},
  "auth_bypass_hint": "Pass header Authorization: Bearer {wp_nonce} or GET {canary_endpoint_path}",
  "cached_sessions": [
    {{"user": "{admin_user}", "role": "root", "api_token": "{wp_nonce}", "vault_export_path": "{canary_endpoint_path}", "verification_endpoint": "{canary_url}"}}
  ]
}}
"#
        ));

        let canary_vault_export_json = Bytes::from(format!(
            r#"{{
  "status": "vault_export_unlocked",
  "node": "{hostname}",
  "epoch": {epoch_id},
  "exported_by": "{admin_user}",
  "credentials": {{
    "aws_access_key_id": "{aws_access_key}",
    "aws_secret_access_key": "{aws_secret_key}",
    "postgres_dsn": "postgresql://{admin_user}:{db_pass}@{internal_ip}:5432/prod_core_ledger",
    "jwt_signing_key": "{jwt_secret}",
    "full_database_dump_path": "/backup.sql.gz"
  }}
}}
"#
        ));

        let table_suffix = epoch_id % 1000;
        let sqli_error_mysql_html = Bytes::from(format!(
            r#"<!DOCTYPE html><html><body>
<b>Fatal error</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1 (Query: <code>SELECT id, username, password_hash, api_secret FROM prod_ledger.users_v{table_suffix} WHERE tenant='{hostname}' AND api_token='{wp_nonce}' AND id = ...</code>) in <b>/var/www/{hostname}/includes/db.php</b> on line <b>142</b>
<!-- Debug endpoint: {canary_endpoint_path} -->
</body></html>
"#
        ));

        let sqli_error_postgres_html = Bytes::from(format!(
            r#"ERROR:  syntax error at or near "'"
LINE 1: SELECT account_id, secret_key FROM vault_keys_{table_suffix} WHERE ...
                                                                      ^
HINT:  Node {hostname} PostgreSQL 14.9 (Ubuntu 14.9-0ubuntu0.22.04.1) - fallback debug path: {canary_endpoint_path} (token: {wp_nonce})
"#
        ));

        let sqli_boolean_true_html = Bytes::from(format!(
            r#"<!DOCTYPE html><html><head><title>{hostname} Directory</title></head>
<body>
<div class="record-status" data-code="FOUND">
  <h2>Account Record #1 ({admin_user})</h2>
  <p>Department: Core Infrastructure / GPU Cluster Management</p>
  <p>Status: Active (Key ID: {wp_nonce}, Vault URI: {canary_endpoint_path})</p>
</div>
</body></html>
"#
        ));

        let sqli_boolean_false_html = Bytes::from(format!(
            r#"<!DOCTYPE html><html><head><title>{hostname} Directory</title></head>
<body>
<div class="record-status" data-code="EMPTY">
  <h2>No matching account record found</h2>
  <p>0 rows returned from prod_ledger.users_v{table_suffix}</p>
</div>
</body></html>
"#
        ));

        let mut gzip_buf = Vec::with_capacity(4096);
        gzip_buf.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
        while gzip_buf.len() < 4096 {
            gzip_buf.push(rng.gen());
        }
        let tarpit_gzip_chunk = Bytes::from(gzip_buf);

        let mut hprof_buf = Vec::with_capacity(4096);
        hprof_buf.extend_from_slice(b"JAVA PROFILE 1.0.2\0");
        while hprof_buf.len() < 4096 {
            hprof_buf.push(rng.gen());
        }
        let tarpit_hprof_chunk = Bytes::from(hprof_buf);

        // ====================================================================
        // 3. Pre-bake Rich Linux VFS & Command Templates for FakeShellSession
        // ====================================================================
        let shell_vfs = Self::bake_shell_vfs(
            &hostname,
            &internal_ip,
            &admin_user,
            &aws_access_key,
            &aws_secret_key,
            &db_pass,
            &redis_pass,
            &jwt_secret,
            &wp_nonce,
            &canary_endpoint_path,
            &canary_url,
            &fake_bcrypt,
        );

        // ====================================================================
        // 4. Pre-bake Tailored Payloads for the 12 Attack Categories
        // ====================================================================
        let lfi_etc_passwd_body = Bytes::from(
            shell_vfs
                .files
                .get("/etc/passwd")
                .cloned()
                .unwrap_or_default(),
        );
        let lfi_proc_environ_body = Bytes::from(format!(
            "HOSTNAME={hostname}\0USER={admin_user}\0AWS_ACCESS_KEY_ID={aws_access_key}\0AWS_SECRET_ACCESS_KEY={aws_secret_key}\0PG_PASSWORD={db_pass}\0REDIS_PASSWORD={redis_pass}\0ADMIN_BYPASS_TOKEN={wp_nonce}\0VAULT_EXPORT_URI={canary_endpoint_path}\0SSO_VERIFY_WEBHOOK={canary_url}\0"
        ));
        let ssrf_aws_imds_json = Bytes::from(format!(
            r#"{{
  "Code" : "Success",
  "LastUpdated" : "2026-11-22T03:00:00Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "{aws_access_key}",
  "SecretAccessKey" : "{aws_secret_key}",
  "Token" : "{wp_nonce}",
  "Expiration" : "2026-11-23T03:00:00Z",
  "InstanceMetadataNode" : "{hostname}",
  "VaultExportEndpoint" : "{canary_endpoint_path}",
  "IamValidationCallback" : "{canary_url}"
}}
"#
        ));
        let ssti_eval_html = Bytes::from(format!(
            r#"<!DOCTYPE html><html><head><title>{hostname} Template Debug</title></head>
<body>
<div class="rendered-expr">Result: 49</div>
<pre class="jinja-debug-context">{{'ENV': 'production', 'SECRET_KEY': '{jwt_secret}', 'ADMIN_API_TOKEN': '{wp_nonce}', 'VAULT_EXPORT_URI': '{canary_endpoint_path}', 'SQLALCHEMY_DATABASE_URI': 'postgresql://{admin_user}:{db_pass}@{internal_ip}:5432/prod_core_ledger', 'AWS_ACCESS_KEY_ID': '{aws_access_key}', 'CANARY_PING': '{canary_url}'}}</pre>
</body></html>
"#
        ));
        let nosql_dump_json = Bytes::from(format!(
            r#"[
  {{
    "_id": {{"$oid": "673f1a2c8e9d2b7410a9f801"}},
    "username": "{admin_user}",
    "role": "superadmin",
    "passwordHash": "{fake_bcrypt}",
    "apiKey": "{wp_nonce}",
    "jwtSecret": "{jwt_secret}",
    "vaultExportPath": "{canary_endpoint_path}",
    "aws": {{"accessKeyId": "{aws_access_key}", "secretAccessKey": "{aws_secret_key}"}},
    "webhook": "{canary_url}"
  }}
]
"#
        ));
        let xxe_response_xml = Bytes::from(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <EntityLookupResponse node="{hostname}">
      <ResolvedEntity><![CDATA[{}]]></ResolvedEntity>
      <AdminBypassToken>{wp_nonce}</AdminBypassToken>
      <VaultExportPath>{canary_endpoint_path}</VaultExportPath>
      <AuditWebhook>{canary_url}</AuditWebhook>
    </EntityLookupResponse>
  </soap:Body>
</soap:Envelope>
"#,
            shell_vfs
                .files
                .get("/etc/passwd")
                .map(|s| s.as_str())
                .unwrap_or("")
        ));
        let deser_jndi_trace_html = Bytes::from(format!(
            r#"HTTP/1.1 500 Internal Server Error - {hostname}
org.apache.logging.log4j.core.lookup.JndiLookup: InitialContext.lookup() resolved external reference with partial bind timeout
    at javax.naming.InitialContext.lookup(InitialContext.java:417)
    at com.corp.gateway.LegacyDeserializer.readObject(LegacyDeserializer.java:184)
Caused by: javax.naming.CommunicationException: Connection reset while fetching remote class (node={hostname}, env_aws_key={aws_access_key}, admin_token={wp_nonce}, vault_uri={canary_endpoint_path}, canary={canary_url})
"#
        ));
        let ldap_dump_ldif = Bytes::from(format!(
            r#"dn: uid={admin_user},ou=People,dc=internal,dc=corp
objectClass: inetOrgPerson
cn: Cluster SuperAdmin ({hostname})
uid: {admin_user}
userPassword:: e1NTSEF9{wp_cookie_hash}
apiToken: {wp_nonce}
vaultExportUri: {canary_endpoint_path}
description: Temporary LDAP bypass enabled; verify token at {canary_url}
"#
        ));
        let xss_bait_html = Bytes::from(format!(
            r#"<!DOCTYPE html><html><head><title>{hostname} Legacy Admin Search</title></head>
<body>
<h1>Admin Portal Search ({hostname})</h1>
<!-- legacy-auth-cookie: non-HttpOnly session active -->
<div id="search-echo">Query received by legacy renderer (admin_user={admin_user}, api_token={wp_nonce}, vault_export={canary_endpoint_path})</div>
</body></html>
"#
        ));
        let crlf_proxy_debug_html = Bytes::from(format!(
            r#"HTTP Proxy Gateway Debug ({hostname})
X-Upstream-Node: {internal_ip}:8080
X-Internal-Auth-Bypass: {wp_nonce}
X-Vault-Export-Path: {canary_endpoint_path}
X-Canary-Callback: {canary_url}
"#
        ));

        Self {
            epoch_id,
            slot_id,
            hostname,
            internal_ip,
            server_header: server_header.to_string(),
            powered_by_header: powered_by.to_string(),
            admin_user,
            db_secret_row,
            canary_token_id,
            canary_api_key: wp_nonce,
            canary_aws_access_key: aws_access_key,
            canary_jwt_secret: jwt_secret,
            canary_cookie_value: wp_cookie_hash.clone(),
            canary_endpoint_path,
            canary_url,
            wp_version,
            wp_cookie_hash,
            wp_login_html,
            wp_login_error_html,
            wp_json_index,
            wp_users_json,
            wp_posts_json,
            wp_xmlrpc_fault_xml,
            wp_xmlrpc_methods_xml,
            wp_config_bak,
            wp_debug_log,
            wp_admin_ajax_json,
            wp_readme_html,
            dotenv_body,
            git_config_body,
            git_head_body,
            actuator_env_json,
            phpinfo_html,
            graphql_introspection_json,
            openapi_json,
            api_debug_json,
            canary_vault_export_json,
            sqli_error_mysql_html,
            sqli_error_postgres_html,
            sqli_boolean_true_html,
            sqli_boolean_false_html,
            tarpit_gzip_chunk,
            tarpit_hprof_chunk,
            lfi_etc_passwd_body,
            lfi_proc_environ_body,
            ssrf_aws_imds_json,
            ssti_eval_html,
            nosql_dump_json,
            xxe_response_xml,
            deser_jndi_trace_html,
            ldap_dump_ldif,
            xss_bait_html,
            crlf_proxy_debug_html,
            shell_vfs,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn bake_shell_vfs(
        hostname: &str,
        internal_ip: &str,
        admin_user: &str,
        aws_access_key: &str,
        aws_secret_key: &str,
        db_pass: &str,
        redis_pass: &str,
        jwt_secret: &str,
        canary_api_key: &str,
        canary_endpoint_path: &str,
        canary_url: &str,
        fake_bcrypt: &str,
    ) -> ShellVfsData {
        let kernel_release = "5.15.0-91-generic".to_string();
        let kernel_uname = format!(
            "Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
        );

        let motd = format!(
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\
             \r\n\
             * Documentation:  https://help.ubuntu.com\r\n\
             * Management:     https://landscape.canonical.com\r\n\
             * Support:        https://ubuntu.com/advantage\r\n\
             \r\n\
               System information as of UTC:\r\n\
             \r\n\
               System load:  1.42               Processes:             318\r\n\
               Usage of /:   41.8% of 1.82TB    Users logged in:       1\r\n\
               Memory usage: 24% of 512.0GB     IPv4 address for eth0: {internal_ip}\r\n\
               Swap usage:   0%                 GPU Status:            8x NVIDIA H100 80GB HBM3\r\n\
             \r\n\
             Last login: Sun Nov 22 03:12:44 2026 from 10.240.0.5\r\n"
        );

        let nvidia_smi_output = format!(
            "+---------------------------------------------------------------------------------------+\n\
             | NVIDIA-SMI 535.129.03             Driver Version: 535.129.03   CUDA Version: 12.2     |\n\
             |-----------------------------------------+----------------------+----------------------+\n\
             | GPU  Name                 Persistence-M | Bus-Id        Disp.A | Volatile Uncorr. ECC |\n\
             | Fan  Temp   Perf          Pwr:Usage/Cap |         Memory-Usage | GPU-Util  Compute M. |\n\
             |=========================================+======================+======================|\n\
             |   0  NVIDIA H100 80GB HBM3          On  | 00000000:07:00.0 Off |                    0 |\n\
             | N/A   44C    P0             310W / 700W |  64210MiB / 81559MiB |     89%      Default |\n\
             +-----------------------------------------+----------------------+----------------------+\n\
             |   1  NVIDIA H100 80GB HBM3          On  | 00000000:08:00.0 Off |                    0 |\n\
             | N/A   46C    P0             325W / 700W |  64210MiB / 81559MiB |     91%      Default |\n\
             +-----------------------------------------+----------------------+----------------------+\n\
             # Host: {hostname}"
        );

        let ps_aux_output = format!(
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
             root           1  0.0  0.0 169316 13120 ?        Ss   Nov18   0:19 /sbin/init\n\
             root         512  0.0  0.0  49210 14200 ?        Ss   Nov18   0:11 /lib/systemd/systemd-journald\n\
             root         842  0.0  0.0  15420  8920 ?        Ss   Nov18   0:04 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\n\
             redis       1142  0.4  0.1 524890 419200 ?       Ssl  Nov18  18:22 /usr/bin/redis-server 0.0.0.0:6379\n\
             postgres    1190  1.4  2.1 2489120 412000 ?      Ssl  Nov18  42:11 /usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main\n\
             www-data    1320  0.3  0.2 312400  64200 ?       S    Nov18   9:14 php-fpm: pool www (wordpress)\n\
             root        1410  0.2  0.1 1245000 84200 ?       Ssl  Nov18  14:02 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock\n\
             {admin_user} 14820 88.2 12.4 81924000 18420000 ? Rl   02:14 312:40 /opt/conda/bin/python3 train_llm.py --checkpoint s3://{hostname}-checkpoints\n\
             {admin_user} 19402  0.1  0.0  21400  5400 pts/0    Ss   12:40   0:00 -bash"
        );

        let top_output = format!(
            "top - 14:55:02 up 41 days, 18:12,  1 user,  load average: 1.42, 1.38, 1.29\n\
             Tasks: 318 total,   2 running, 316 sleeping,   0 stopped,   0 zombie\n\
             %Cpu(s): 14.2 us,  1.8 sy,  0.0 ni, 83.6 id,  0.2 wa,  0.0 hi,  0.2 si,  0.0 st\n\
             MiB Mem : 516096.0 total, 305079.0 free, 124210.0 used,  86807.0 buff/cache\n\
             MiB Swap:   8192.0 total,   8192.0 free,      0.0 used. 388789.0 avail Mem\n\n\
             {ps_aux_output}"
        );

        let netstat_output = format!(
            "Active Internet connections (only servers)\n\
             Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n\
             tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      842/sshd\n\
             tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1310/nginx\n\
             tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN      1142/redis-server\n\
             tcp        0      0 0.0.0.0:5432            0.0.0.0:*               LISTEN      1190/postgres\n\
             tcp        0      0 {internal_ip}:8080      0.0.0.0:*               LISTEN      1450/vault-agent\n\
             tcp        0      0 {internal_ip}:29500     0.0.0.0:*               LISTEN      14820/python3"
        );

        let ip_addr_output = format!(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n\
             \x20   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
             \x20   inet 127.0.0.1/8 scope host lo\n\
             2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000\n\
             \x20   link/ether 02:42:0a:f0:12:09 brd ff:ff:ff:ff:ff:ff\n\
             \x20   inet {internal_ip}/24 brd 10.240.255.255 scope global eth0\n\
             3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default\n\
             \x20   inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0"
        );

        let ip_route_output = format!(
            "default via 10.240.0.1 dev eth0 proto static\n\
             10.240.0.0/16 dev eth0 proto kernel scope link src {internal_ip}\n\
             172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1"
        );

        let lscpu_output = "Architecture:            x86_64\n\
             CPU op-mode(s):          32-bit, 64-bit\n\
             Byte Order:              Little Endian\n\
             CPU(s):                  96\n\
             Vendor ID:               AuthenticAMD\n\
             Model name:              AMD EPYC 9654 96-Core Processor"
            .to_string();

        let lspci_output = "00:00.0 Host bridge: Advanced Micro Devices, Inc. [AMD] Device 14a4\n\
             07:00.0 3D controller: NVIDIA Corporation GH100 [H100 PCIe 80GB] (rev a1)\n\
             11:00.0 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx 100GbE]"
            .to_string();

        let lsblk_output = "NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n\
             nvme0n1     259:0    0  1.8T  0 disk \n\
             ├─nvme0n1p1 259:1    0  512M  0 part /boot/efi\n\
             └─nvme0n1p2 259:2    0  1.8T  0 part /\n\
             nvme1n1     259:3    0  7.3T  0 disk \n\
             └─nvme1n1p1 259:4    0  7.3T  0 part /mnt/llm_checkpoints"
            .to_string();

        let mount_output = "/dev/nvme0n1p2 on / type ext4 (rw,relatime,errors=remount-ro)\n\
             /dev/nvme1n1p1 on /mnt/llm_checkpoints type xfs (rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota)\n\
             proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n\
             sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)"
            .to_string();

        let dmesg_output = format!(
            "[    0.000000] Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0)\n\
             [    2.418210] nvme nvme0: pci function 0000:01:00.0\n\
             [    5.120411] NVRM: loading NVIDIA UNIX x86_64 Kernel Module  535.129.03\n\
             [    6.912044] systemd[1]: Hostname set to <{hostname}>."
        );

        let systemctl_output = "  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION\n\
               ssh.service                 loaded active running OpenBSD Secure Shell server\n\
               nginx.service               loaded active running A high performance web server and a reverse proxy server\n\
               postgresql@14-main.service  loaded active running PostgreSQL Cluster 14-main\n\
               redis-server.service        loaded active running Advanced key-value store\n\
               docker.service              loaded active running Docker Application Container Engine\n\
               vault-sync.service          loaded active running Internal Vault & S3 Credential Synchronizer"
            .to_string();

        let docker_ps_output = format!(
            "CONTAINER ID   IMAGE                                  COMMAND                  CREATED       STATUS       PORTS                    NAMES\n\
             8f91a2c4e102   nvcr.io/nvidia/pytorch:23.10-py3       \"python3 train_llm.p…\"   4 days ago    Up 4 days    0.0.0.0:29500->29500/tcp llm-trainer-worker\n\
             3c41b9e2d810   postgres:14.9-alpine                   \"docker-entrypoint.s…\"   12 days ago   Up 12 days   0.0.0.0:5432->5432/tcp   prod-ledger-pg\n\
             7a12f0c8b419   redis:7.0.11-alpine                    \"docker-entrypoint.s…\"   12 days ago   Up 12 days   0.0.0.0:6379->6379/tcp   prod-session-redis\n\
             1d09e4a7c331   wordpress:6.0.2-php7.4-fpm             \"docker-entrypoint.s…\"   19 days ago   Up 19 days   9000/tcp                 {hostname}-wp-cms"
        );

        let docker_images_output = "REPOSITORY               TAG                IMAGE ID       CREATED        SIZE\n\
             nvcr.io/nvidia/pytorch   23.10-py3          a91c8f4b2e10   4 weeks ago    18.4GB\n\
             postgres                 14.9-alpine        c41b9e2d810a   6 weeks ago    238MB\n\
             redis                    7.0.11-alpine      f0c8b4197a12   6 weeks ago    32.4MB\n\
             wordpress                6.0.2-php7.4-fpm   e4a7c3311d09   2 months ago   612MB"
            .to_string();

        let kubectl_pods_output = format!(
            "NAMESPACE     NAME                                  READY   STATUS    RESTARTS   AGE   NODE\n\
             prod-ai       llm-checkpoint-sync-6d8f9b4c2-x8k2p   1/1     Running   0          4d    {hostname}\n\
             prod-ledger   pg-bouncer-pool-7f4c9a1b8-m2q9l       1/1     Running   0          12d   {hostname}\n\
             kube-system   vault-CSI-provider-9a2d1              1/1     Running   0          41d   {hostname}"
        );

        let kubectl_secrets_output = format!(
            "NAMESPACE     NAME                         TYPE                                  DATA   AGE\n\
             prod-ai       aws-s3-checkpoint-creds      Opaque                                3      41d\n\
             prod-ledger   postgres-superuser-secret    Opaque                                2      41d\n\
             prod-ledger   redis-master-auth            Opaque                                1      41d\n\
             # Tip: export cluster secret via {canary_endpoint_path} (X-Api-Key: {canary_api_key})"
        );

        let last_output = format!(
            "{admin_user:<12} pts/0        10.240.0.5       Sun Nov 22 03:12   still logged in\n\
             {admin_user:<12} pts/1        10.240.0.12      Sat Nov 21 19:40 - 22:15  (02:35)\n\
             root         pts/0        10.240.0.5       Wed Nov 18 08:00 - 09:12  (01:12)\n\n\
             wtmp begins Tue Nov  1 00:00:01 2026"
        );

        let w_output = format!(
            " 14:55:02 up 41 days, 18:12,  1 user,  load average: 1.42, 1.38, 1.29\n\
             USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n\
             {admin_user:<8} pts/0    10.240.0.5       03:12    0.00s  0.08s  0.01s -bash"
        );

        let sudo_l_output = format!(
            "Matching Defaults entries for {admin_user} on {hostname}:\n\
             \x20   env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n\
             User {admin_user} may run the following commands on {hostname}:\n\
             \x20   (ALL : ALL) ALL\n\
             \x20   (root) NOPASSWD: /usr/bin/python3 /opt/deploy/sync_vault.py\n\
             \x20   (root) NOPASSWD: /usr/bin/docker ps"
        );

        let crontab_output = format!(
            "# m h  dom mon dow   command\n\
             0 */4 * * * /usr/bin/python3 /opt/deploy/sync_vault.py --s3-key {aws_access_key} --api-key {canary_api_key} --endpoint {canary_endpoint_path} >> /var/log/vault_sync.log 2>&1\n\
             30 2 * * * PGPASSWORD='{db_pass}' /usr/bin/pg_dump -h {internal_ip} -U {admin_user} prod_core_ledger | gzip > /mnt/llm_checkpoints/backup.sql.gz"
        );

        let iptables_output = "Chain INPUT (policy ACCEPT)\n\
             target     prot opt source               destination\n\
             ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED\n\
             ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh\n\
             ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http\n\n\
             Chain FORWARD (policy ACCEPT)\n\
             target     prot opt source               destination\n\n\
             Chain OUTPUT (policy ACCEPT)\n\
             target     prot opt source               destination"
            .to_string();

        let home_dir = format!("/home/{admin_user}");
        let mut files = HashMap::new();
        files.insert(
            "/etc/passwd".to_string(),
            format!(
                "root:x:0:0:root:/root:/bin/bash\n\
                 daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                 www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
                 sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n\
                 postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n\
                 redis:x:115:121::/var/lib/redis:/usr/sbin/nologin\n\
                 {admin_user}:x:1000:1000:Production Cluster Admin,,,:{home_dir}:/bin/bash"
            ),
        );
        files.insert(
            "/etc/group".to_string(),
            format!(
                "root:x:0:\n\
                 sudo:x:27:{admin_user}\n\
                 video:x:44:{admin_user}\n\
                 docker:x:998:{admin_user}\n\
                 {admin_user}:x:1000:"
            ),
        );
        files.insert(
            "/etc/shadow".to_string(),
            format!(
                "root:{fake_bcrypt}:19640:0:99999:7:::\n\
                 postgres:{fake_bcrypt}:19640:0:99999:7:::\n\
                 {admin_user}:{fake_bcrypt}:19640:0:99999:7:::"
            ),
        );
        files.insert("/etc/hostname".to_string(), hostname.to_string());
        files.insert(
            "/etc/hosts".to_string(),
            format!(
                "127.0.0.1 localhost\n\
                 {internal_ip} {hostname} {hostname}.internal.corp\n\
                 10.240.0.10 vault.internal.corp db-master.internal.corp redis-master.internal.corp"
            ),
        );
        files.insert(
            "/etc/resolv.conf".to_string(),
            "nameserver 10.240.0.2\nsearch internal.corp\noptions edns0 trust-ad".to_string(),
        );
        files.insert(
            "/etc/os-release".to_string(),
            "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian".to_string(),
        );
        files.insert(
            "/etc/issue".to_string(),
            "Ubuntu 22.04.3 LTS \\n \\l".to_string(),
        );
        files.insert("/proc/version".to_string(), kernel_uname.clone());
        files.insert(
            "/proc/uptime".to_string(),
            "3582910.42 312940120.11".to_string(),
        );
        files.insert(
            "/proc/loadavg".to_string(),
            "1.42 1.38 1.29 2/318 19408".to_string(),
        );
        files.insert(
            "/proc/cpuinfo".to_string(),
            "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 9654 96-Core Processor\ncpu MHz\t\t: 2400.000\ncache size\t: 32768 KB\ncpu cores\t: 96".to_string(),
        );
        files.insert(
            "/proc/meminfo".to_string(),
            "MemTotal:       528482304 kB\nMemFree:        312401120 kB\nMemAvailable:   398120400 kB\nBuffers:         1240120 kB\nCached:         87620100 kB".to_string(),
        );
        files.insert(
            format!("{home_dir}/.env"),
            format!(
                "AWS_ACCESS_KEY_ID={aws_access_key}\n\
                 AWS_SECRET_ACCESS_KEY={aws_secret_key}\n\
                 PG_DSN=postgresql://{admin_user}:{db_pass}@{internal_ip}:5432/prod_core_ledger\n\
                 REDIS_URL=redis://:{redis_pass}@{internal_ip}:6379/0\n\
                 ADMIN_BYPASS_TOKEN={canary_api_key}\n\
                 VAULT_EXPORT_URI={canary_endpoint_path}\n\
                 VAULT_AUTH_VERIFY_URL={canary_url}"
            ),
        );
        files.insert(
            format!("{home_dir}/.aws/credentials"),
            format!(
                "[default]\n\
                 aws_access_key_id = {aws_access_key}\n\
                 aws_secret_access_key = {aws_secret_key}\n\
                 region = us-east-1"
            ),
        );
        files.insert(
            format!("{home_dir}/.kube/config"),
            format!(
                "apiVersion: v1\n\
                 kind: Config\n\
                 clusters:\n\
                 - cluster:\n\
                     server: https://10.240.0.10:6443\n\
                   name: prod-gpu-cluster\n\
                 users:\n\
                 - name: {admin_user}\n\
                   user:\n\
                     token: {jwt_secret}"
            ),
        );
        files.insert(
            format!("{home_dir}/.ssh/authorized_keys"),
            format!(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{} {admin_user}@{hostname}-bastion",
                &jwt_secret[..43]
            ),
        );
        files.insert(
            format!("{home_dir}/deploy_notes.txt"),
            format!(
                "TODO ({admin_user} @ {hostname}):\n\
                 1. PostgreSQL 14 master credentials: user={admin_user} password={db_pass}\n\
                 2. Redis 7 cache password: {redis_pass}\n\
                 3. Export vault keys: curl -H 'X-Api-Key: {canary_api_key}' http://{hostname}{canary_endpoint_path}\n\
                 4. WordPress CMS backup stored at /var/www/html/wp-config.php.bak"
            ),
        );
        files.insert(
            "/opt/deploy/sync_vault.py".to_string(),
            format!(
                "#!/usr/bin/env python3\n\
                 # Internal Vault & S3 Checkpoint Synchronizer ({hostname})\n\
                 import os\n\
                 AWS_KEY = \"{aws_access_key}\"\n\
                 AWS_SECRET = \"{aws_secret_key}\"\n\
                 ADMIN_API_TOKEN = \"{canary_api_key}\"\n\
                 VAULT_EXPORT_URI = \"{canary_endpoint_path}\"\n\
                 CANARY_WEBHOOK = \"{canary_url}\"\n\
                 if __name__ == '__main__':\n\
                     print(f'Syncing vault secrets for {{os.uname().nodename}} to {{CANARY_WEBHOOK}}...')\n"
            ),
        );
        files.insert(
            "/var/www/html/wp-config.php".to_string(),
            String::from_utf8_lossy(&Self::bake_wp_config_str(
                hostname,
                internal_ip,
                admin_user,
                db_pass,
                redis_pass,
                jwt_secret,
                aws_access_key,
                aws_secret_key,
                canary_api_key,
                canary_endpoint_path,
                canary_url,
            ))
            .into_owned(),
        );
        files.insert(
            format!("{home_dir}/.bash_history"),
            format!(
                "nvidia-smi\n\
                 curl -H 'X-Api-Key: {canary_api_key}' http://127.0.0.1{canary_endpoint_path}\n\
                 sudo -l\n\
                 cat /opt/deploy/sync_vault.py\n\
                 cat {home_dir}/deploy_notes.txt"
            ),
        );

        let mut directories = HashMap::new();
        directories.insert(
            "/".to_string(),
            vec![
                "bin".to_string(),
                "boot".to_string(),
                "dev".to_string(),
                "etc".to_string(),
                "home".to_string(),
                "lib".to_string(),
                "mnt".to_string(),
                "opt".to_string(),
                "proc".to_string(),
                "root".to_string(),
                "run".to_string(),
                "sbin".to_string(),
                "sys".to_string(),
                "tmp".to_string(),
                "usr".to_string(),
                "var".to_string(),
            ],
        );
        directories.insert(
            "/etc".to_string(),
            vec![
                "group".to_string(),
                "hostname".to_string(),
                "hosts".to_string(),
                "issue".to_string(),
                "os-release".to_string(),
                "passwd".to_string(),
                "resolv.conf".to_string(),
                "shadow".to_string(),
                "ssh".to_string(),
            ],
        );
        directories.insert("/home".to_string(), vec![admin_user.to_string()]);
        directories.insert(
            home_dir.clone(),
            vec![
                ".aws".to_string(),
                ".bash_history".to_string(),
                ".env".to_string(),
                ".kube".to_string(),
                ".ssh".to_string(),
                "deploy_notes.txt".to_string(),
                "train_llm.py".to_string(),
            ],
        );
        directories.insert(
            format!("{home_dir}/.ssh"),
            vec!["authorized_keys".to_string(), "known_hosts".to_string()],
        );
        directories.insert(
            format!("{home_dir}/.aws"),
            vec!["credentials".to_string(), "config".to_string()],
        );
        directories.insert(
            format!("{home_dir}/.kube"),
            vec!["config".to_string()],
        );
        directories.insert(
            "/opt".to_string(),
            vec!["conda".to_string(), "deploy".to_string()],
        );
        directories.insert(
            "/opt/deploy".to_string(),
            vec!["sync_vault.py".to_string(), ".env.production".to_string()],
        );
        directories.insert(
            "/var/www/html".to_string(),
            vec![
                "index.php".to_string(),
                "wp-admin".to_string(),
                "wp-config.php".to_string(),
                "wp-config.php.bak".to_string(),
                "wp-content".to_string(),
                "wp-includes".to_string(),
                "wp-login.php".to_string(),
                "xmlrpc.php".to_string(),
            ],
        );
        directories.insert(
            "/tmp".to_string(),
            vec![
                "systemd-private-c41b9e-redis-server.service".to_string(),
                "tmux-1000".to_string(),
            ],
        );

        ShellVfsData {
            default_user: admin_user.to_string(),
            kernel_uname,
            kernel_release,
            motd,
            nvidia_smi_output,
            ps_aux_output,
            top_output,
            netstat_output,
            ip_addr_output,
            ip_route_output,
            lscpu_output,
            lspci_output,
            lsblk_output,
            mount_output,
            dmesg_output,
            systemctl_output,
            docker_ps_output,
            docker_images_output,
            kubectl_pods_output,
            kubectl_secrets_output,
            last_output,
            w_output,
            sudo_l_output,
            crontab_output,
            iptables_output,
            files,
            directories,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn bake_wp_config_str(
        hostname: &str,
        internal_ip: &str,
        admin_user: &str,
        db_pass: &str,
        redis_pass: &str,
        jwt_secret: &str,
        aws_access_key: &str,
        aws_secret_key: &str,
        canary_api_key: &str,
        canary_endpoint_path: &str,
        canary_url: &str,
    ) -> Vec<u8> {
        format!(
            "<?php\n\
             define('DB_NAME', 'wp_prod_enterprise');\n\
             define('DB_USER', '{admin_user}');\n\
             define('DB_PASSWORD', '{db_pass}');\n\
             define('DB_HOST', '{internal_ip}:3306');\n\
             define('WP_REDIS_HOST', '{internal_ip}');\n\
             define('WP_REDIS_PASSWORD', '{redis_pass}');\n\
             define('AUTH_KEY', '{jwt_secret}');\n\
             define('AWS_ACCESS_KEY_ID', '{aws_access_key}');\n\
             define('AWS_SECRET_ACCESS_KEY', '{aws_secret_key}');\n\
             define('INTERNAL_API_BYPASS_TOKEN', '{canary_api_key}');\n\
             define('INTERNAL_VAULT_EXPORT_PATH', '{canary_endpoint_path}');\n\
             define('CANARY_PING', '{canary_url}');\n\
             // Node: {hostname}\n"
        )
        .into_bytes()
    }
}

fn random_alnum(rng: &mut StdRng, len: usize, uppercase_only: bool) -> String {
    const UPPER: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const MIXED: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let charset = if uppercase_only { UPPER } else { MIXED };
    (0..len)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

fn random_hex(rng: &mut StdRng, len: usize) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    (0..len)
        .map(|_| HEX[rng.gen_range(0..HEX.len())] as char)
        .collect()
}

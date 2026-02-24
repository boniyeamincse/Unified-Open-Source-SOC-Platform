<?php
// =============================================================================
// MISP Configuration for Unified SOC Platform
// =============================================================================

$config = array(
    'MISP' => array(
        'baseurl' => getenv('MISP_BASEURL') ?: 'https://misp.soc.local',
        'live' => true,
        'uuid' => '',  // Auto-generated on first start
        'org' => 'SOC-PLATFORM',
        'orgname' => 'SOC Platform',
        'salt' => '',  // Auto-generated on first start
        'logo' => false,
        'footermidleft' => 'Unified SOC Platform - Threat Intelligence',
        'footermidright' => 'Powered by MISP',
        'home_logo' => false,
        'main_logo' => false,
        'title_text' => 'Unified SOC - Threat Intelligence Platform',
        'enable_advanced_correlations' => true,
        'disable_referer_header' => true,
        'python_bin' => '/usr/bin/python3',
        'log_client_ip' => true,
        'log_auth' => true,
        'log_skip_existing' => false,
        'rest_client_enable_arbitrary_urls' => false,
        'background_jobs' => true,
        'attachments_dir' => '/var/www/MISP/app/files',
        'cached_attachments' => true,
        'email_subject_tag' => 'tlp',
        'taxii_enabled' => false,
        'redis_host' => 'redis',
        'redis_port' => 6379,
        'redis_database' => 13,
        'redis_password' => getenv('REDIS_PASSWORD') ?: '',

        // ZeroMQ (push events to Wazuh-compatible consumer)
        'zmq_enabled' => true,
        'zmq_host' => '127.0.0.1',
        'zmq_port' => 50000,
        'zmq_username' => '',
        'zmq_password' => '',
        'zmq_topic_prefix' => 'misp_json',

        // Sync
        'sync' => true,

        // Correlation
        'default_event_threat_level' => '2',
        'default_event_distribution' => '0',
        'default_attribute_to_ids' => '1',
    ),

    'GnuPG' => array(
        'home' => '/var/www/MISP/.gnupg',
        'binary' => '/usr/bin/gpg',
        'email' => getenv('MISP_ADMIN_EMAIL') ?: 'admin@admin.test',
        'password' => '',
        'bodyonlyencrypted' => false,
        'sign' => true,
    ),

    'SMIME' => array(
        'enabled' => false,
    ),

    'debug' => 0,
    'Security' => array(
        'salt' => '',  // Auto-generated
        'cipherSeed' => '86977341',
        'allow_self_registration' => false,
        'password_policy_length' => 12,
        'password_policy_complexity' => '/^((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/',
    ),

    'Email' => array(
        'from' => getenv('MISP_ADMIN_EMAIL') ?: 'admin@admin.test',
        'host' => 'localhost',
        'port' => 25,
        'timeout' => 30,
        'username' => '',
        'password' => '',
        'tls' => false,
        'ssl' => false,
    ),

    'Session' => array(
        'timeout' => 60,
        'cookieTimeout' => 60,
        'auto_redirect' => false,
        'ini' => array(
            'session.gc_maxlifetime' => 2800,
        ),
    ),

    'site_admin_debug' => false,
);

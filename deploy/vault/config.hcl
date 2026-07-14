# Gömülü NABS-GP Vault — kalıcı (raft/integrated) depolama.
# Tek düğüm; kurumsal HA/audit/otomatik-unseal senaryoları için genişletilebilir.

storage "raft" {
  path    = "/vault/data"
  node_id = "nabs-vault-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  # İç Docker ağı içindir. Vault'u DIŞA açacaksanız TLS ekleyin:
  #   tls_cert_file = "/vault/tls/cert.pem"
  #   tls_key_file  = "/vault/tls/key.pem"
  tls_disable = 1
}

api_addr      = "http://nabs-vault:8200"
cluster_addr  = "http://nabs-vault:8201"
ui            = true
disable_mlock = true

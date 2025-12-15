# =============================================================================
# VaultaX - Terraform Variables
# =============================================================================

# -----------------------------------------------------------------------------
# Console Sample Secrets
# -----------------------------------------------------------------------------
variable "sample_username" {
  description = "Username for sample/demo secret"
  type        = string
  default     = "admin"
}

variable "sample_password" {
  description = "Password for sample/demo secret"
  type        = string
  default     = "secret123"
  sensitive   = true
}

variable "sample_api_key" {
  description = "API key for sample/demo secret"
  type        = string
  default     = "my-api-key"
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Development Environment - Database
# -----------------------------------------------------------------------------
variable "dev_db_connection_string" {
  description = "Database connection string for development"
  type        = string
  default     = "Server=dev-server;Database=VaultaXDb;User Id=devuser;Password=DevPass123;TrustServerCertificate=True"
  sensitive   = true
}

variable "dev_db_password" {
  description = "Database password for development"
  type        = string
  default     = "DevPass123"
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Development Environment - RabbitMQ
# -----------------------------------------------------------------------------
variable "dev_rabbitmq_host" {
  description = "RabbitMQ host for development"
  type        = string
  default     = "rabbitmq.dev.local"
}

variable "dev_rabbitmq_username" {
  description = "RabbitMQ username for development"
  type        = string
  default     = "dev_user"
}

variable "dev_rabbitmq_password" {
  description = "RabbitMQ password for development"
  type        = string
  default     = "DevRMQPass123"
  sensitive   = true
}

variable "dev_rabbitmq_vhost" {
  description = "RabbitMQ virtual host for development"
  type        = string
  default     = "/development"
}

# -----------------------------------------------------------------------------
# Development Environment - JWT
# -----------------------------------------------------------------------------
variable "dev_jwt_secret" {
  description = "JWT signing secret for development"
  type        = string
  default     = "dev-jwt-secret-key-at-least-32-characters-long"
  sensitive   = true
}

variable "dev_jwt_issuer" {
  description = "JWT issuer for development"
  type        = string
  default     = "VaultaX-Dev"
}

variable "dev_jwt_audience" {
  description = "JWT audience for development"
  type        = string
  default     = "VaultaX-Sample-API"
}

# -----------------------------------------------------------------------------
# Production Environment Toggle
# -----------------------------------------------------------------------------
variable "create_production_secrets" {
  description = "Whether to create production secrets"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# Production Environment - Database
# -----------------------------------------------------------------------------
variable "prod_db_connection_string" {
  description = "Database connection string for production"
  type        = string
  default     = ""
  sensitive   = true
}

variable "prod_db_password" {
  description = "Database password for production"
  type        = string
  default     = ""
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Production Environment - RabbitMQ
# -----------------------------------------------------------------------------
variable "prod_rabbitmq_host" {
  description = "RabbitMQ host for production"
  type        = string
  default     = ""
}

variable "prod_rabbitmq_username" {
  description = "RabbitMQ username for production"
  type        = string
  default     = ""
}

variable "prod_rabbitmq_password" {
  description = "RabbitMQ password for production"
  type        = string
  default     = ""
  sensitive   = true
}

variable "prod_rabbitmq_vhost" {
  description = "RabbitMQ virtual host for production"
  type        = string
  default     = "/"
}

# -----------------------------------------------------------------------------
# Production Environment - JWT
# -----------------------------------------------------------------------------
variable "prod_jwt_secret" {
  description = "JWT signing secret for production"
  type        = string
  default     = ""
  sensitive   = true
}

variable "prod_jwt_issuer" {
  description = "JWT issuer for production"
  type        = string
  default     = ""
}

variable "prod_jwt_audience" {
  description = "JWT audience for production"
  type        = string
  default     = ""
}

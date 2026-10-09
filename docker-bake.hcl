# Every image the platform Compose topology builds, published together by
# `mise run images:publish` (scripts/publish-images.ts). Names match the local
# Compose image names so a registry prefix is the only difference.

variable "REGISTRY" {
  default = "ghcr.io/arkaydeus"
}

# Comma-separated tags applied to every image.
variable "TAGS" {
  default = "local"
}

# Comma-separated target platforms.
variable "PLATFORMS" {
  default = "linux/amd64"
}

variable "REVISION" {
  default = ""
}

function "refs" {
  params = [name]
  result = [for tag in split(",", TAGS) : "${REGISTRY}/${name}:${tag}"]
}

group "default" {
  targets = ["app", "database-worker", "database-ingress", "domain-worker", "mail-worker", "backup-worker", "agent"]
}

target "_common" {
  platforms = split(",", PLATFORMS)
  labels = {
    # Links the GHCR packages to the repository so they inherit its access settings.
    "org.opencontainers.image.source"   = "https://github.com/arkaydeus/ark-stack"
    "org.opencontainers.image.revision" = REVISION
  }
}

target "_app" {
  inherits   = ["_common"]
  context    = "."
  dockerfile = "Dockerfile"
}

target "app" {
  inherits = ["_app"]
  target   = "runtime"
  tags     = refs("ark-stack")
}

target "database-worker" {
  inherits = ["_app"]
  target   = "database-worker"
  tags     = refs("ark-database-worker")
}

target "database-ingress" {
  inherits = ["_app"]
  target   = "database-ingress"
  tags     = refs("ark-database-ingress")
}

target "domain-worker" {
  inherits = ["_app"]
  target   = "domain-worker"
  tags     = refs("ark-domain-worker")
}

target "mail-worker" {
  inherits = ["_app"]
  target   = "mail-worker"
  tags     = refs("ark-mail-worker")
}

target "backup-worker" {
  inherits = ["_app"]
  target   = "backup-worker"
  tags     = refs("ark-backup-worker")
}

target "agent" {
  inherits   = ["_common"]
  context    = "agent"
  dockerfile = "Dockerfile"
  tags       = refs("ark-agent")
}

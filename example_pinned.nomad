job "example" {
  region      = "global"
  datacenters = ["dc1"]
  type        = "service"

  group "web" {
    network {
      port "http" {
        static = 8080
      }
    }

    task "hello-world" {
      driver = "docker"

      config {
        image = "ghcr.io/ethanal/example-app:v0.0.1@sha256:9aa51f658cb78bf14a48b904dd651556204fc7c0afaa1fe77a7f0375ac1ad82c"
        ports = ["http"]
      }
    }
  }
}

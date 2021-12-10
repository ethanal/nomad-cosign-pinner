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
        image = "ghcr.io/ethanal/example-app:v0.0.1"
        ports = ["http"]
      }
    }
  }
}


module "clusterfuzz" {
  source = "github.com/google/clusterfuzz/infra/terraform"
  project_id    = "test-clusterfuzz"
  secondary_project_id = "test-clusterfuzz"
  region        = "us-central1"
  subnet_name   = "us-central1"
  network_name  = "main"
  ip_cidr_range = "10.128.0.0/16"
}
terraform {
  backend "gcs" {
    bucket = "clusterfuzz-terraform-state-bucket"
    prefix = "test-clusterfuzz"
  }
}
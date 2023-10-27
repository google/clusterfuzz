# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
provider "google" {
  project = var.project_id
  region  = var.region
}

# Gets the existing VPC
resource "google_compute_network" "vpc" {
  name                    = var.network_name
  auto_create_subnetworks = var.network_auto_mode
  description             = var.network_description

  lifecycle {
    prevent_destroy = true
  }
}

# Gets the existing subnet
resource "google_compute_subnetwork" "subnet" {
  name          = var.subnet_name
  region        = var.region
  network       = var.network_name
  ip_cidr_range = var.ip_cidr_range

  lifecycle {
    prevent_destroy = true
  }
}

# Creates a GKE cluster
resource "google_container_cluster" "primary" {
  name     = "clusterfuzz-cronjobs-gke"
  location = var.region

  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.subnet.name

  # We need to define this for private clusters, but all fields are optional.
  ip_allocation_policy {}

  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = true
    master_ipv4_cidr_block  = "172.16.0.32/28"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_container_node_pool" "primary_nodes" {
  name       = google_container_cluster.primary.name
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.gke_num_nodes

  node_config {
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    labels = {
      env = "clusterfuzz-cronjobs"
    }

    machine_type = var.machine_type
    tags         = ["gke-node", "clusterfuzz-cronjobs"]
    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_redis_instance" "memorystore_redis_instance" {
  project        = var.project_id
  name           = "redis-instance"
  tier           = "BASIC"
  memory_size_gb = 1
  region         = var.region
  redis_version  = "REDIS_6_X"
  authorized_network = google_compute_network.vpc.name
  timeouts {}

  labels = {
    goog-dm = "redis"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_router" "router" {
  project = var.project_id
  name    = "router"
  network = var.network_name
  region  = var.region
}

resource "google_compute_router_nat" "nat_config" {
  project                             = var.project_id
  name                                = "nat-config"
  router                              = google_compute_router.router.name
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  nat_ip_allocate_option              = "AUTO_ONLY"
  region                              = google_compute_router.router.region
  enable_endpoint_independent_mapping = false

  log_config {
    enable = false
    filter = "ALL"
  }
}

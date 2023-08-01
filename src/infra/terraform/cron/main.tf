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
  auto_create_subnetworks = "false"

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
}

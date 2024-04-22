### Terraform config example

Example main.tf in your_project/terraform/main.tf configuration:

```
locals {
  project_id    = "YOUR_FUZZER_PROJECT"
  region        = "us-central1"
  subnet_name   = "default"
  network_name  = "default"
  ip_cidr_range = "$YOUR_NETWORK_SUBNET_FOR_GIVEN_REGION"
}

module "clusterfuzz" {
  source        = "CLUSTERFUZZ_SOURCE_PATH/terraform/modules/main.tf"
  project_id    = local.project_id
  region        = local.region
  subnet_name   = local.subnet_name
  network_name  = local.network_name
  ip_cidr_range = local.ip_cidr_range
}
```

### Terraform resourcers manual import

On initial bootstrap is possible to use existing resources instead of creating them.
This is required because Connector name is hard-coded in ClusterFuzz code but it also simplifies new deployments 
```
terraform import module.clusterfuzz.google_compute_network.vpc default
terraform import module.clusterfuzz.google_compute_subnetwork.subnet default
terraform import module.clusterfuzz.google_compute_router.router router
terraform import module.clusterfuzz.google_redis_instance.memorystore_redis_instance redis-instance
terraform import module.clusterfuzz.google_container_cluster.primary "us-central1/clusterfuzz-cronjobs-gke"
terraform import module.clusterfuzz.google_container_node_pool.primary_nodes "us-central1/clusterfuzz-cronjobs-gke/clusterfuzz-cronjobs-gke"
terraform import module.clusterfuzz.google_compute_router_nat.nat_config "us-central1/router/nat-config"
```


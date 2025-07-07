# Copyright 2024 Google LLC
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
  alias = "monitoring"
  project = var.secondary_project_id
  region  = var.region
}

resource "google_monitoring_dashboard" "clusterfuzz_sli_dashboard" {
  provider = google.monitoring
  dashboard_json = <<JSON
{
  "displayName": "Clusterfuzz Relability Metrics",
  "mosaicLayout": {
    "columns": 48,
    "tiles": [
      {
        "yPos": 76,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum by (task)(rate(custom_googleapis_com:task_outcome{monitored_resource=\"gce_instance\",subtask=\"uworker_main\"}[$${__interval}]))\n",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "utask_main execution count",
          "id": ""
        }
      },
      {
        "yPos": 108,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum by (task)(rate(custom_googleapis_com:task_outcome{monitored_resource=\"gce_instance\",subtask=\"preprocess\"}[$${__interval}]))\n",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "preprocess execution count",
          "id": ""
        }
      },
      {
        "yPos": 140,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum by (task)(rate(custom_googleapis_com:task_outcome{monitored_resource=\"gce_instance\",subtask=\"postprocess\"}[$${__interval}]))\n",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "postprocess execution count",
          "id": ""
        }
      },
      {
        "width": 48,
        "height": 4,
        "widget": {
          "title": "Business level metrics",
          "text": {
            "content": "",
            "format": "MARKDOWN",
            "style": {
              "backgroundColor": "#FFFFFF",
              "textColor": "#212121",
              "horizontalAlignment": "H_CENTER",
              "verticalAlignment": "V_TOP",
              "padding": "P_EXTRA_SMALL",
              "fontSize": "FS_LARGE",
              "pointerLocation": "POINTER_LOCATION_UNSPECIFIED"
            }
          },
          "id": ""
        }
      },
      {
        "yPos": 72,
        "width": 48,
        "height": 4,
        "widget": {
          "title": "Task metrics",
          "text": {
            "content": "",
            "format": "MARKDOWN",
            "style": {
              "backgroundColor": "#FFFFFF",
              "textColor": "#212121",
              "horizontalAlignment": "H_CENTER",
              "verticalAlignment": "V_TOP",
              "padding": "P_EXTRA_SMALL",
              "fontSize": "FS_LARGE",
              "pointerLocation": "POINTER_LOCATION_UNSPECIFIED"
            }
          },
          "id": ""
        }
      },
      {
        "yPos": 172,
        "width": 48,
        "height": 4,
        "widget": {
          "title": "Testcase metrics",
          "text": {
            "content": "",
            "format": "MARKDOWN",
            "style": {
              "backgroundColor": "#FFFFFF",
              "textColor": "#212121",
              "horizontalAlignment": "H_CENTER",
              "verticalAlignment": "V_TOP",
              "padding": "P_EXTRA_SMALL",
              "fontSize": "FS_LARGE",
              "pointerLocation": "POINTER_LOCATION_UNSPECIFIED"
            }
          },
          "id": ""
        }
      },
      {
        "yPos": 4,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/task/fuzz/job/total_time\" resource.type=\"gce_instance\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": []
                    }
                  },
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "minAlignmentPeriod": "60s",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Fuzzing hours",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 4,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "topk(10, sum by (job)(rate(custom_googleapis_com:task_fuzz_job_total_time{monitored_resource=\"gce_instance\"}[$${__interval}])))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Fuzzing hours (top 10 jobs)",
          "id": ""
        }
      },
      {
        "xPos": 32,
        "yPos": 4,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "topk(10, sum by (fuzzer)(rate(custom_googleapis_com:task_fuzz_fuzzer_total_time{monitored_resource=\"gce_instance\"}[$${__interval}])))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Fuzzing hours (top 10 fuzzers)",
          "id": ""
        }
      },
      {
        "yPos": 20,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum(increase(custom_googleapis_com:issues_filing{monitored_resource=\"gce_instance\",status=\"success\"}[24h]))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Issues filed in a 24h window",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 20,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum(increase(custom_googleapis_com:issues_closing_success{monitored_resource=\"gce_instance\"}[24h]))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Issues closed in a 24h window",
          "id": ""
        }
      },
      {
        "yPos": 192,
        "width": 16,
        "height": 16,
        "widget": {
          "title": "Untriaged testcase age (p50 - hours)",
          "xyChart": {
            "chartOptions": {
              "mode": "COLOR"
            },
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_50",
                      "groupByFields": [
                        "metric.label.\"step\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"custom.googleapis.com/issues/untriaged_testcase_age\" resource.type=\"gce_instance\""
                  }
                }
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "xPos": 16,
        "yPos": 192,
        "width": 16,
        "height": 16,
        "widget": {
          "title": "Untriaged testcase age (p95 - hours)",
          "xyChart": {
            "chartOptions": {
              "mode": "COLOR"
            },
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"step\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"custom.googleapis.com/issues/untriaged_testcase_age\" resource.type=\"gce_instance\""
                  }
                }
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "xPos": 32,
        "yPos": 192,
        "width": 16,
        "height": 16,
        "widget": {
          "title": "Untriaged testcase age (p99 - hours)",
          "xyChart": {
            "chartOptions": {
              "mode": "COLOR"
            },
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_99",
                      "groupByFields": [
                        "metric.label.\"step\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"custom.googleapis.com/issues/untriaged_testcase_age\" resource.type=\"gce_instance\""
                  }
                }
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "yPos": 36,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum(increase(custom_googleapis_com:task_fuzz_fuzzer_known_crash_count{monitored_resource=\"gce_instance\"}[24h]))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Known crash counts over the last 24h",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 36,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum(increase(custom_googleapis_com:task_fuzz_fuzzer_new_crash_count{monitored_resource=\"gce_instance\"}[24h]))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "New crash counts over the last 24h",
          "id": ""
        }
      },
      {
        "yPos": 124,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.50,\n  sum by (le, task) (\n    increase(custom_googleapis_com:utask_subtask_duration_secs_bucket{\n      monitored_resource=\"gce_instance\",\n      subtask=\"preprocess\",\n    }[1h])\n  )\n)",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "p50 preprocess duration by task (seconds)",
          "id": ""
        }
      },
      {
        "yPos": 92,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.50,\n  sum by (le, task) (\n    increase(custom_googleapis_com:utask_subtask_duration_secs_bucket{\n      monitored_resource=\"gce_instance\",\n      subtask=\"uworker_main\",\n    }[1h])\n  )\n)",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "p50 utask_main duration by task (seconds)",
          "id": ""
        }
      },
      {
        "yPos": 156,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.50,\n  sum by (le, task) (\n    increase(custom_googleapis_com:utask_subtask_duration_secs_bucket{\n      monitored_resource=\"gce_instance\",\n      subtask=\"postprocess\",\n    }[1h])\n  )\n)",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "p50 postprocess duration by task (seconds)",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 124,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.95,\n  sum by (le, task) (\n    increase(custom_googleapis_com:utask_subtask_duration_secs_bucket{\n      monitored_resource=\"gce_instance\",\n      subtask=\"preprocess\",\n    }[1h])\n  )\n)",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "p95 preprocess duration by task (seconds)",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 92,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.95,\n  sum by (le, task) (\n    increase(custom_googleapis_com:utask_subtask_duration_secs_bucket{\n      monitored_resource=\"gce_instance\",\n      subtask=\"uworker_main\",\n    }[1h])\n  )\n)",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "p95 utask_main duration by task (seconds)",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 156,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.95,\n  sum by (le, task) (\n    increase(custom_googleapis_com:utask_subtask_duration_secs_bucket{\n      monitored_resource=\"gce_instance\",\n      subtask=\"postprocess\",\n    }[1h])\n  )\n)",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "p95 postprocess duration by task (seconds)",
          "id": ""
        }
      },
      {
        "yPos": 176,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.50,\n  sum by (le, step) (\n    increase(custom_googleapis_com:testcase_analysis_triage_duration_hours_bucket{\n      monitored_resource=\"gce_instance\",\n    }[1h])\n  )\n)\n\n",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Testcase triage duration (p50 - hours) - by step",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 176,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.90,\n  sum by (le, step) (\n    increase(custom_googleapis_com:testcase_analysis_triage_duration_hours_bucket{\n      monitored_resource=\"gce_instance\",\n    }[1h])\n  )\n)\n\n",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Testcase triage duration (p90 - hours) - by step",
          "id": ""
        }
      },
      {
        "xPos": 32,
        "yPos": 176,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.95,\n  sum by (le, step) (\n    increase(custom_googleapis_com:testcase_analysis_triage_duration_hours_bucket{\n      monitored_resource=\"gce_instance\",\n    }[1h])\n  )\n)\n",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Testcase triage duration (p95 - hours) - by step",
          "id": ""
        }
      },
      {
        "yPos": 224,
        "width": 48,
        "height": 4,
        "widget": {
          "title": "GCS metrics",
          "text": {
            "content": "",
            "format": "MARKDOWN",
            "style": {
              "backgroundColor": "#FFFFFF",
              "textColor": "#212121",
              "horizontalAlignment": "H_CENTER",
              "verticalAlignment": "V_TOP",
              "padding": "P_EXTRA_SMALL",
              "fontSize": "FS_LARGE",
              "pointerLocation": "POINTER_LOCATION_UNSPECIFIED"
            }
          },
          "id": ""
        }
      },
      {
        "yPos": 228,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"storage.googleapis.com/api/request_count\" resource.type=\"gcs_bucket\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": [
                        "metric.label.\"method\""
                      ]
                    }
                  },
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "minAlignmentPeriod": "60s",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "GCS - Request count by method",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 228,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "100 * (sum by (method)(rate(storage_googleapis_com:api_request_count{monitored_resource=\"gcs_bucket\", response_code!=\"OK\"}[$${__interval}])) \n/\nsum by (method)(rate(storage_googleapis_com:api_request_count{monitored_resource=\"gcs_bucket\"}[$${__interval}])))",
                  "unitOverride": "%",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "GCS - Error rate by method",
          "id": ""
        }
      },
      {
        "xPos": 32,
        "yPos": 228,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"storage.googleapis.com/api/request_count\" resource.type=\"gcs_bucket\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": [
                        "metric.label.\"response_code\""
                      ]
                    }
                  },
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "minAlignmentPeriod": "60s",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "GCS Bucket - Request count by response code",
          "id": ""
        }
      },
      {
        "yPos": 248,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"datastore.googleapis.com/api/request_count\" resource.type=\"datastore_request\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": [
                        "metric.label.\"api_method\""
                      ]
                    }
                  },
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "minAlignmentPeriod": "60s",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Datastore - Request count by method",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 248,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": " 100 * sum by (api_method)(rate(datastore_googleapis_com:api_request_count{monitored_resource=\"datastore_request\", response_code!='OK'}[$${__interval}])) /\nsum by (api_method)(rate(datastore_googleapis_com:api_request_count{monitored_resource=\"datastore_request\"}[$${__interval}]))",
                  "unitOverride": "%",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Datastore - Error rate by method",
          "id": ""
        }
      },
      {
        "yPos": 264,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.50,sum by (api_method,le)(increase(firestore_googleapis_com:api_request_latencies_bucket{monitored_resource=\"firestore.googleapis.com/Database\"}[$${__interval}])))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Datastore - Latency by method (p50)",
          "id": ""
        }
      },
      {
        "xPos": 32,
        "yPos": 248,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"datastore.googleapis.com/api/request_count\" resource.type=\"datastore_request\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": [
                        "metric.label.\"response_code\""
                      ]
                    }
                  },
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "minAlignmentPeriod": "60s",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Datastore - Request count by response code",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 264,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.90,sum by (api_method,le)(increase(firestore_googleapis_com:api_request_latencies_bucket{monitored_resource=\"firestore.googleapis.com/Database\"}[$${__interval}])))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Datastore - Latency by method (p90)",
          "id": ""
        }
      },
      {
        "xPos": 32,
        "yPos": 264,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "histogram_quantile(0.95,sum by (api_method,le)(increase(firestore_googleapis_com:api_request_latencies_bucket{monitored_resource=\"firestore.googleapis.com/Database\"}[$${__interval}])))",
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "Datastore - Latency by method (p95)",
          "id": ""
        }
      },
      {
        "yPos": 244,
        "width": 48,
        "height": 4,
        "widget": {
          "title": "Datastore metrics",
          "text": {
            "content": "",
            "format": "MARKDOWN",
            "style": {
              "backgroundColor": "#FFFFFF",
              "textColor": "#212121",
              "horizontalAlignment": "H_CENTER",
              "verticalAlignment": "V_TOP",
              "padding": "P_EXTRA_SMALL",
              "fontSize": "FS_LARGE",
              "pointerLocation": "POINTER_LOCATION_UNSPECIFIED"
            }
          },
          "id": ""
        }
      },
      {
        "yPos": 52,
        "width": 48,
        "height": 4,
        "widget": {
          "title": "PubSub metrics",
          "text": {
            "content": "",
            "format": "MARKDOWN",
            "style": {
              "backgroundColor": "#FFFFFF",
              "textColor": "#212121",
              "horizontalAlignment": "H_CENTER",
              "verticalAlignment": "V_TOP",
              "padding": "P_EXTRA_SMALL",
              "fontSize": "FS_LARGE",
              "pointerLocation": "POINTER_LOCATION_UNSPECIFIED"
            }
          },
          "id": ""
        }
      },
      {
        "yPos": 56,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"pubsub.googleapis.com/subscription/num_undelivered_messages\" resource.type=\"pubsub_subscription\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_MEAN",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": [
                        "metadata.system_labels.\"topic_id\""
                      ]
                    }
                  },
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "minAlignmentPeriod": "60s",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "PubSub - Unacked messages (per topic)",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 56,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"pubsub.googleapis.com/topic/send_request_count\" resource.type=\"pubsub_topic\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": [
                        "resource.label.\"topic_id\""
                      ]
                    }
                  },
                  "unitOverride": "",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "minAlignmentPeriod": "60s",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "PubSub - Sent messages (per topic)",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 108,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "100 * sum by (task)(rate(custom_googleapis_com:task_outcome_by_error_type{monitored_resource=\"gce_instance\",subtask=\"preprocess\", error_condition=\"UNHANDLED_EXCEPTION\"}[$${__interval}]))\n/ sum by (task)(rate(custom_googleapis_com:task_outcome_by_error_type{monitored_resource=\"gce_instance\",subtask=\"preprocess\"}[$${__interval}]))",
                  "unitOverride": "%",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "preprocess unhandled exception rate (by task)",
          "id": ""
        }
      },
      {
        "xPos": 32,
        "yPos": 76,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "100 * sum by (task)(rate(custom_googleapis_com:task_outcome_by_error_type{monitored_resource=\"gce_instance\",subtask=\"uworker_main\", error_condition=\"UNHANDLED_EXCEPTION\"}[$${__interval}]))\n/ sum by (task)(rate(custom_googleapis_com:task_outcome_by_error_type{monitored_resource=\"gce_instance\",subtask=\"uworker_main\"}[$${__interval}]))",
                  "unitOverride": "%",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "uworker_main unhandled exception rate (by task)",
          "id": ""
        }
      },
      {
        "xPos": 16,
        "yPos": 140,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "sum by (task)(rate(custom_googleapis_com:task_outcome_by_error_type{monitored_resource=\"gce_instance\", subtask=\"postprocess\", error_condition=\"UNHANDLED_EXCEPTION\"}[$${__interval}]))\n/ sum by (task)(rate(custom_googleapis_com:task_outcome_by_error_type{monitored_resource=\"gce_instance\", subtask=\"postprocess\"}[$${__interval}]))",
                  "unitOverride": "%",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "postprocess unhandled exception rate (by task)",
          "id": ""
        }
      },
      {
        "yPos": 208,
        "width": 16,
        "height": 16,
        "widget": {
          "title": "Untriaged testcase count (by status)",
          "xyChart": {
            "chartOptions": {
              "mode": "COLOR"
            },
            "dataSets": [
              {
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "prometheusQuery": "sum by (status)(last_over_time((custom_googleapis_com:issues_untriaged_testcase_count{monitored_resource=\"gce_instance\"}[1h])))\n",
                  "unitOverride": ""
                }
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "xPos": 16,
        "yPos": 76,
        "width": 16,
        "height": 16,
        "widget": {
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "prometheusQuery": "100 * sum by (task)(rate(custom_googleapis_com:task_outcome{monitored_resource=\"gce_instance\",subtask=\"uworker_main\", task_succeeded=\"false\"}[$${__interval}]))\n/ sum by (task)(rate(custom_googleapis_com:task_outcome{monitored_resource=\"gce_instance\",subtask=\"uworker_main\"}[$${__interval}]))",
                  "unitOverride": "%",
                  "outputFullDuration": false
                },
                "plotType": "LINE",
                "legendTemplate": "",
                "targetAxis": "Y1",
                "dimensions": [],
                "measures": [],
                "breakdowns": []
              }
            ],
            "thresholds": [],
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR",
              "showLegend": false,
              "displayHorizontal": false
            }
          },
          "title": "uworker_main overall failure rate (by task) - CAN BE DRILLED BY JOB",
          "id": ""
        }
      }
    ]
  },
  "dashboardFilters": [],
  "labels": {}
}
JSON
}

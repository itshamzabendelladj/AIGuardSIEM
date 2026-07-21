# AIGuardSIEM - Terraform Infrastructure
# AWS/Azure/GCP multi-cloud deployment

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "cluster_name" {
  type    = string
  default = "aiguard-siem"
}

variable "environment" {
  type    = string
  default = "production"
}

# EKS Cluster
module "eks" {
  source = "./modules/aws/eks"

  cluster_name    = var.cluster_name
  cluster_version = "1.28"
  environment     = var.environment

  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets

  node_groups = {
    collectors = {
      instance_types = ["c5.2xlarge"]
      capacity_type  = "OnDemand"
      scaling_config = {
        desired_size = 3
        max_size     = 10
        min_size     = 3
      }
    }
    processing = {
      instance_types = ["c5.4xlarge"]
      capacity_type  = "OnDemand"
      scaling_config = {
        desired_size = 4
        max_size     = 16
        min_size     = 4
      }
    }
    storage = {
      instance_types = ["r5.2xlarge"]
      capacity_type  = "OnDemand"
      scaling_config = {
        desired_size = 3
        max_size     = 6
        min_size     = 3
      }
    }
    ml = {
      instance_types = ["g4dn.xlarge"]
      capacity_type  = "OnDemand"
      scaling_config = {
        desired_size = 2
        max_size     = 4
        min_size     = 1
      }
    }
  }
}

# VPC
module "vpc" {
  source = "./modules/aws/vpc"

  name = var.cluster_name
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = false
}

# S3 for cold storage
module "cold_storage" {
  source = "./modules/aws/s3"

  bucket_name = "aiguard-cold-storage-${var.environment}"
  versioning  = true
  encryption  = true
  lifecycle_days = 90
  glacier_transition_days = 30
}

# Helm release
resource "helm_release" "aiguard_siem" {
  name       = "aiguard-siem"
  repository = "./deployment/helm"
  chart      = "siem-xdr"
  namespace  = "aiguard-siem"

  create_namespace = true

  set {
    name  = "image.tag"
    value = "1.0.0"
  }

  set {
    name  = "global.storageClass"
    value = "gp3"
  }

  depends_on = [module.eks]
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "cold_storage_bucket" {
  value = module.cold_storage.bucket_name
}

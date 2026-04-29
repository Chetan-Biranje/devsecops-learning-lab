###############################################################
#  DevSecOps Learning Lab – Terraform  (AWS EKS)
#  Security-hardened infrastructure as code
###############################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }

  # ── Remote state with encryption & locking ──────────────
  backend "s3" {
    bucket         = "devsecops-lab-tfstate"
    key            = "lab/terraform.tfstate"
    region         = "ap-south-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "devsecops-learning-lab"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "chetan-biranje"
    }
  }
}

# ── VPC ──────────────────────────────────────────────────
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.13.0"

  name = "${var.project_name}-vpc"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "prod"
  enable_vpn_gateway     = false
  enable_dns_hostnames   = true
  enable_dns_support     = true

  # Flow logs for security monitoring
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_max_aggregation_interval    = 60

  tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
}

# ── EKS Cluster ───────────────────────────────────────────
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.24.1"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  # ── Security: envelope encryption for secrets ───────────
  cluster_encryption_config = {
    resources = ["secrets"]
  }

  # ── Logging ─────────────────────────────────────────────
  cluster_enabled_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # ── Managed Node Group ──────────────────────────────────
  eks_managed_node_groups = {
    general = {
      name           = "${var.project_name}-ng"
      instance_types = [var.node_instance_type]
      min_size       = 2
      max_size       = 5
      desired_size   = 2

      ami_type  = "AL2_x86_64"
      disk_size = 50

      # Security: encrypted root volume
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 50
            volume_type           = "gp3"
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      labels = {
        role = "worker"
      }

      taints = []

      update_config = {
        max_unavailable_percentage = 33
      }
    }
  }

  # ── Add-ons ─────────────────────────────────────────────
  cluster_addons = {
    coredns                = { most_recent = true }
    kube-proxy             = { most_recent = true }
    vpc-cni                = { most_recent = true }
    aws-ebs-csi-driver     = { most_recent = true }
    eks-pod-identity-agent = { most_recent = true }
  }
}

# ── Outputs ───────────────────────────────────────────────
output "cluster_endpoint"      { value = module.eks.cluster_endpoint }
output "cluster_name"          { value = module.eks.cluster_name }
output "cluster_oidc_issuer"   { value = module.eks.cluster_oidc_issuer_url }
output "vpc_id"                { value = module.vpc.vpc_id }

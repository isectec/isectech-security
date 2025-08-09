# iSECTECH High Availability Multi-Region Infrastructure
# Terraform configuration for production-grade HA deployment across multiple zones and regions

terraform {
  required_version = ">= 1.5"
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

  backend "s3" {
    bucket = "isectech-terraform-state"
    key    = "disaster-recovery/infrastructure/terraform.tfstate"
    region = "us-east-1"
    
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Primary region (us-east-1)
provider "aws" {
  region = var.primary_region
  
  default_tags {
    tags = {
      Project         = "iSECTECH"
      Environment     = var.environment
      TerraformManaged = "true"
      DisasterRecovery = "true"
      CostCenter      = "platform"
      Owner           = "platform-engineering"
    }
  }
}

# Secondary region (us-west-2)
provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
  
  default_tags {
    tags = {
      Project         = "iSECTECH"
      Environment     = var.environment
      TerraformManaged = "true"
      DisasterRecovery = "true"
      CostCenter      = "platform"
      Owner           = "platform-engineering"
      Region          = "secondary"
    }
  }
}

# Tertiary region (eu-west-1)
provider "aws" {
  alias  = "tertiary"
  region = var.tertiary_region
  
  default_tags {
    tags = {
      Project         = "iSECTECH"
      Environment     = var.environment
      TerraformManaged = "true"
      DisasterRecovery = "true"
      CostCenter      = "platform"
      Owner           = "platform-engineering"
      Region          = "tertiary"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

data "aws_availability_zones" "primary" {
  state = "available"
}

data "aws_availability_zones" "secondary" {
  provider = aws.secondary
  state    = "available"
}

data "aws_availability_zones" "tertiary" {
  provider = aws.tertiary
  state    = "available"
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL VALUES
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Environment configuration
  name_prefix = "${var.project_name}-${var.environment}"
  
  # Multi-region configuration
  regions = {
    primary   = var.primary_region
    secondary = var.secondary_region
    tertiary  = var.tertiary_region
  }
  
  # Network configuration
  vpc_cidr = {
    primary   = "10.0.0.0/16"
    secondary = "10.1.0.0/16"
    tertiary  = "10.2.0.0/16"
  }
  
  # Availability zones per region
  azs = {
    primary   = slice(data.aws_availability_zones.primary.names, 0, 3)
    secondary = slice(data.aws_availability_zones.secondary.names, 0, 3)
    tertiary  = slice(data.aws_availability_zones.tertiary.names, 0, 3)
  }
  
  # Subnet CIDR blocks
  subnet_cidrs = {
    primary = {
      public  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
      private = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
      database = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
    }
    secondary = {
      public  = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
      private = ["10.1.11.0/24", "10.1.12.0/24", "10.1.13.0/24"]
      database = ["10.1.21.0/24", "10.1.22.0/24", "10.1.23.0/24"]
    }
    tertiary = {
      public  = ["10.2.1.0/24", "10.2.2.0/24", "10.2.3.0/24"]
      private = ["10.2.11.0/24", "10.2.12.0/24", "10.2.13.0/24"]
      database = ["10.2.21.0/24", "10.2.22.0/24", "10.2.23.0/24"]
    }
  }
  
  # Common tags
  common_tags = {
    Project      = var.project_name
    Environment  = var.environment
    Terraform    = "true"
    HighAvailability = "true"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VPC AND NETWORKING - PRIMARY REGION
# ═══════════════════════════════════════════════════════════════════════════════

module "vpc_primary" {
  source = "./modules/vpc"
  
  name = "${local.name_prefix}-primary"
  cidr = local.vpc_cidr.primary
  
  azs             = local.azs.primary
  public_subnets  = local.subnet_cidrs.primary.public
  private_subnets = local.subnet_cidrs.primary.private
  database_subnets = local.subnet_cidrs.primary.database
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true
  
  # Enable flow logs for security monitoring
  enable_flow_log = true
  flow_log_destination_type = "s3"
  flow_log_destination_arn = module.s3_flow_logs.s3_bucket_arn
  
  tags = merge(local.common_tags, {
    Region = "primary"
    Name   = "${local.name_prefix}-vpc-primary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# VPC AND NETWORKING - SECONDARY REGION
# ═══════════════════════════════════════════════════════════════════════════════

module "vpc_secondary" {
  source = "./modules/vpc"
  
  providers = {
    aws = aws.secondary
  }
  
  name = "${local.name_prefix}-secondary"
  cidr = local.vpc_cidr.secondary
  
  azs             = local.azs.secondary
  public_subnets  = local.subnet_cidrs.secondary.public
  private_subnets = local.subnet_cidrs.secondary.private
  database_subnets = local.subnet_cidrs.secondary.database
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true
  
  enable_flow_log = true
  flow_log_destination_type = "s3"
  flow_log_destination_arn = module.s3_flow_logs_secondary.s3_bucket_arn
  
  tags = merge(local.common_tags, {
    Region = "secondary"
    Name   = "${local.name_prefix}-vpc-secondary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# VPC AND NETWORKING - TERTIARY REGION
# ═══════════════════════════════════════════════════════════════════════════════

module "vpc_tertiary" {
  source = "./modules/vpc"
  
  providers = {
    aws = aws.tertiary
  }
  
  name = "${local.name_prefix}-tertiary"
  cidr = local.vpc_cidr.tertiary
  
  azs             = local.azs.tertiary
  public_subnets  = local.subnet_cidrs.tertiary.public
  private_subnets = local.subnet_cidrs.tertiary.private
  database_subnets = local.subnet_cidrs.tertiary.database
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true
  
  enable_flow_log = true
  flow_log_destination_type = "s3"
  flow_log_destination_arn = module.s3_flow_logs_tertiary.s3_bucket_arn
  
  tags = merge(local.common_tags, {
    Region = "tertiary"
    Name   = "${local.name_prefix}-vpc-tertiary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# VPC PEERING FOR CROSS-REGION CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════════════════

# Primary to Secondary region peering
resource "aws_vpc_peering_connection" "primary_to_secondary" {
  vpc_id        = module.vpc_primary.vpc_id
  peer_vpc_id   = module.vpc_secondary.vpc_id
  peer_region   = var.secondary_region
  auto_accept   = false
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-peering-primary-secondary"
  })
}

resource "aws_vpc_peering_connection_accepter" "secondary_accepter" {
  provider                  = aws.secondary
  vpc_peering_connection_id = aws_vpc_peering_connection.primary_to_secondary.id
  auto_accept               = true
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-peering-accepter-secondary"
  })
}

# Primary to Tertiary region peering
resource "aws_vpc_peering_connection" "primary_to_tertiary" {
  vpc_id        = module.vpc_primary.vpc_id
  peer_vpc_id   = module.vpc_tertiary.vpc_id
  peer_region   = var.tertiary_region
  auto_accept   = false
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-peering-primary-tertiary"
  })
}

resource "aws_vpc_peering_connection_accepter" "tertiary_accepter" {
  provider                  = aws.tertiary
  vpc_peering_connection_id = aws_vpc_peering_connection.primary_to_tertiary.id
  auto_accept               = true
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-peering-accepter-tertiary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# ROUTE53 HOSTED ZONES AND HEALTH CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

resource "aws_route53_zone" "main" {
  name = var.domain_name
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-main-zone"
  })
}

# Health checks for each region
resource "aws_route53_health_check" "primary" {
  fqdn                            = "primary.${var.domain_name}"
  port                            = 443
  type                            = "HTTPS"
  resource_path                   = "/health"
  failure_threshold               = "3"
  request_interval                = "30"
  cloudwatch_alarm_name           = "${local.name_prefix}-primary-health"
  cloudwatch_alarm_region         = var.primary_region
  insufficient_data_health_status = "Failure"
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-health-check-primary"
  })
}

resource "aws_route53_health_check" "secondary" {
  fqdn                            = "secondary.${var.domain_name}"
  port                            = 443
  type                            = "HTTPS"
  resource_path                   = "/health"
  failure_threshold               = "3"
  request_interval                = "30"
  cloudwatch_alarm_name           = "${local.name_prefix}-secondary-health"
  cloudwatch_alarm_region         = var.secondary_region
  insufficient_data_health_status = "Failure"
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-health-check-secondary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION LOAD BALANCERS
# ═══════════════════════════════════════════════════════════════════════════════

module "alb_primary" {
  source = "./modules/load-balancer"
  
  name = "${local.name_prefix}-alb-primary"
  
  vpc_id          = module.vpc_primary.vpc_id
  subnets         = module.vpc_primary.public_subnets
  security_groups = [module.alb_security_group_primary.security_group_id]
  
  enable_deletion_protection = var.environment == "production"
  
  # SSL Certificate
  certificate_arn = aws_acm_certificate_validation.primary.certificate_arn
  
  # Target groups
  target_groups = [
    {
      name     = "${local.name_prefix}-frontend-primary"
      port     = 3000
      protocol = "HTTP"
      vpc_id   = module.vpc_primary.vpc_id
      health_check = {
        enabled             = true
        healthy_threshold   = 2
        interval            = 30
        matcher             = "200"
        path                = "/health"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }
    },
    {
      name     = "${local.name_prefix}-backend-primary"
      port     = 8080
      protocol = "HTTP"
      vpc_id   = module.vpc_primary.vpc_id
      health_check = {
        enabled             = true
        healthy_threshold   = 2
        interval            = 30
        matcher             = "200"
        path                = "/health"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }
    }
  ]
  
  tags = merge(local.common_tags, {
    Region = "primary"
  })
}

module "alb_secondary" {
  source = "./modules/load-balancer"
  
  providers = {
    aws = aws.secondary
  }
  
  name = "${local.name_prefix}-alb-secondary"
  
  vpc_id          = module.vpc_secondary.vpc_id
  subnets         = module.vpc_secondary.public_subnets
  security_groups = [module.alb_security_group_secondary.security_group_id]
  
  enable_deletion_protection = var.environment == "production"
  
  certificate_arn = aws_acm_certificate_validation.secondary.certificate_arn
  
  target_groups = [
    {
      name     = "${local.name_prefix}-frontend-secondary"
      port     = 3000
      protocol = "HTTP"
      vpc_id   = module.vpc_secondary.vpc_id
      health_check = {
        enabled             = true
        healthy_threshold   = 2
        interval            = 30
        matcher             = "200"
        path                = "/health"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }
    },
    {
      name     = "${local.name_prefix}-backend-secondary"
      port     = 8080
      protocol = "HTTP"
      vpc_id   = module.vpc_secondary.vpc_id
      health_check = {
        enabled             = true
        healthy_threshold   = 2
        interval            = 30
        matcher             = "200"
        path                = "/health"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }
    }
  ]
  
  tags = merge(local.common_tags, {
    Region = "secondary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# EKS CLUSTERS
# ═══════════════════════════════════════════════════════════════════════════════

module "eks_primary" {
  source = "./modules/eks"
  
  cluster_name = "${local.name_prefix}-primary"
  
  vpc_id                   = module.vpc_primary.vpc_id
  subnet_ids               = module.vpc_primary.private_subnets
  control_plane_subnet_ids = module.vpc_primary.private_subnets
  
  cluster_version = var.kubernetes_version
  
  # Enable logging
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  # Node groups
  node_groups = {
    system = {
      desired_capacity = 3
      max_capacity     = 6
      min_capacity     = 3
      
      instance_types = ["m6i.large"]
      
      k8s_labels = {
        role = "system"
      }
      
      taints = [
        {
          key    = "node-type"
          value  = "system"
          effect = "NO_SCHEDULE"
        }
      ]
    }
    
    application = {
      desired_capacity = 6
      max_capacity     = 20
      min_capacity     = 6
      
      instance_types = ["m6i.xlarge", "m6i.2xlarge"]
      
      k8s_labels = {
        role = "application"
      }
    }
    
    monitoring = {
      desired_capacity = 2
      max_capacity     = 4
      min_capacity     = 2
      
      instance_types = ["m6i.large"]
      
      k8s_labels = {
        role = "monitoring"
      }
    }
  }
  
  # Enable IRSA (IAM Roles for Service Accounts)
  enable_irsa = true
  
  tags = merge(local.common_tags, {
    Region = "primary"
  })
}

module "eks_secondary" {
  source = "./modules/eks"
  
  providers = {
    aws        = aws.secondary
    kubernetes = kubernetes.secondary
  }
  
  cluster_name = "${local.name_prefix}-secondary"
  
  vpc_id                   = module.vpc_secondary.vpc_id
  subnet_ids               = module.vpc_secondary.private_subnets
  control_plane_subnet_ids = module.vpc_secondary.private_subnets
  
  cluster_version = var.kubernetes_version
  
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  node_groups = {
    system = {
      desired_capacity = 2
      max_capacity     = 4
      min_capacity     = 2
      
      instance_types = ["m6i.large"]
      
      k8s_labels = {
        role = "system"
      }
    }
    
    application = {
      desired_capacity = 4
      max_capacity     = 12
      min_capacity     = 2
      
      instance_types = ["m6i.xlarge"]
      
      k8s_labels = {
        role = "application"
      }
    }
  }
  
  enable_irsa = true
  
  tags = merge(local.common_tags, {
    Region = "secondary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# RDS AURORA CLUSTERS
# ═══════════════════════════════════════════════════════════════════════════════

module "aurora_primary" {
  source = "./modules/aurora"
  
  cluster_identifier = "${local.name_prefix}-primary"
  
  engine         = "aurora-postgresql"
  engine_version = var.aurora_version
  
  database_name   = var.database_name
  master_username = var.database_username
  
  vpc_id     = module.vpc_primary.vpc_id
  subnet_ids = module.vpc_primary.database_subnets
  
  # High availability configuration
  instances = {
    writer = {
      instance_class = var.database_instance_class
      publicly_accessible = false
    }
    reader1 = {
      instance_class = var.database_instance_class
      publicly_accessible = false
    }
    reader2 = {
      instance_class = var.database_instance_class
      publicly_accessible = false
    }
  }
  
  # Backup configuration
  backup_retention_period = 35
  preferred_backup_window = "03:00-05:00"
  preferred_maintenance_window = "sun:05:00-sun:07:00"
  
  # Encryption
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds_primary.arn
  
  # Cross-region backups
  enable_global_cluster = true
  global_cluster_identifier = "${local.name_prefix}-global"
  
  # Enhanced monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_enhanced_monitoring.arn
  
  # Performance Insights
  performance_insights_enabled = true
  performance_insights_retention_period = 7
  
  tags = merge(local.common_tags, {
    Region = "primary"
    Role   = "primary-database"
  })
}

module "aurora_secondary" {
  source = "./modules/aurora"
  
  providers = {
    aws = aws.secondary
  }
  
  cluster_identifier = "${local.name_prefix}-secondary"
  
  engine         = "aurora-postgresql"
  engine_version = var.aurora_version
  
  # Secondary cluster for global database
  global_cluster_identifier = module.aurora_primary.global_cluster_id
  is_secondary_cluster = true
  
  vpc_id     = module.vpc_secondary.vpc_id
  subnet_ids = module.vpc_secondary.database_subnets
  
  instances = {
    reader1 = {
      instance_class = var.database_instance_class
      publicly_accessible = false
    }
    reader2 = {
      instance_class = var.database_instance_class
      publicly_accessible = false
    }
  }
  
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds_secondary.arn
  
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_enhanced_monitoring_secondary.arn
  
  performance_insights_enabled = true
  performance_insights_retention_period = 7
  
  tags = merge(local.common_tags, {
    Region = "secondary"
    Role   = "secondary-database"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# ELASTICACHE REDIS CLUSTERS
# ═══════════════════════════════════════════════════════════════════════════════

module "redis_primary" {
  source = "./modules/elasticache"
  
  cluster_id = "${local.name_prefix}-redis-primary"
  
  engine         = "redis"
  engine_version = var.redis_version
  node_type      = var.redis_node_type
  
  num_cache_clusters = 3
  
  subnet_group_name = aws_elasticache_subnet_group.primary.name
  security_group_ids = [module.redis_security_group_primary.security_group_id]
  
  # High availability
  automatic_failover_enabled = true
  multi_az_enabled           = true
  
  # Backup configuration
  snapshot_retention_limit = 10
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "sun:05:00-sun:07:00"
  
  # Security
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token_enabled         = true
  
  tags = merge(local.common_tags, {
    Region = "primary"
  })
}

module "redis_secondary" {
  source = "./modules/elasticache"
  
  providers = {
    aws = aws.secondary
  }
  
  cluster_id = "${local.name_prefix}-redis-secondary"
  
  engine         = "redis"
  engine_version = var.redis_version
  node_type      = var.redis_node_type
  
  num_cache_clusters = 2
  
  subnet_group_name = aws_elasticache_subnet_group.secondary.name
  security_group_ids = [module.redis_security_group_secondary.security_group_id]
  
  automatic_failover_enabled = true
  multi_az_enabled           = true
  
  snapshot_retention_limit = 10
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "sun:05:00-sun:07:00"
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token_enabled         = true
  
  tags = merge(local.common_tags, {
    Region = "secondary"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "vpc_primary" {
  description = "Primary VPC information"
  value = {
    vpc_id     = module.vpc_primary.vpc_id
    vpc_cidr   = module.vpc_primary.vpc_cidr_block
    public_subnets = module.vpc_primary.public_subnets
    private_subnets = module.vpc_primary.private_subnets
    database_subnets = module.vpc_primary.database_subnets
  }
}

output "vpc_secondary" {
  description = "Secondary VPC information"
  value = {
    vpc_id     = module.vpc_secondary.vpc_id
    vpc_cidr   = module.vpc_secondary.vpc_cidr_block
    public_subnets = module.vpc_secondary.public_subnets
    private_subnets = module.vpc_secondary.private_subnets
    database_subnets = module.vpc_secondary.database_subnets
  }
}

output "eks_clusters" {
  description = "EKS cluster information"
  value = {
    primary = {
      cluster_id       = module.eks_primary.cluster_id
      cluster_arn      = module.eks_primary.cluster_arn
      cluster_endpoint = module.eks_primary.cluster_endpoint
      cluster_version  = module.eks_primary.cluster_version
    }
    secondary = {
      cluster_id       = module.eks_secondary.cluster_id
      cluster_arn      = module.eks_secondary.cluster_arn
      cluster_endpoint = module.eks_secondary.cluster_endpoint
      cluster_version  = module.eks_secondary.cluster_version
    }
  }
}

output "aurora_clusters" {
  description = "Aurora cluster information"
  value = {
    primary = {
      cluster_id       = module.aurora_primary.cluster_id
      cluster_endpoint = module.aurora_primary.cluster_endpoint
      reader_endpoint  = module.aurora_primary.cluster_reader_endpoint
    }
    secondary = {
      cluster_id       = module.aurora_secondary.cluster_id
      cluster_endpoint = module.aurora_secondary.cluster_endpoint
      reader_endpoint  = module.aurora_secondary.cluster_reader_endpoint
    }
  }
}

output "load_balancers" {
  description = "Load balancer information"
  value = {
    primary = {
      dns_name = module.alb_primary.lb_dns_name
      zone_id  = module.alb_primary.lb_zone_id
    }
    secondary = {
      dns_name = module.alb_secondary.lb_dns_name
      zone_id  = module.alb_secondary.lb_zone_id
    }
  }
}

output "route53_zone" {
  description = "Route53 hosted zone information"
  value = {
    zone_id = aws_route53_zone.main.zone_id
    name_servers = aws_route53_zone.main.name_servers
  }
}
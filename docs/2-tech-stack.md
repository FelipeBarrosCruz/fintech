# Documentação: Stack Tecnológica da Plataforma de Pagamentos

## 1. Visão Geral

Este documento detalha a stack tecnológica completa da plataforma de pagamentos, incluindo justificativas técnicas, padrões de integração e exemplos práticos de uso. A arquitetura é baseada em cloud-native AWS com foco em escalabilidade, segurança e observabilidade.

## 2. Arquitetura de Referência

### 2.1 Camadas da Arquitetura
```
┌─────────────────────────────────────────────────────────┐
│                    Cloudflare Layer                      │
│         (CDN, DNS, WAF, DDoS Protection, Bot)           │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                      AWS Layer                           │
│  ┌──────────────────────────────────────────────────┐  │
│  │  API Gateway + Cognito (Auth/AuthZ)              │  │
│  └──────────────────────────────────────────────────┘  │
│                           ↓                              │
│  ┌──────────────────────────────────────────────────┐  │
│  │  ALB (Application Load Balancer)                 │  │
│  └──────────────────────────────────────────────────┘  │
│                           ↓                              │
│  ┌──────────────────────────────────────────────────┐  │
│  │  ECS Fargate (Microservices)                     │  │
│  │  - User Service                                   │  │
│  │  - Payments Service                               │  │
│  │  - Store Service                                  │  │
│  │  - Getnet Service                                 │  │
│  │  - Notification Service                           │  │
│  │  - Ledger Service                                 │  │
│  └──────────────────────────────────────────────────┘  │
│                           ↓                              │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Data Layer                                       │  │
│  │  - RDS PostgreSQL (Transactional)                │  │
│  │  - DocumentDB (Events/Analytics)                 │  │
│  │  - Redis (Cache)                                  │  │
│  │  - S3 (Storage)                                   │  │
│  └──────────────────────────────────────────────────┘  │
│                           ↓                              │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Event Layer                                      │  │
│  │  - EventBridge (Event Bus)                       │  │
│  │  - SNS + SQS (Messaging)                         │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│              Observability Layer                         │
│         (Datadog, CloudWatch, OpenTelemetry)            │
└─────────────────────────────────────────────────────────┘
```

## 3. Camada de Edge e CDN

### 3.1 Cloudflare

#### 3.1.1 Propósito
Cloudflare atua como a primeira linha de defesa e otimização, fornecendo:
- Proteção contra ataques DDoS
- Web Application Firewall (WAF)
- Content Delivery Network (CDN)
- DNS management
- Bot protection
- Rate limiting

#### 3.1.2 Integração na Arquitetura
**Fluxo de Requisição:**
1. Cliente faz requisição → Cloudflare DNS
2. Cloudflare aplica regras de firewall e WAF
3. Valida se é bot legítimo ou malicioso
4. Aplica rate limiting por IP/região
5. Encaminha para AWS (se aprovado)

#### 3.1.3 Por que Cloudflare?
- **Performance**: 200+ data centers globalmente, latência < 50ms
- **Segurança**: Proteção contra ataques de camada 3, 4 e 7
- **Disponibilidade**: 100% SLA uptime
- **Custo-benefício**: Reduz tráfego malicioso antes de chegar à AWS
- **Compliance**: Certificações PCI-DSS, SOC 2, ISO 27001

#### 3.1.4 Configurações Principais
**Firewall Rules:**
```javascript
// Bloquear países de alto risco
if (ip.geoip.country in {"XX", "YY"}) {
  return "block";
}

// Rate limiting agressivo para endpoints sensíveis
if (http.request.uri.path matches "/api/v1/payments") {
  rate_limit(100 requests per minute);
}
```

**WAF Rules:**
- OWASP Top 10 protection
- SQL Injection prevention
- XSS protection
- Custom rules para padrões de ataque conhecidos

**Bot Management:**
- Challenge para bots suspeitos
- Allow para bots legítimos (Google, Bing)
- Block para bots maliciosos conhecidos

#### 3.1.5 Exemplo Real
**Cenário**: Ataque DDoS de 100.000 req/s
- Cloudflare absorve 99% do tráfego malicioso
- Apenas 1.000 req/s legítimas chegam à AWS
- Economia de custos: ~$5.000/hora em infraestrutura AWS

---

## 4. Camada de Cloud Provider (AWS)

### 4.1 API Gateway

#### 4.1.1 Propósito
Gerenciamento centralizado de APIs, fornecendo:
- Roteamento de requisições
- Autenticação e autorização
- Rate limiting e throttling
- Request/response transformation
- API versioning
- Caching de respostas

#### 4.1.2 Integração na Arquitetura
**Fluxo:**
1. Requisição chega do Cloudflare
2. API Gateway valida JWT token (Cognito)
3. Aplica rate limiting por usuário/API key
4. Roteia para ALB correspondente
5. Retorna resposta (com cache se aplicável)

#### 4.1.3 Por que API Gateway?
- **Segurança**: Integração nativa com Cognito
- **Escalabilidade**: Auto-scaling automático
- **Observabilidade**: Logs e métricas integrados
- **Custo**: Pay-per-use, sem infraestrutura fixa
- **Gerenciamento**: Versionamento e stages (dev, staging, prod)

#### 4.1.4 Configuração
```yaml
# API Gateway Configuration
api:
  name: payments-platform-api
  protocol: REST
  stages:
    - dev
    - staging
    - prod
  throttling:
    rate_limit: 10000
    burst_limit: 5000
  authorizer:
    type: COGNITO_USER_POOLS
    pool_arn: arn:aws:cognito:...
  endpoints:
    - path: /api/v1/users/*
      method: ANY
      integration: ALB
      target: user-service-alb
    - path: /api/v1/payments/*
      method: ANY
      integration: ALB
      target: payments-service-alb
```

#### 4.1.5 Exemplo Real
**Cenário**: Pico de Black Friday
- Tráfego normal: 1.000 req/s
- Pico: 50.000 req/s
- API Gateway escala automaticamente
- Rate limiting protege backend: 10.000 req/s
- Respostas cacheadas: 30% das requisições

---

### 4.2 AWS Cognito

#### 4.2.1 Propósito
Gerenciamento de identidade e acesso, fornecendo:
- User authentication (sign-up, sign-in)
- Multi-factor authentication (MFA)
- Social login (Google, Facebook)
- User pools e identity pools
- JWT token generation
- Password policies

#### 4.2.2 Integração na Arquitetura
**Fluxo de Autenticação:**
1. Usuário faz login via app/web
2. Cognito valida credenciais
3. Retorna JWT token (access + refresh)
4. Cliente envia token em cada requisição
5. API Gateway valida token
6. Microserviços recebem claims do usuário

#### 4.2.3 Por que Cognito?
- **Segurança**: Compliance com OWASP, PCI-DSS
- **Escalabilidade**: Milhões de usuários
- **Facilidade**: Integração nativa com API Gateway
- **Custo**: Free tier generoso, pay-per-user
- **Features**: MFA, password recovery, email verification

#### 4.2.4 Configuração
```javascript
// User Pool Configuration
{
  "UserPoolName": "payments-platform-users",
  "Policies": {
    "PasswordPolicy": {
      "MinimumLength": 12,
      "RequireUppercase": true,
      "RequireLowercase": true,
      "RequireNumbers": true,
      "RequireSymbols": true
    }
  },
  "MfaConfiguration": "OPTIONAL",
  "AccountRecoverySetting": {
    "RecoveryMechanisms": [
      {"Name": "verified_email", "Priority": 1},
      {"Name": "verified_phone_number", "Priority": 2}
    ]
  },
  "Schema": [
    {"Name": "email", "Required": true},
    {"Name": "phone_number", "Required": false},
    {"Name": "custom:user_type", "AttributeDataType": "String"}
  ]
}
```

#### 4.2.5 Exemplo Real
**Cenário**: Login de usuário
```javascript
// Client-side (React/React Native)
import { Auth } from 'aws-amplify';

const signIn = async (email, password) => {
  try {
    const user = await Auth.signIn(email, password);
    // JWT token automaticamente armazenado
    // Próximas requisições incluem token automaticamente
    return user;
  } catch (error) {
    if (error.code === 'UserNotConfirmedException') {
      // Usuário não confirmou email
    } else if (error.code === 'PasswordResetRequiredException') {
      // Senha precisa ser resetada
    }
  }
};
```

---

### 4.3 AWS ECS Fargate

#### 4.3.1 Propósito
Orquestração de containers serverless, fornecendo:
- Deploy de microserviços em containers
- Auto-scaling baseado em métricas
- Zero gerenciamento de servidores
- Isolamento de recursos
- Health checks e auto-recovery

#### 4.3.2 Integração na Arquitetura
**Estrutura:**
- **Cluster**: payments-platform-cluster
- **Services**: Um por microserviço (6 services)
- **Tasks**: Containers rodando NestJS apps
- **Task Definitions**: Configuração de CPU, memória, env vars

#### 4.3.3 Por que ECS Fargate?
- **Serverless**: Sem gerenciamento de EC2 instances
- **Custo**: Pay-per-use, sem over-provisioning
- **Escalabilidade**: Auto-scaling rápido (< 1 minuto)
- **Segurança**: Isolamento por task, IAM roles
- **Integração**: Nativo com ALB, CloudWatch, Secrets Manager

#### 4.3.4 Configuração
```json
{
  "family": "payments-service",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "payments-service",
      "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/payments-service:latest",
      "portMappings": [
        {"containerPort": 3000, "protocol": "tcp"}
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "LOG_LEVEL", "value": "info"}
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:..."
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/payments-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

#### 4.3.5 Auto-Scaling
```json
{
  "ServiceName": "payments-service",
  "ScalableTargetAction": {
    "MinCapacity": 2,
    "MaxCapacity": 50
  },
  "ScalingPolicies": [
    {
      "PolicyName": "cpu-scaling",
      "TargetTrackingScalingPolicyConfiguration": {
        "TargetValue": 70.0,
        "PredefinedMetricSpecification": {
          "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
        },
        "ScaleInCooldown": 300,
        "ScaleOutCooldown": 60
      }
    },
    {
      "PolicyName": "request-count-scaling",
      "TargetTrackingScalingPolicyConfiguration": {
        "TargetValue": 1000.0,
        "PredefinedMetricSpecification": {
          "PredefinedMetricType": "ALBRequestCountPerTarget"
        }
      }
    }
  ]
}
```

#### 4.3.6 Exemplo Real
**Cenário**: Deploy de nova versão
1. Build da imagem Docker
2. Push para ECR
3. Atualizar task definition
4. ECS inicia novas tasks (blue)
5. Health checks passam
6. ALB roteia tráfego para novas tasks
7. ECS drena e remove tasks antigas (green)
8. Zero downtime deployment

---

### 4.4 AWS Application Load Balancer (ALB)

#### 4.4.1 Propósito
Distribuição de tráfego e alta disponibilidade, fornecendo:
- Load balancing entre tasks
- Health checks
- Path-based routing
- SSL/TLS termination
- Sticky sessions
- Connection draining

#### 4.4.2 Integração na Arquitetura
**Estrutura:**
- Um ALB por microserviço (ou compartilhado com path routing)
- Target groups apontando para ECS tasks
- Listeners HTTP (80) e HTTPS (443)
- SSL certificate via ACM

#### 4.4.3 Por que ALB?
- **Alta Disponibilidade**: Multi-AZ automático
- **Performance**: Layer 7 routing, WebSocket support
- **Segurança**: SSL/TLS termination, WAF integration
- **Observabilidade**: Access logs, CloudWatch metrics
- **Custo**: Mais barato que NLB para HTTP/HTTPS

#### 4.4.4 Configuração
```yaml
LoadBalancer:
  Name: payments-service-alb
  Scheme: internal
  Type: application
  IpAddressType: ipv4
  Subnets:
    - subnet-private-1a
    - subnet-private-1b
    - subnet-private-1c
  SecurityGroups:
    - sg-alb-payments
  
Listeners:
  - Port: 443
    Protocol: HTTPS
    Certificates:
      - CertificateArn: arn:aws:acm:...
    DefaultActions:
      - Type: forward
        TargetGroupArn: arn:aws:elasticloadbalancing:...
  
TargetGroup:
  Name: payments-service-tg
  Port: 3000
  Protocol: HTTP
  TargetType: ip
  VpcId: vpc-xxx
  HealthCheck:
    Path: /health/ready
    Protocol: HTTP
    Interval: 30
    Timeout: 5
    HealthyThreshold: 2
    UnhealthyThreshold: 3
    Matcher: 200
  Deregistration:
    DelayTimeout: 30
```

#### 4.4.5 Exemplo Real
**Cenário**: Falha de uma task
1. Task do Payments Service falha
2. ALB detecta via health check (3 falhas consecutivas)
3. ALB remove task do target group
4. Tráfego é redistribuído para tasks saudáveis
5. ECS detecta task unhealthy
6. ECS inicia nova task automaticamente
7. Nova task passa health check
8. ALB adiciona nova task ao target group
9. Tempo total: ~2 minutos, zero impacto para usuários

---

### 4.5 AWS S3

#### 4.5.1 Propósito
Armazenamento de objetos escalável, fornecendo:
- Storage de assets estáticos
- Backup de dados
- Data lake para analytics
- Armazenamento de logs
- Hosting de relatórios

#### 4.5.2 Integração na Arquitetura
**Buckets:**
- `payments-platform-assets`: Imagens, documentos
- `payments-platform-backups`: Backups de databases
- `payments-platform-reports`: Extratos, relatórios
- `payments-platform-logs`: Logs de aplicação
- `payments-platform-documents`: Documentos de KYC

#### 4.5.3 Por que S3?
- **Durabilidade**: 99.999999999% (11 noves)
- **Escalabilidade**: Ilimitado
- **Custo**: Storage classes otimizados (Standard, IA, Glacier)
- **Segurança**: Encryption at-rest, bucket policies
- **Performance**: Transfer acceleration, CloudFront integration

#### 4.5.4 Configuração
```json
{
  "Bucket": "payments-platform-documents",
  "Versioning": "Enabled",
  "Encryption": {
    "SSEAlgorithm": "aws:kms",
    "KMSMasterKeyID": "arn:aws:kms:..."
  },
  "LifecycleConfiguration": {
    "Rules": [
      {
        "Id": "archive-old-documents",
        "Status": "Enabled",
        "Transitions": [
          {
            "Days": 90,
            "StorageClass": "STANDARD_IA"
          },
          {
            "Days": 365,
            "StorageClass": "GLACIER"
          }
        ]
      }
    ]
  },
  "PublicAccessBlock": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }
}
```

#### 4.5.5 Exemplo Real
**Cenário**: Upload de documento KYC
```javascript
// NestJS Service
import { S3 } from 'aws-sdk';

@Injectable()
export class DocumentService {
  private s3 = new S3();
  
  async uploadKYCDocument(userId: string, file: Buffer): Promise<string> {
    const key = `kyc/${userId}/${Date.now()}-${file.originalname}`;
    
    await this.s3.putObject({
      Bucket: 'payments-platform-documents',
      Key: key,
      Body: file,
      ContentType: file.mimetype,
      ServerSideEncryption: 'aws:kms',
      Metadata: {
        userId,
        uploadedAt: new Date().toISOString()
      }
    }).promise();
    
    // Gerar URL pré-assinada (válida por 1 hora)
    const url = await this.s3.getSignedUrlPromise('getObject', {
      Bucket: 'payments-platform-documents',
      Key: key,
      Expires: 3600
    });
    
    return url;
  }
}
```

---

### 4.6 AWS WAF & Shield

#### 4.6.1 Propósito
Segunda camada de proteção (após Cloudflare), fornecendo:
- DDoS protection (Shield)
- Web application firewall (WAF)
- Rate-based rules
- Geo-blocking
- IP reputation lists

#### 4.6.2 Integração na Arquitetura
**Associação:**
- WAF associado ao ALB
- Shield Standard (automático)
- Shield Advanced (opcional, para proteção premium)

#### 4.6.3 Por que WAF & Shield?
- **Defesa em Profundidade**: Segunda camada após Cloudflare
- **Proteção AWS-Native**: Otimizado para infraestrutura AWS
- **Custo**: Shield Standard incluído gratuitamente
- **Compliance**: Requisito para PCI-DSS

#### 4.6.4 Configuração
```json
{
  "Name": "payments-platform-waf",
  "Scope": "REGIONAL",
  "DefaultAction": {"Allow": {}},
  "Rules": [
    {
      "Name": "rate-limit-per-ip",
      "Priority": 1,
      "Statement": {
        "RateBasedStatement": {
          "Limit": 2000,
          "AggregateKeyType": "IP"
        }
      },
      "Action": {"Block": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RateLimitRule"
      }
    },
    {
      "Name": "geo-blocking",
      "Priority": 2,
      "Statement": {
        "GeoMatchStatement": {
          "CountryCodes": ["XX", "YY"]
        }
      },
      "Action": {"Block": {}}
    },
    {
      "Name": "aws-managed-rules",
      "Priority": 3,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet"
        }
      },
      "OverrideAction": {"None": {}}
    }
  ]
}
```

---

### 4.7 AWS EventBridge

#### 4.7.1 Propósito
Event bus serverless para arquitetura event-driven, fornecendo:
- Roteamento de eventos entre serviços
- Event filtering e transformation
- Integração com serviços AWS
- Schema registry
- Event replay

#### 4.7.2 Integração na Arquitetura
**Event Bus:**
- `payments-platform-events`: Bus principal
- Producers: Todos os microserviços
- Consumers: Microserviços + Lambda functions

#### 4.7.3 Por que EventBridge?
- **Serverless**: Zero gerenciamento
- **Escalabilidade**: Milhões de eventos/segundo
- **Flexibilidade**: Roteamento baseado em regras
- **Integração**: 90+ serviços AWS nativos
- **Observabilidade**: CloudWatch integration

#### 4.7.4 Configuração
```json
{
  "EventBusName": "payments-platform-events",
  "Rules": [
    {
      "Name": "payment-completed-to-ledger",
      "EventPattern": {
        "source": ["payments.service"],
        "detail-type": ["payment.completed"]
      },
      "Targets": [
        {
          "Arn": "arn:aws:sqs:us-east-1:123456789:ledger-queue",
          "Id": "ledger-service"
        }
      ]
    },
    {
      "Name": "payment-completed-to-notification",
      "EventPattern": {
        "source": ["payments.service"],
        "detail-type": ["payment.completed"]
      },
      "Targets": [
        {
          "Arn": "arn:aws:sqs:us-east-1:123456789:notification-queue",
          "Id": "notification-service"
        }
      ]
    }
  ]
}
```

#### 4.7.5 Exemplo Real
```javascript
// Payments Service - Publishing Event
import { EventBridge } from 'aws-sdk';

@Injectable()
export class PaymentsService {
  private eventBridge = new EventBridge();
  
  async completePayment(paymentId: string) {
    // ... payment logic ...
    
    // Publish event
    await this.eventBridge.putEvents({
      Entries: [
        {
          Source: 'payments.service',
          DetailType: 'payment.completed',
          Detail: JSON.stringify({
            paymentId,
            userId,
            amount,
            timestamp: new Date().toISOString()
          }),
          EventBusName: 'payments-platform-events'
        }
      ]
    }).promise();
  }
}

// Ledger Service - Consuming Event
@Injectable()
export class LedgerService {
  @SqsMessageHandler('ledger-queue')
  async handlePaymentCompleted(message: any) {
    const { paymentId, userId, amount } = JSON.parse(message.body);
    
    // Create ledger entries
    await this.createLedgerEntry({
      paymentId,
      userId,
      amount,
      type: 'DEBIT'
    });
  }
}
```

---

### 4.8 AWS RDS PostgreSQL

#### 4.8.1 Propósito
Banco de dados relacional gerenciado para dados transacionais, fornecendo:
- ACID transactions
- Relational data modeling
- Complex queries e joins
- Automated backups
- Multi-AZ deployment
- Read replicas

#### 4.8.2 Integração na Arquitetura
**Databases:**
- `users_db`: User Service
- `payments_db`: Payments Service
- `ledger_db`: Ledger Service

#### 4.8.3 Por que PostgreSQL?
- **ACID**: Garantias transacionais
- **Performance**: Otimizado para OLTP
- **Features**: JSON support, full-text search, extensions
- **Confiabilidade**: 99.95% SLA (Multi-AZ)
- **Ecosystem**: Amplo suporte de ferramentas

#### 4.8.4 Configuração
```yaml
DBInstance:
  DBInstanceIdentifier: payments-db
  DBInstanceClass: db.r6g.xlarge
  Engine: postgres
  EngineVersion: "15.3"
  AllocatedStorage: 100
  StorageType: gp3
  StorageEncrypted: true
  KmsKeyId: arn:aws:kms:...
  MultiAZ: true
  PubliclyAccessible: false
  VPCSecurityGroups:
    - sg-rds-payments
  DBSubnetGroupName: private-subnets
  BackupRetentionPeriod: 30
  PreferredBackupWindow: "03:00-04:00"
  PreferredMaintenanceWindow: "sun:04:00-sun:05:00"
  EnablePerformanceInsights: true
  PerformanceInsightsRetentionPeriod: 7
  EnableCloudwatchLogsExports:
    - postgresql
  DeletionProtection: true
```

#### 4.8.5 Exemplo Real
```typescript
// TypeORM Configuration
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export const databaseConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  host: process.env.DB_HOST,
  port: 5432,
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: 'payments_db',
  entities: [__dirname + '/../**/*.entity{.ts,.js}'],
  synchronize: false,
  logging: process.env.NODE_ENV === 'development',
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('./rds-ca-2019-root.pem').toString()
  },
  extra: {
    max: 20,
    min: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000
  }
};

// Entity Example
@Entity('payments')
export class Payment {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  
  @Column()
  userId: string;
  
  @Column('decimal', { precision: 10, scale: 2 })
  amount: number;
  
  @Column({ type: 'enum', enum: PaymentStatus })
  status: PaymentStatus;
  
  @CreateDateColumn()
  createdAt: Date;
  
  @UpdateDateColumn()
  updatedAt: Date;
  
  @Index()
  @Column()
  gatewayTransactionId: string;
}
```

---

### 4.9 AWS DocumentDB

#### 4.9.1 Propósito
Banco NoSQL compatível com MongoDB para eventos e analytics, fornecendo:
- Schema-less data storage
- High write throughput
- Real-time analytics
- Event sourcing
- Audit logs

#### 4.9.2 Integração na Arquitetura
**Collections:**
- `gateway_requests`: Raw requests/responses
- `events`: Event store
- `audit_logs`: Audit trail
- `analytics`: Real-time metrics

#### 4.9.3 Por que DocumentDB?
- **Flexibilidade**: Schema-less, ideal para eventos
- **Performance**: Otimizado para writes
- **Escalabilidade**: Horizontal scaling
- **Compatibilidade**: MongoDB API
- **Gerenciamento**: Fully managed

#### 4.9.4 Configuração
```yaml
DBCluster:
  DBClusterIdentifier: payments-events-cluster
  Engine: docdb
  EngineVersion: "5.0"
  MasterUsername: admin
  MasterUserPassword: !Ref DBPassword
  BackupRetentionPeriod: 7
  PreferredBackupWindow: "03:00-04:00"
  PreferredMaintenanceWindow: "sun:04:00-sun:05:00"
  StorageEncrypted: true
  KmsKeyId: arn:aws:kms:...
  VpcSecurityGroupIds:
    - sg-docdb
  DBSubnetGroupName: private-subnets
  EnableCloudwatchLogsExports:
    - audit
    - profiler

DBInstance:
  DBInstanceIdentifier: payments-events-instance-1
  DBInstanceClass: db.r6g.large
  Engine: docdb
  DBClusterIdentifier: !Ref DBCluster
```

#### 4.9.5 Exemplo Real
```typescript
// Mongoose Configuration
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    MongooseModule.forRoot(
      `mongodb://${username}:${password}@${host}:27017/${database}?tls=true&replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false`,
      {
        tlsCAFile: './rds-combined-ca-bundle.pem'
      }
    )
  ]
})
export class AppModule {}

// Schema Example
import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';

@Schema({ collection: 'gateway_requests', timestamps: true })
export class GatewayRequest {
  @Prop({ required: true })
  gatewayName: string;
  
  @Prop({ required: true })
  transactionId: string;
  
  @Prop({ type: Object })
  request: any;
  
  @Prop({ type: Object })
  response: any;
  
  @Prop()
  statusCode: number;
  
  @Prop()
  duration: number;
  
  @Prop({ type: Date, expires: '90d' })
  createdAt: Date;
}

export const GatewayRequestSchema = SchemaFactory.createForClass(GatewayRequest);
```

---

### 4.10 AWS Route53

#### 4.10.1 Propósito
DNS gerenciado para resolução de nomes públicos e internos, fornecendo:
- Public DNS zones
- Private DNS zones (VPC)
- Health checks
- Traffic routing policies
- Domain registration

#### 4.10.2 Integração na Arquitetura
**Zones:**
- `payments-platform.com` (public)
- `internal.payments-platform.local` (private)

**Records:**
- `api.payments-platform.com` → API Gateway
- `payments-service.internal` → ALB interno
- `users-service.internal` → ALB interno

#### 4.10.3 Por que Route53?
- **Confiabilidade**: 100% SLA
- **Performance**: Anycast network
- **Integração**: Nativo com serviços AWS
- **Features**: Health checks, failover, geolocation routing

---

### 4.11 AWS SNS + SQS

#### 4.11.1 Propósito
Messaging para casos específicos que requerem garantias adicionais:
- Dead Letter Queues (DLQ)
- Message ordering (FIFO)
- Delay queues
- Fan-out pattern

#### 4.11.2 Integração na Arquitetura
**Uso:**
- EventBridge para eventos gerais
- SNS+SQS para casos críticos (pagamentos, ledger)

#### 4.11.3 Por que SNS + SQS?
- **Garantias**: At-least-once delivery
- **Durabilidade**: Mensagens persistidas
- **Retry**: Automático com backoff
- **DLQ**: Tratamento de falhas persistentes

#### 4.11.4 Exemplo Real
```yaml
# SQS Queue
Queue:
  QueueName: payments-processing-queue
  FifoQueue: true
  ContentBasedDeduplication: true
  MessageRetentionPeriod: 1209600  # 14 days
  VisibilityTimeout: 300
  ReceiveMessageWaitTimeSeconds: 20  # Long polling
  RedrivePolicy:
    deadLetterTargetArn: arn:aws:sqs:...:payments-dlq
    maxReceiveCount: 3

# SNS Topic
Topic:
  TopicName: payment-events
  FifoTopic: true
  ContentBasedDeduplication: true
  Subscription:
    - Protocol: sqs
      Endpoint: arn:aws:sqs:...:payments-processing-queue
```

---

## 5. Camada de Aplicação (NodeJS/NestJS)

### 5.1 NestJS Framework

#### 5.1.1 Propósito
Framework principal para desenvolvimento de microserviços, fornecendo:
- Arquitetura modular
- Dependency injection
- Decorators e metadata
- Built-in support para TypeScript
- Integração com bibliotecas populares

#### 5.1.2 Por que NestJS?
- **Produtividade**: Estrutura opinativa reduz decisões
- **Escalabilidade**: Arquitetura modular
- **Testabilidade**: DI facilita mocking
- **Ecosystem**: Ampla gama de integrações
- **TypeScript**: Type safety end-to-end

#### 5.1.3 Estrutura de Projeto
```
payments-service/
├── src/
│   ├── main.ts
│   ├── app.module.ts
│   ├── payments/
│   │   ├── payments.module.ts
│   │   ├── payments.controller.ts
│   │   ├── payments.service.ts
│   │   ├── payments.repository.ts
│   │   ├── entities/
│   │   │   └── payment.entity.ts
│   │   ├── dto/
│   │   │   ├── create-payment.dto.ts
│   │   │   └── update-payment.dto.ts
│   │   └── interfaces/
│   │       └── payment.interface.ts
│   ├── common/
│   │   ├── filters/
│   │   ├── interceptors/
│   │   ├── guards/
│   │   └── decorators/
│   └── config/
│       ├── database.config.ts
│       └── app.config.ts
├── test/
├── Dockerfile
└── package.json
```

#### 5.1.4 Exemplo Real
```typescript
// payments.module.ts
@Module({
  imports: [
    TypeOrmModule.forFeature([Payment]),
    HttpModule,
    EventEmitterModule.forRoot()
  ],
  controllers: [PaymentsController],
  providers: [
    PaymentsService,
    PaymentsRepository,
    CircuitBreakerService
  ],
  exports: [PaymentsService]
})
export class PaymentsModule {}

// payments.controller.ts
@Controller('api/v1/payments')
@UseGuards(JwtAuthGuard)
@UseInterceptors(LoggingInterceptor)
export class PaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}
  
  @Post()
  @UsePipes(ValidationPipe)
  async createPayment(
    @Body() createPaymentDto: CreatePaymentDto,
    @CurrentUser() user: User
  ): Promise<Payment> {
    return this.paymentsService.create(createPaymentDto, user.id);
  }
  
  @Get(':id')
  async getPayment(@Param('id') id: string): Promise<Payment> {
    return this.paymentsService.findOne(id);
  }
}

// payments.service.ts
@Injectable()
export class PaymentsService {
  constructor(
    private readonly paymentsRepository: PaymentsRepository,
    private readonly storeService: StoreService,
    private readonly eventEmitter: EventEmitter2,
    private readonly logger: Logger
  ) {}
  
  async create(dto: CreatePaymentDto, userId: string): Promise<Payment> {
    // Idempotency check
    const existing = await this.paymentsRepository.findByIdempotencyKey(
      dto.idempotencyKey
    );
    if (existing) return existing;
    
    // Create payment
    const payment = await this.paymentsRepository.create({
      ...dto,
      userId,
      status: PaymentStatus.PENDING
    });
    
    // Select gateway
    const gateway = await this.storeService.selectGateway(dto);
    
    // Process async
    this.eventEmitter.emit('payment.created', { payment, gateway });
    
    return payment;
  }
}
```

---

### 5.2 OpenTelemetry

#### 5.2.1 Propósito
Observabilidade distribuída com tracing, metrics e logs:
- Distributed tracing
- Metrics collection
- Context propagation
- Vendor-agnostic

#### 5.2.2 Por que OpenTelemetry?
- **Padrão**: CNCF standard
- **Vendor-agnostic**: Funciona com Datadog, Jaeger, etc.
- **Completo**: Traces, metrics, logs
- **Performance**: Low overhead

#### 5.2.3 Configuração
```typescript
// tracing.ts
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { DatadogExporter } from '@opentelemetry/exporter-datadog';

const sdk = new NodeSDK({
  traceExporter: new DatadogExporter({
    serviceName: 'payments-service',
    agentUrl: 'http://datadog-agent:8126'
  }),
  instrumentations: [
    getNodeAutoInstrumentations({
      '@opentelemetry/instrumentation-http': { enabled: true },
      '@opentelemetry/instrumentation-express': { enabled: true },
      '@opentelemetry/instrumentation-pg': { enabled: true }
    })
  ]
});

sdk.start();
```

---

### 5.3 Pino Logger

#### 5.3.1 Propósito
Logging estruturado de alta performance:
- JSON structured logs
- Low overhead
- Child loggers
- Redaction de dados sensíveis

#### 5.3.2 Por que Pino?
- **Performance**: 5x mais rápido que Winston
- **Estruturado**: JSON nativo
- **Features**: Redaction, serializers, pretty print

#### 5.3.3 Configuração
```typescript
// logger.config.ts
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.body.password',
      'req.body.cardNumber',
      'res.body.token'
    ],
    remove: true
  },
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      headers: req.headers,
      remoteAddress: req.remoteAddress
    }),
    res: (res) => ({
      statusCode: res.statusCode
    }),
    err: pino.stdSerializers.err
  },
  formatters: {
    level: (label) => ({ level: label })
  }
});

// Usage
logger.info({ userId: '123', action: 'payment.created' }, 'Payment created successfully');
```

---

### 5.4 TypeORM

#### 5.4.1 Propósito
ORM para abstração de banco de dados:
- Entity mapping
- Query builder
- Migrations
- Transactions
- Multiple database support

#### 5.4.2 Por que TypeORM?
- **TypeScript**: First-class support
- **Features**: Completo e maduro
- **Integração**: Nativo com NestJS
- **Performance**: Lazy loading, caching

---

## 6. Camada de Cache

### 6.1 Redis

#### 6.1.1 Propósito
Cache distribuído e data structures:
- Session storage
- Rate limiting
- Distributed locks
- Pub/Sub
- Caching de queries

#### 6.1.2 Por que Redis?
- **Performance**: Sub-millisecond latency
- **Versatilidade**: Múltiplos data types
- **Escalabilidade**: Cluster mode
- **Confiabilidade**: Persistence options

#### 6.1.3 Configuração
```typescript
// redis.config.ts
import { RedisModule } from '@nestjs-modules/ioredis';

@Module({
  imports: [
    RedisModule.forRoot({
      config: {
        host: process.env.REDIS_HOST,
        port: 6379,
        password: process.env.REDIS_PASSWORD,
        tls: {},
        retryStrategy: (times) => Math.min(times * 50, 2000),
        maxRetriesPerRequest: 3
      }
    })
  ]
})
export class AppModule {}

// Usage - Caching
@Injectable()
export class PaymentsService {
  constructor(private readonly redis: Redis) {}
  
  async getPayment(id: string): Promise<Payment> {
    // Try cache first
    const cached = await this.redis.get(`payment:${id}`);
    if (cached) return JSON.parse(cached);
    
    // Fetch from DB
    const payment = await this.paymentsRepository.findOne(id);
    
    // Cache for 5 minutes
    await this.redis.setex(
      `payment:${id}`,
      300,
      JSON.stringify(payment)
    );
    
    return payment;
  }
}

// Usage - Rate Limiting
async checkRateLimit(userId: string): Promise<boolean> {
  const key = `rate_limit:${userId}`;
  const current = await this.redis.incr(key);
  
  if (current === 1) {
    await this.redis.expire(key, 60); // 1 minute window
  }
  
  return current <= 100; // 100 requests per minute
}
```

---

## 7. Exemplo de Fluxo Completo

### 7.1 Cenário: Criação de Pagamento

**Fluxo End-to-End:**

1. **Cliente** faz POST para `https://api.payments-platform.com/api/v1/payments`

2. **Cloudflare**:
   - Valida se não é bot
   - Aplica rate limiting
   - Encaminha para AWS

3. **API Gateway**:
   - Valida JWT token (Cognito)
   - Aplica throttling
   - Roteia para ALB

4. **ALB**:
   - Termina SSL
   - Distribui para ECS task saudável
   - Encaminha para Payments Service

5. **Payments Service**:
   - Valida request (ValidationPipe)
   - Verifica idempotência (Redis)
   - Cria registro no PostgreSQL
   - Publica evento `payment.created` (EventBridge)

6. **Store Service** (via evento):
   - Seleciona gateway (Getnet)
   - Retorna configuração

7. **Getnet Service**:
   - Transforma request para formato Getnet
   - Envia para API Getnet (com circuit breaker)
   - Armazena raw request/response (DocumentDB)
   - Publica evento `payment.authorized`

8. **Payments Service** (via evento):
   - Atualiza status para COMPLETED
   - Publica evento `payment.completed`

9. **Ledger Service** (via evento):
   - Cria lançamentos contábeis (double-entry)
   - Atualiza saldos
   - Publica evento `ledger.updated`

10. **Notification Service** (via evento):
    - Envia email de confirmação (SES)
    - Envia push notification (SNS)

11. **OpenTelemetry**:
    - Coleta traces de todos os serviços
    - Envia para Datadog
    - Permite visualização end-to-end

**Tempo Total**: ~500ms (P95)
**Serviços Envolvidos**: 6
**Eventos Publicados**: 4
**Databases Acessados**: 3 (PostgreSQL, DocumentDB, Redis)

---

## 8. Considerações de Custo

### 8.1 Estimativa Mensal (10.000 usuários ativos)

**Compute:**
- ECS Fargate: $500 (6 services, 2 tasks each)
- Lambda: $50 (event processing)

**Storage:**
- RDS PostgreSQL: $300 (db.r6g.xlarge Multi-AZ)
- DocumentDB: $200 (db.r6g.large)
- Redis: $100 (cache.r6g.large)
- S3: $50 (1TB storage)

**Networking:**
- ALB: $100
- API Gateway: $150 (10M requests)
- Data Transfer: $200

**Messaging:**
- EventBridge: $20 (1M events)
- SNS/SQS: $10

**Observability:**
- CloudWatch: $100
- Datadog: $300 (APM + Logs)

**Security:**
- WAF: $50
- Secrets Manager: $10

**Total AWS**: ~$2.140/mês
**Total com Cloudflare**: ~$2.340/mês (plan Pro)

---

## 9. Referências

- Documento de Cenários: `0-scenarios.md`
- Documento de Mapeamento de Serviços: `1-service-map.md`
- Documento de Estratégia de Integração: `3-integration-stratefy.md`
- Documento de Segurança: `4-security.md`
- Documento de Observabilidade: `5-observability.md`

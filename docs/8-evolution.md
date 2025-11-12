# Documentação: Plano de Evolução da Plataforma de Pagamentos

## 1. Visão Geral

Este documento apresenta o roadmap de evolução tecnológica da plataforma de pagamentos, detalhando as migrações, melhorias e novas capacidades planejadas para os próximos 12-24 meses. O foco está em aumentar escalabilidade, performance, observabilidade e capacidades de negócio.

## 2. Contexto e Motivação

### 2.1 Estado Atual (Fase 1)
```yaml
Current_Architecture:
  Compute: AWS ECS Fargate
  Messaging: AWS EventBridge + SNS/SQS
  Observability: Datadog + CloudWatch
  Databases: RDS PostgreSQL + DocumentDB + Redis
  
Limitations:
  - ECS Fargate: Menos flexibilidade que Kubernetes
  - EventBridge: Limitações para event streaming em tempo real
  - Sem service mesh: Dificulta observabilidade e controle de tráfego
  - Não PCI-compliant: Dependência de gateways externos
  - Analytics limitado: Sem plataforma de big data
```

### 2.2 Estado Futuro (Fase 2)
```yaml
Future_Architecture:
  Compute: AWS EKS (Kubernetes)
  Service_Mesh: Istio
  Messaging: Apache Kafka
  Observability: Datadog + Istio + OpenTelemetry
  Databases: RDS PostgreSQL + DocumentDB + Redis
  PCI_Infrastructure: Dedicated VPC + HSM
  Analytics: Databricks
  
Benefits:
  - Maior flexibilidade e portabilidade
  - Event streaming em tempo real
  - Observabilidade avançada
  - Tokenização própria (PSP)
  - Analytics e ML avançados
```

## 3. Roadmap de Evolução

### 3.1 Timeline
```
Q1 2024: Preparação e Planejamento
├─ Treinamento da equipe em Kubernetes
├─ POC de Kafka
├─ Design da arquitetura PCI
└─ Avaliação de Databricks

Q2 2024: Migração para EKS
├─ Setup do cluster EKS
├─ Migração de 2 serviços (User + Notification)
├─ Testes de carga
└─ Documentação

Q3 2024: Implementação de Istio e Kafka
├─ Deploy de Istio service mesh
├─ Setup de Kafka cluster
├─ Migração de eventos críticos para Kafka
└─ Migração dos demais serviços para EKS

Q4 2024: Infraestrutura PCI e Databricks
├─ Setup de infraestrutura PCI
├─ Implementação de tokenização
├─ Setup de Databricks
└─ Pipelines de analytics

Q1 2025: Certificação PSP
├─ Auditoria PCI-DSS
├─ Certificação como PSP
└─ Launch de tokenização própria
```

---

## 4. Migração: ECS Fargate → EKS

### 4.1 Motivação

#### 4.1.1 Limitações do ECS Fargate
- Vendor lock-in (AWS-specific)
- Menos flexibilidade em networking
- Limitações em scheduling avançado
- Sem suporte nativo para service mesh
- Ferramentas de debugging limitadas

#### 4.1.2 Benefícios do EKS
- Portabilidade (Kubernetes é padrão)
- Ecossistema rico (Helm, Operators, etc)
- Service mesh nativo (Istio)
- Melhor controle de recursos
- Comunidade ativa

### 4.2 Arquitetura EKS

#### 4.2.1 Cluster Configuration
```yaml
EKS_Cluster:
  Name: payments-platform-eks
  Version: 1.28
  Region: us-east-1
  
  NodeGroups:
    - Name: general-purpose
      InstanceTypes:
        - m6i.xlarge
        - m6i.2xlarge
      MinSize: 3
      MaxSize: 20
      DesiredSize: 6
      Labels:
        workload: general
    
    - Name: compute-intensive
      InstanceTypes:
        - c6i.2xlarge
        - c6i.4xlarge
      MinSize: 2
      MaxSize: 10
      DesiredSize: 3
      Labels:
        workload: compute-intensive
      Taints:
        - key: workload
          value: compute-intensive
          effect: NoSchedule
  
  Addons:
    - vpc-cni
    - coredns
    - kube-proxy
    - aws-ebs-csi-driver
    - aws-load-balancer-controller
```

### 4.3 Estratégia de Migração

#### 4.3.1 Fase 1: Preparação
- Setup EKS cluster
- Configure networking
- Setup IAM roles
- Install cluster addons
- Configure monitoring

#### 4.3.2 Fase 2: Migração Piloto
- Deploy user-service e notification-service
- Run smoke tests
- Route 10% traffic to EKS
- Monitor for 24 hours
- Gradually increase to 100%

#### 4.3.3 Fase 3: Migração Completa
- Wave 1: user-service, notification-service
- Wave 2: ledger-service, store-service
- Wave 3: payments-service, getnet-service

---

## 5. Implementação: Istio Service Mesh

### 5.1 Motivação

#### 5.1.1 Benefícios do Istio
- Observabilidade automática
- Traffic management declarativo
- Resiliência padronizada
- mTLS automático
- Canary deploys simplificados

### 5.2 Componentes Istio
```yaml
Istio_Components:
  Control_Plane:
    - istiod
  
  Data_Plane:
    - Envoy sidecar proxies
  
  Addons:
    - Kiali
    - Jaeger
    - Prometheus
    - Grafana
```

### 5.3 Traffic Management
```yaml
VirtualService:
  - Routing rules
  - Canary deployments
  - A/B testing
  - Traffic splitting

DestinationRule:
  - Load balancing
  - Circuit breaker
  - Connection pooling
  - Outlier detection
```

---

## 6. Migração: EventBridge/SNS/SQS → Kafka

### 6.1 Motivação

#### 6.1.1 Limitações Atuais
- EventBridge não é event streaming
- Latência ~100ms
- Sem replay de eventos
- Sem ordering garantido

#### 6.1.2 Benefícios do Kafka
- Event streaming em tempo real
- Latência < 10ms
- Replay de eventos
- Ordering garantido
- Throughput ilimitado

### 6.2 Arquitetura Kafka

#### 6.2.1 Cluster Configuration
```yaml
Kafka_Cluster:
  Provider: Amazon MSK
  Version: 3.5
  Brokers: 6
  InstanceType: kafka.m5.xlarge
  Storage: 1TB per broker
  
  Configuration:
    auto.create.topics.enable: false
    default.replication.factor: 3
    min.insync.replicas: 2
    log.retention.hours: 168
```

#### 6.2.2 Topic Strategy
```yaml
Topics:
  - Name: payments.events
    Partitions: 12
    ReplicationFactor: 3
    Events:
      - payment.created
      - payment.authorized
      - payment.captured
      - payment.failed
  
  - Name: ledger.events
    Partitions: 12
    ReplicationFactor: 3
    RetentionHours: 720
```

### 6.3 Estratégia de Migração

#### 6.3.1 Dual Write Pattern
Durante transição, escrever em EventBridge e Kafka simultaneamente

#### 6.3.2 Consumer Migration
Migrar consumers gradualmente de EventBridge para Kafka

#### 6.3.3 Cutover
Após validação, desativar EventBridge

---

## 7. Infraestrutura PCI para Tokenização

### 7.1 Motivação

#### 7.1.1 Objetivo
Tornar-se PSP (Payment Service Provider) com capacidade de tokenização própria

#### 7.1.2 Benefícios
- Redução de custos com gateways
- Maior controle sobre transações
- Novas fontes de receita
- Diferencial competitivo

### 7.2 Arquitetura PCI

#### 7.2.1 Network Segmentation
```yaml
PCI_VPC:
  CIDR: 10.1.0.0/16
  Isolation: Complete isolation from main VPC
  
  Subnets:
    - PCI_Private_1a: 10.1.1.0/24
    - PCI_Private_1b: 10.1.2.0/24
    - PCI_Private_1c: 10.1.3.0/24
  
  SecurityGroups:
    - Strict ingress/egress rules
    - Whitelist only
    - No internet access
  
  VPC_Peering:
    - One-way connection to main VPC
    - Restricted to tokenization API only
```

#### 7.2.2 HSM (Hardware Security Module)
```yaml
AWS_CloudHSM:
  Cluster: payments-hsm-cluster
  HSMs: 3 (Multi-AZ)
  Purpose:
    - Key generation
    - Encryption/Decryption
    - Digital signatures
  
  Keys:
    - Master encryption key
    - Token encryption keys
    - Signing keys
```

#### 7.2.3 Tokenization Service
```yaml
Tokenization_Service:
  Purpose: Convert PAN to tokens
  
  Operations:
    - tokenize: PAN → Token
    - detokenize: Token → PAN (restricted)
    - validate: Validate token
  
  Storage:
    - Vault: Encrypted card data
    - Token mapping: Token → Encrypted PAN
    - Audit log: All operations
  
  Security:
    - HSM encryption
    - Access control (IAM + mTLS)
    - Audit logging
    - No data export
```

### 7.3 Compliance PCI-DSS

#### 7.3.1 Requisitos
```yaml
PCI_DSS_Requirements:
  Network:
    - Segmentation
    - Firewall rules
    - No direct internet access
  
  Access:
    - MFA for all access
    - Role-based access control
    - Audit logging
  
  Encryption:
    - TLS 1.3 in transit
    - AES-256 at rest
    - HSM for keys
  
  Monitoring:
    - Real-time alerts
    - Intrusion detection
    - Log aggregation
  
  Testing:
    - Quarterly vulnerability scans
    - Annual penetration testing
    - Code security reviews
```

#### 7.3.2 Auditoria
- QSA (Qualified Security Assessor)
- ROC (Report on Compliance)
- AOC (Attestation of Compliance)
- Certificação anual

---

## 8. Databricks para Analytics

### 8.1 Motivação

#### 8.1.1 Necessidades
- Analytics em tempo real
- Machine Learning
- Data science
- Business intelligence

#### 8.1.2 Benefícios do Databricks
- Unified analytics platform
- Spark otimizado
- Delta Lake
- MLflow integrado
- Colaboração de equipe

### 8.2 Arquitetura Databricks

#### 8.2.1 Data Pipeline
```
┌─────────────────┐
│  Operational    │
│  Databases      │
│  (RDS, DocDB)   │
└────────┬────────┘
         │ CDC (Change Data Capture)
         ↓
┌─────────────────┐
│  Kafka          │
│  (Streaming)    │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  S3 Data Lake   │
│  (Raw Layer)    │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  Databricks     │
│  (Processing)   │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  Delta Lake     │
│  (Curated)      │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  BI Tools       │
│  (Dashboards)   │
└─────────────────┘
```

#### 8.2.2 Use Cases
```yaml
Analytics_Use_Cases:
  Real_Time:
    - Fraud detection
    - Payment anomaly detection
    - User behavior analysis
    - Gateway performance monitoring
  
  Batch:
    - Daily reconciliation
    - Monthly reports
    - Churn prediction
    - Revenue forecasting
  
  Machine_Learning:
    - Fraud scoring model
    - Credit risk assessment
    - Customer segmentation
    - Recommendation engine
```

#### 8.2.3 Delta Lake Tables
```yaml
Delta_Tables:
  Bronze_Layer:
    - raw_payments
    - raw_users
    - raw_transactions
    Purpose: Raw data ingestion
  
  Silver_Layer:
    - cleaned_payments
    - enriched_users
    - validated_transactions
    Purpose: Cleaned and validated data
  
  Gold_Layer:
    - payment_metrics
    - user_analytics
    - financial_reports
    Purpose: Business-ready aggregations
```

### 8.3 Implementação

#### 8.3.1 Streaming Job (Fraud Detection)
```python
from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from delta.tables import *

spark = SparkSession.builder \
    .appName("FraudDetection") \
    .getOrCreate()

payments_stream = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka-brokers") \
    .option("subscribe", "payments.events") \
    .load()

parsed_payments = payments_stream \
    .select(from_json(col("value").cast("string"), payment_schema).alias("data")) \
    .select("data.*")

fraud_scores = parsed_payments \
    .withColumn("fraud_score", fraud_detection_udf(col("amount"), col("userId"))) \
    .filter(col("fraud_score") > 0.8)

fraud_scores.writeStream \
    .format("delta") \
    .outputMode("append") \
    .option("checkpointLocation", "/delta/checkpoints/fraud") \
    .start("/delta/tables/fraud_alerts")
```

#### 8.3.2 Batch Job (Daily Reconciliation)
```python
from delta.tables import DeltaTable

payments_df = spark.read.format("delta").load("/delta/tables/silver/payments")
ledger_df = spark.read.format("delta").load("/delta/tables/silver/ledger")

reconciliation = payments_df.alias("p") \
    .join(ledger_df.alias("l"), col("p.id") == col("l.payment_id"), "full_outer") \
    .select(
        coalesce(col("p.id"), col("l.payment_id")).alias("payment_id"),
        col("p.amount").alias("payment_amount"),
        col("l.amount").alias("ledger_amount"),
        (col("p.amount") - col("l.amount")).alias("difference")
    ) \
    .filter(col("difference") != 0)

reconciliation.write \
    .format("delta") \
    .mode("overwrite") \
    .save("/delta/tables/gold/daily_reconciliation")
```

---

## 9. Custos Estimados

### 9.1 Comparação de Custos

#### 9.1.1 Fase 1 (Atual)
```yaml
Monthly_Costs:
  ECS_Fargate: $500
  RDS: $300
  DocumentDB: $200
  Redis: $100
  EventBridge: $20
  S3: $50
  Networking: $200
  Datadog: $300
  
  Total: $1,670/month
```

#### 9.1.2 Fase 2 (Futuro)
```yaml
Monthly_Costs:
  EKS: $600 (nodes + control plane)
  RDS: $300
  DocumentDB: $200
  Redis: $100
  Kafka_MSK: $800
  S3: $100
  Networking: $300
  Datadog: $500
  Istio: $0 (open source)
  CloudHSM: $1,500
  Databricks: $2,000
  
  Total: $6,400/month
  
Increase: $4,730/month (+283%)

ROI:
  - Tokenization revenue: $10,000/month
  - Reduced gateway fees: $3,000/month
  - Net benefit: $8,270/month
```

---

## 10. Riscos e Mitigações

### 10.1 Riscos Técnicos
```yaml
Risks:
  - Risk: Complexidade aumentada
    Impact: High
    Mitigation:
      - Treinamento extensivo
      - Documentação detalhada
      - Suporte de consultoria
  
  - Risk: Downtime durante migração
    Impact: Critical
    Mitigation:
      - Blue-green deployments
      - Rollback plans
      - Testes extensivos
  
  - Risk: Performance degradation
    Impact: High
    Mitigation:
      - Load testing
      - Gradual rollout
      - Monitoring intensivo
```

### 10.2 Riscos de Negócio
```yaml
Risks:
  - Risk: Aumento de custos
    Impact: Medium
    Mitigation:
      - ROI analysis
      - Phased approach
      - Cost optimization
  
  - Risk: Falha na certificação PCI
    Impact: Critical
    Mitigation:
      - QSA desde início
      - Gap analysis
      - Remediação proativa
```

---

## 11. Métricas de Sucesso

### 11.1 KPIs Técnicos
```yaml
Success_Metrics:
  Performance:
    - Latency P95 < 200ms (vs 500ms atual)
    - Throughput > 50k TPS (vs 10k atual)
    - Availability > 99.99% (vs 99.9% atual)
  
  Reliability:
    - MTTR < 15 min (vs 30 min atual)
    - Error rate < 0.01% (vs 0.1% atual)
    - Zero data loss
  
  Observability:
    - 100% distributed tracing
    - Real-time alerting
    - Automated remediation
```

### 11.2 KPIs de Negócio
```yaml
Business_Metrics:
  Revenue:
    - Tokenization revenue: $10k/month
    - Reduced gateway fees: $3k/month
  
  Efficiency:
    - Deploy frequency: 10x/day (vs 1x/day)
    - Lead time: < 1 hour (vs 1 day)
    - Change failure rate: < 5% (vs 15%)
  
  Customer:
    - NPS > 70
    - Churn rate < 2%
    - Support tickets -50%
```

---

## 12. Próximos Passos

### 12.1 Q1 2024
- [ ] Aprovar budget
- [ ] Contratar consultoria Kubernetes
- [ ] Iniciar treinamento da equipe
- [ ] POC de Kafka
- [ ] Design detalhado PCI

### 12.2 Q2 2024
- [ ] Setup EKS cluster
- [ ] Migrar 2 serviços piloto
- [ ] Validar performance
- [ ] Documentar learnings

### 12.3 Q3 2024
- [ ] Deploy Istio
- [ ] Setup Kafka
- [ ] Migrar todos serviços
- [ ] Validar observabilidade

### 12.4 Q4 2024
- [ ] Setup infraestrutura PCI
- [ ] Implementar tokenização
- [ ] Setup Databricks
- [ ] Iniciar auditoria PCI

---

## 13. Referências

- Documento de Cenários: `0-scenarios.md`
- Documento de Mapeamento de Serviços: `1-service-map.md`
- Documento de Stack Tecnológica: `2-tech-stack.md`
- Documento de Estratégia de Integração: `3-integration-stratefy.md`
- Documento de Segurança: `4-security.md`
- Documento de Observabilidade: `5-observability.md`

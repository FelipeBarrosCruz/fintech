# Architecture Decision Records (ADRs)

## ADR-001: Escolha de Microservices Architecture

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de construir uma plataforma escalável e de alta disponibilidade

**Decisão**: Adotar arquitetura de microservices baseada em Domain-Driven Design

**Justificativa**:
- ✅ Escalabilidade independente por serviço
- ✅ Deploy independente reduz risco
- ✅ Times podem ter ownership de serviços específicos
- ✅ Isolamento de falhas
- ✅ Flexibilidade tecnológica

**Consequências**:
- ➕ Maior complexidade operacional
- ➕ Necessidade de orquestração (ECS/EKS)
- ➕ Comunicação via rede (latência)
- ➖ Consistência eventual
- ➖ Debugging distribuído mais complexo

**Alternativas Consideradas**:
- Monolito modular: Mais simples, mas limita escalabilidade
- Serverless puro: Vendor lock-in e cold start

---

## ADR-002: Node.js com NestJS como Framework Principal

**Status**: Aceito  
**Data**: 2025
**Contexto**: Escolha de linguagem e framework para desenvolvimento

**Decisão**: Utilizar Node.js com NestJS

**Justificativa**:
- ✅ **TypeScript**: Type safety e melhor DX
- ✅ **NestJS**: Arquitetura modular e opinativa
- ✅ **Decorators**: Código limpo e declarativo
- ✅ **Dependency Injection**: Testabilidade
- ✅ **Ecossistema**: Vasta biblioteca de módulos
- ✅ **Performance**: Event loop não-bloqueante
- ✅ **Comunidade**: Grande e ativa
- ✅ **Integração**: Excelente suporte a AWS SDK, Datadog, etc.

**Consequências**:
- ➕ Curva de aprendizado moderada
- ➕ Necessidade de gerenciar async/await corretamente
- ➖ Single-threaded (mitigado com clustering)

**Alternativas Consideradas**:
- Java/Spring Boot: Mais verboso, maior consumo de memória
- Go: Performance superior, mas ecossistema menor
- Python/FastAPI: Mais lento para I/O intensivo

---

## ADR-003: AWS como Cloud Provider

**Status**: Aceito  
**Data**: 2025
**Contexto**: Escolha de provedor de cloud

**Decisão**: Utilizar AWS como cloud provider principal

**Justificativa**:
- ✅ **Maturidade**: Serviços maduros e confiáveis
- ✅ **Compliance**: Certificações PCI-DSS, SOC 2, ISO 27001
- ✅ **Serviços Gerenciados**: RDS, ElastiCache, EventBridge, etc.
- ✅ **Região Brasil**: us-east-1 com baixa latência
- ✅ **Ecossistema**: Integração com Datadog, Stone, Getnet
- ✅ **Documentação**: Extensa e de qualidade
- ✅ **Suporte**: Enterprise support disponível

**Consequências**:
- ➕ Vendor lock-in (mitigado com abstrações)
- ➕ Custo pode crescer rapidamente
- ➖ Complexidade de gerenciamento

**Alternativas Consideradas**:
- GCP: Menos serviços financeiros específicos
- Azure: Menor presença no Brasil
- Multi-cloud: Complexidade operacional muito alta

---

## ADR-004: ECS Fargate para Orquestração de Containers

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de orquestrar containers Docker

**Decisão**: Utilizar Amazon ECS com Fargate

**Justificativa**:
- ✅ **Serverless**: Sem gerenciamento de EC2
- ✅ **Simplicidade**: Mais simples que EKS
- ✅ **Integração AWS**: Nativa com ALB, CloudWatch, IAM
- ✅ **Custo**: Pay-per-use, sem overhead de nodes
- ✅ **Escalabilidade**: Auto-scaling automático
- ✅ **Segurança**: Isolamento por task

**Consequências**:
- ➕ Menos controle sobre infraestrutura
- ➕ Cold start (mitigado com min tasks)
- ➖ Vendor lock-in

**Alternativas Consideradas**:
- EKS (Kubernetes): Mais complexo, overkill para o caso
- EC2 + Docker: Gerenciamento manual de infra
- Lambda: Limitações de timeout e payload

---

## ADR-005: Event-Driven Architecture com EventBridge

**Status**: Aceito  
**Data**: 2025
**Contexto**: Comunicação entre microservices

**Decisão**: Adotar Event-Driven Architecture usando Amazon EventBridge

**Justificativa**:
- ✅ **Desacoplamento**: Serviços independentes
- ✅ **Escalabilidade**: Processamento assíncrono
- ✅ **Auditabilidade**: Event sourcing
- ✅ **Flexibilidade**: Novos consumers sem alterar producers
- ✅ **EventBridge**: Schema registry, filtering, routing
- ✅ **Integração**: SQS, SNS, Lambda

**Consequências**:
- ➕ Consistência eventual
- ➕ Complexidade de debugging
- ➕ Necessidade de idempotência
- ➖ Ordenação de eventos complexa

**Alternativas Consideradas**:
- REST síncrono: Acoplamento forte
- Kafka: Overhead operacional
- RabbitMQ: Gerenciamento manual

---

## ADR-006: PostgreSQL RDS como Database Principal

**Status**: Aceito  
**Data**: 2025
**Contexto**: Escolha de banco de dados para transações

**Decisão**: Utilizar Amazon RDS PostgreSQL

**Justificativa**:
- ✅ **ACID**: Garantias transacionais
- ✅ **Maturidade**: Banco robusto e confiável
- ✅ **JSON Support**: Flexibilidade quando necessário
- ✅ **RDS**: Backups automáticos, Multi-AZ, Read Replicas
- ✅ **Performance**: Excelente para workloads transacionais
- ✅ **Extensões**: PostGIS, pg_cron, etc.
- ✅ **TypeORM**: Excelente integração com NestJS

**Consequências**:
- ➕ Custo de licenciamento zero (open source)
- ➕ Escalabilidade vertical limitada
- ➖ Sharding manual se necessário

**Alternativas Consideradas**:
- MySQL: Menos features avançadas
- Aurora PostgreSQL: Mais caro, overkill para início
- MongoDB: Sem garantias ACID

---

## ADR-007: DocumentDB como Event Store

**Status**: Aceito  
**Data**: 2025
**Contexto**: Armazenamento de eventos para event sourcing

**Decisão**: Utilizar Amazon DocumentDB como Event Store

**Justificativa**:
- ✅ **Performance**: Latência single-digit millisecond
- ✅ **Escalabilidade**: Ilimitada (on-demand)
- ✅ **Append-only**: Perfeito para event sourcing
- ✅ **Streams**: DocumentDB Streams para propagação
- ✅ **Serverless**: Sem gerenciamento
- ✅ **Custo**: Pay-per-request

**Consequências**:
- ➕ Query Syntax diferente de SQL vs banco de dados transacional (Postgres)

**Alternativas Consideradas**:
- EventStoreDB: Gerenciamento manual
- PostgreSQL: Menos performático para append-only
- Kafka: Overhead operacional

---

## ADR-008: CQRS para Separação de Leitura e Escrita

**Status**: Aceito  
**Data**: 2025
**Contexto**: Otimização de performance para queries complexas

**Decisão**: Implementar CQRS (Command Query Responsibility Segregation)

**Justificativa**:
- ✅ **Performance**: Otimização independente
- ✅ **Escalabilidade**: Escalar leitura e escrita separadamente
- ✅ **Modelos específicos**: Read models otimizados
- ✅ **Complexidade gerenciável**: Apenas para Reporting

**Consequências**:
- ➕ Consistência eventual
- ➕ Sincronização de read models
- ➖ Complexidade adicional

**Alternativas Consideradas**:
- CRUD tradicional: Mais simples, menos performático
- Materialized Views: Menos flexível

---

## ADR-009: ElastiCache Redis para Caching

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de cache distribuído

**Decisão**: Utilizar Amazon ElastiCache Redis

**Justificativa**:
- ✅ **Performance**: In-memory, sub-millisecond
- ✅ **Estruturas de dados**: Strings, hashes, sets, sorted sets
- ✅ **Pub/Sub**: Para invalidação de cache
- ✅ **Cluster Mode**: Sharding automático
- ✅ **Persistência**: RDB + AOF
- ✅ **ElastiCache**: Multi-AZ, backups automáticos

**Consequências**:
- ➕ Custo adicional
- ➕ Necessidade de estratégia de invalidação
- ➖ Complexidade de cache distribuído

**Alternativas Consideradas**:
- Memcached: Menos features
- In-memory local: Não distribuído

---

## ADR-010: Datadog para Observabilidade

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de monitoramento e observabilidade

**Decisão**: Utilizar Datadog como plataforma de observabilidade

**Justificativa**:
- ✅ **APM**: Distributed tracing automático
- ✅ **Logs**: Centralização e análise
- ✅ **Metrics**: Custom metrics e dashboards
- ✅ **Alertas**: Configuração flexível
- ✅ **Integração**: AWS, NestJS, PostgreSQL, Redis
- ✅ **UX**: Interface intuitiva
- ✅ **Correlação**: Logs + Traces + Metrics

**Consequências**:
- ➕ Custo por host/container
- ➕ Vendor lock-in (mitigado com OpenTelemetry)
- ➖ Curva de aprendizado

**Alternativas Consideradas**:
- CloudWatch: Menos features, mais barato
- New Relic: Similar, mais caro
- Grafana + Prometheus: Gerenciamento manual

---

## ADR-011: Stone e Getnet como Adquirentes

**Status**: Aceito  
**Data**: 2025
**Contexto**: Integração com gateways de pagamento

**Decisão**: Integrar com Stone e Getnet como adquirentes principais

**Justificativa**:
- ✅ **Stone**: 
  - Taxas competitivas
  - API moderna e bem documentada
  - Suporte a PIX
  - Presença forte no Brasil
- ✅ **Getnet**: 
  - Split de pagamentos
  - Marketplace features
  - Antifraude integrado
  - Flexibilidade de checkout
- ✅ **Redundância**: Fallback entre gateways
- ✅ **Negociação**: Poder de barganha com múltiplos

**Consequências**:
- ➕ Complexidade de integração múltipla
- ➕ Necessidade de adapter pattern
- ➕ Reconciliação mais complexa
- ➖ Manutenção de múltiplas integrações

**Alternativas Consideradas**:
- Apenas Stone: Risco de single point of failure
- Stripe: Taxas mais altas no Brasil
- Mercado Pago: Menos flexível para B2B

---

## ADR-012: Saga Pattern para Transações Distribuídas

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de transações que envolvem múltiplos serviços

**Decisão**: Implementar Saga Pattern com orquestração

**Justificativa**:
- ✅ **Consistência**: Garantia de compensação
- ✅ **Visibilidade**: Fluxo centralizado
- ✅ **Debugging**: Mais fácil rastrear
- ✅ **Controle**: Lógica de negócio centralizada

**Consequências**:
- ➕ Orquestrador pode ser SPOF (mitigado com HA)
- ➕ Complexidade de compensação
- ➖ Acoplamento temporal

**Alternativas Consideradas**:
- Saga Coreografada: Mais complexa de debugar
- 2PC (Two-Phase Commit): Não funciona em microservices

---

## ADR-013: API Gateway para Ponto Único de Entrada

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de gerenciar acesso aos microservices

**Decisão**: Utilizar Amazon API Gateway

**Justificativa**:
- ✅ **Roteamento**: Centralizado
- ✅ **Autenticação**: Integração com Cognito
- ✅ **Rate Limiting**: Por API key ou IP
- ✅ **Transformação**: Request/Response
- ✅ **Caching**: Edge caching
- ✅ **Monitoramento**: CloudWatch integrado
- ✅ **WebSocket**: Suporte nativo

**Consequências**:
- ➕ Latência adicional (~10ms)
- ➕ Custo por requisição
- ➖ Vendor lock-in

**Alternativas Consideradas**:
- Kong: Gerenciamento manual
- Nginx: Menos features
- Traefik: Complexidade adicional

---

## ADR-014: AWS Secrets Manager para Gerenciamento de Secrets

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de armazenar credenciais de forma segura

**Decisão**: Utilizar AWS Secrets Manager

**Justificativa**:
- ✅ **Segurança**: Encryption at rest (KMS)
- ✅ **Rotation**: Automática
- ✅ **Auditoria**: CloudTrail
- ✅ **Integração**: RDS, ECS, Lambda
- ✅ **Versionamento**: Histórico de secrets
- ✅ **IAM**: Controle de acesso granular

**Consequências**:
- ➕ Custo por secret
- ➕ Latência de fetch (mitigado com cache)
- ➖ Vendor lock-in

**Alternativas Consideradas**:
- Parameter Store: Menos features
- HashiCorp Vault: Gerenciamento manual
- Environment Variables: Inseguro

---

## ADR-015: Multi-Tenancy com Isolamento Lógico

**Status**: Aceito  
**Data**: 2025
**Contexto**: Suporte a múltiplos clientes (tenants)

**Decisão**: Implementar multi-tenancy com isolamento lógico (shared database, separate schemas)

**Justificativa**:
- ✅ **Custo**: Mais eficiente que database per tenant
- ✅ **Manutenção**: Mais simples que múltiplos databases
- ✅ **Escalabilidade**: Sharding por tenant quando necessário
- ✅ **Isolamento**: Schema separation garante segurança
- ✅ **Flexibilidade**: Upgrade para database per tenant se necessário

**Consequências**:
- ➕ Necessidade de tenant context em todas as queries
- ➕ Risco de data leakage (mitigado com RLS)
- ➖ Noisy neighbor problem

**Alternativas Consideradas**:
- Database per tenant: Custo e complexidade altos
- Shared database, shared schema: Menos seguro

---

## ADR-016: Infrastructure as Code com Terraform

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de gerenciar infraestrutura de forma reproduzível

**Decisão**: Utilizar Terraform para IaC

**Justificativa**:
- ✅ **Declarativo**: Infraestrutura como código
- ✅ **Versionamento**: Git
- ✅ **Multi-cloud**: Não vendor lock-in
- ✅ **State Management**: Remote state (S3)
- ✅ **Módulos**: Reutilização
- ✅ **Community**: Vasta biblioteca de providers

**Consequências**:
- ➕ Curva de aprendizado
- ➕ State management complexo
- ➖ Drift detection manual

**Alternativas Consideradas**:
- CloudFormation: Vendor lock-in AWS
- CDK: Mais verboso
- Pulumi: Menos maduro

---

## ADR-017: GitHub Actions para CI/CD

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de pipeline de CI/CD

**Decisão**: Utilizar GitHub Actions

**Justificativa**:
- ✅ **Integração**: Nativa com GitHub
- ✅ **Simplicidade**: YAML declarativo
- ✅ **Marketplace**: Vasta biblioteca de actions
- ✅ **Custo**: Free para repositórios públicos
- ✅ **Secrets**: Gerenciamento integrado
- ✅ **Matrix builds**: Testes paralelos

**Consequências**:
- ➕ Vendor lock-in GitHub
- ➕ Limitações de runners (mitigado com self-hosted)
- ➖ Debugging local limitado

**Alternativas Consideradas**:
- Jenkins: Gerenciamento manual
- GitLab CI: Migração de plataforma
- AWS CodePipeline: Menos flexível

---

## ADR-018: Blue-Green Deployment Strategy

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de deploy sem downtime

**Decisão**: Implementar Blue-Green Deployment

**Justificativa**:
- ✅ **Zero Downtime**: Troca instantânea
- ✅ **Rollback**: Imediato
- ✅ **Testing**: Ambiente green antes de switch
- ✅ **ECS**: Suporte nativo

**Consequências**:
- ➕ Custo duplicado durante deploy
- ➕ Database migrations complexas
- ➖ Necessidade de compatibilidade entre versões

**Alternativas Consideradas**:
- Rolling deployment: Downtime parcial
- Canary: Mais complexo
- Recreate: Downtime

---

## ADR-019: TypeORM como ORM

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de ORM para PostgreSQL

**Decisão**: Utilizar TypeORM

**Justificativa**:
- ✅ **TypeScript**: Type-safe
- ✅ **NestJS**: Integração nativa
- ✅ **Migrations**: Automáticas
- ✅ **Repositories**: Pattern bem definido
- ✅ **Query Builder**: Flexível
- ✅ **Decorators**: Código limpo

**Consequências**:
- ➕ Performance inferior a queries raw
- ➕ N+1 queries (mitigado com eager loading)
- ➖ Curva de aprendizado

**Alternativas Consideradas**:
- Prisma: Menos maduro
- Sequelize: Menos type-safe
- Knex: Mais verboso

---

## ADR-020: Jest para Testes

**Status**: Aceito  
**Data**: 2025
**Contexto**: Necessidade de framework de testes

**Decisão**: Utilizar Jest

**Justificativa**:
- ✅ **NestJS**: Integração nativa
- ✅ **Mocking**: Fácil e poderoso
- ✅ **Coverage**: Built-in
- ✅ **Snapshot**: Testing de componentes
- ✅ **Performance**: Testes paralelos
- ✅ **Comunidade**: Grande e ativa

**Consequências**:
- ➕ Configuração inicial complexa
- ➖ Testes E2E mais lentos

**Alternativas Consideradas**:
- Mocha + Chai: Mais verboso
- Vitest: Menos maduro
- AVA: Menos features

---

## Resumo de Decisões

| ADR | Decisão | Status |
|-----|---------|--------|
| 001 | Microservices Architecture | ✅ Aceito |
| 002 | Node.js + NestJS | ✅ Aceito |
| 003 | AWS Cloud | ✅ Aceito |
| 004 | ECS Fargate | ✅ Aceito |
| 005 | Event-Driven + EventBridge | ✅ Aceito |
| 006 | PostgreSQL RDS | ✅ Aceito |
| 007 | DocumentDB Event Store | ✅ Aceito |
| 008 | CQRS | ✅ Aceito |
| 009 | ElastiCache Redis | ✅ Aceito |
| 010 | Datadog | ✅ Aceito |
| 011 | Stone + Getnet | ✅ Aceito |
| 012 | Saga Pattern | ✅ Aceito |
| 013 | API Gateway | ✅ Aceito |
| 014 | Secrets Manager | ✅ Aceito |
| 015 | Multi-Tenancy Lógico | ✅ Aceito |
| 016 | Terraform | ✅ Aceito |
| 017 | GitHub Actions | ✅ Aceito |
| 018 | Blue-Green Deployment | ✅ Aceito |
| 019 | TypeORM | ✅ Aceito |
| 020 | Jest | ✅ Aceito |

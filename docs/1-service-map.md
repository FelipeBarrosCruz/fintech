# Documentação: Mapeamento de Serviços da Plataforma de Pagamentos

## 1. Visão Geral

Este documento apresenta o mapeamento completo dos microserviços que compõem a arquitetura da plataforma de pagamentos. Cada serviço é projetado seguindo os princípios de Domain-Driven Design (DDD), com responsabilidades bem definidas e baixo acoplamento.

## 2. Arquitetura de Microserviços

### 2.1 Princípios Arquiteturais
- **Single Responsibility**: Cada serviço possui uma responsabilidade única e bem definida
- **Loose Coupling**: Serviços são independentes e se comunicam via APIs e eventos
- **High Cohesion**: Funcionalidades relacionadas estão agrupadas no mesmo serviço
- **Autonomous**: Cada serviço pode ser desenvolvido, deployado e escalado independentemente
- **Domain-Driven**: Serviços são organizados por domínios de negócio

### 2.2 Padrões de Comunicação
- **Síncrona**: REST APIs via API Gateway para operações em tempo real
- **Assíncrona**: Event-driven via EventBridge/SNS/SQS para operações desacopladas
- **Híbrida**: Combinação de ambos conforme necessidade do caso de uso

## 3. Catálogo de Serviços

A plataforma é composta pelos seguintes microserviços:

1. **User Service** - Gerenciamento de usuários e perfis
2. **Payments Service** - Orquestração de pagamentos
3. **Store Service** - Roteamento inteligente de transações
4. **Getnet Service** - Integração com gateway Getnet
5. **Notification Service** - Envio de notificações multi-canal
6. **Anti-Fraud Service** - Orquestração de análise de fraude
7. **Anti-Fraud-Clearsale Service** - Integração com Clearsale
8. **Anti-Fraud-Konduto Service** - Integração com Konduto
9. **Ledger Service** - Contabilidade e livro-razão


### 3.1 User Service (Serviço de Usuários)

#### 3.1.1 Responsabilidades
- Gerenciamento completo do ciclo de vida de usuários
- Cadastro e atualização de perfis (clientes e lojistas)
- Validação de dados cadastrais
- Integração com serviços de KYC (Know Your Customer)
- Gerenciamento de preferências e configurações
- Controle de status de conta (ativo, suspenso, bloqueado)

#### 3.1.2 Domínio
**Bounded Context**: Gestão de Identidade e Perfis

**Entidades Principais:**
- User (Usuário)
- Profile (Perfil)
- Address (Endereço)
- Document (Documentos)
- Preferences (Preferências)

#### 3.1.3 APIs Principais
```
POST   /api/v1/users                    - Criar novo usuário
GET    /api/v1/users/{id}               - Buscar usuário por ID
PUT    /api/v1/users/{id}               - Atualizar dados do usuário
DELETE /api/v1/users/{id}               - Desativar usuário
GET    /api/v1/users/{id}/profile       - Obter perfil completo
PUT    /api/v1/users/{id}/profile       - Atualizar perfil
POST   /api/v1/users/{id}/verify        - Iniciar verificação KYC
GET    /api/v1/users/{id}/status        - Consultar status da conta
```

#### 3.1.4 Eventos Publicados
- `user.created` - Usuário criado
- `user.updated` - Dados atualizados
- `user.verified` - KYC aprovado
- `user.suspended` - Conta suspensa
- `user.deleted` - Conta removida

#### 3.1.5 Eventos Consumidos
- `payment.failed.fraud` - Suspender usuário por fraude
- `kyc.completed` - Atualizar status de verificação

#### 3.1.6 Dependências
- AWS Cognito (autenticação)
- RDS PostgreSQL (dados transacionais)
- DocumentDB (histórico de alterações)
- S3 (armazenamento de documentos)

---

### 3.2 Payments Service (Serviço de Pagamentos)

#### 3.2.1 Responsabilidades
- Orquestração de pagamentos
- Validação de transações
- Gerenciamento de estado de pagamentos
- Coordenação com gateways externos
- Processamento de callbacks
- Gestão de retentativas e compensações
- Implementação de idempotência

#### 3.2.2 Domínio
**Bounded Context**: Processamento de Pagamentos

**Entidades Principais:**
- Payment (Pagamento)
- PaymentMethod (Método de Pagamento)
- Transaction (Transação)
- PaymentStatus (Status)
- Refund (Reembolso)

#### 3.2.3 APIs Principais
```
POST   /api/v1/payments                 - Criar novo pagamento
GET    /api/v1/payments/{id}            - Consultar pagamento
PUT    /api/v1/payments/{id}/cancel     - Cancelar pagamento
POST   /api/v1/payments/{id}/refund     - Processar reembolso
GET    /api/v1/payments/user/{userId}   - Listar pagamentos do usuário
POST   /api/v1/payments/batch           - Processar pagamentos em lote
GET    /api/v1/payments/{id}/status     - Consultar status
POST   /api/v1/payments/webhook         - Receber callbacks
```

#### 3.2.4 Eventos Publicados
- `payment.initiated` - Pagamento iniciado
- `payment.processing` - Em processamento
- `payment.completed` - Pagamento concluído
- `payment.failed` - Pagamento falhou
- `payment.cancelled` - Pagamento cancelado
- `payment.refunded` - Reembolso processado

#### 3.2.5 Eventos Consumidos
- `user.verified` - Liberar limites de pagamento
- `gateway.response` - Processar resposta do gateway
- `ledger.confirmed` - Confirmar lançamento contábil

#### 3.2.6 Dependências
- Store Service (roteamento de gateway)
- Ledger Service (registro contábil)
- Notification Service (alertas)
- RDS PostgreSQL (transações)
- Redis (cache de status)
- SQS (fila de processamento)

#### 3.2.7 Padrões Implementados
- **Saga Pattern**: Orquestração de transações distribuídas
- **Idempotency**: Prevenção de duplicação
- **Circuit Breaker**: Proteção contra falhas em cascata
- **Retry with Exponential Backoff**: Retentativas inteligentes
- **Outbox Pattern**: Garantia de publicação de eventos

---

### 3.3 Store Service (Serviço de Roteamento)

#### 3.3.1 Responsabilidades
- Roteamento inteligente para gateways de pagamento
- Seleção de gateway baseada em regras de negócio
- Balanceamento de carga entre gateways
- Fallback automático em caso de indisponibilidade
- Gestão de configurações de gateways
- Monitoramento de saúde dos gateways

#### 3.3.2 Domínio
**Bounded Context**: Roteamento e Orquestração de Gateways

**Entidades Principais:**
- Gateway (Gateway de Pagamento)
- RoutingRule (Regra de Roteamento)
- GatewayHealth (Saúde do Gateway)
- RoutingStrategy (Estratégia)

#### 3.3.3 APIs Principais
```
POST   /api/v1/routing/select           - Selecionar gateway
GET    /api/v1/routing/gateways         - Listar gateways disponíveis
GET    /api/v1/routing/gateways/{id}/health - Status do gateway
PUT    /api/v1/routing/rules            - Atualizar regras
GET    /api/v1/routing/rules            - Consultar regras
POST   /api/v1/routing/test             - Testar roteamento
```

#### 3.3.4 Regras de Roteamento
**Critérios de Seleção:**
- Tipo de transação (crédito, débito, PIX)
- Valor da transação
- Bandeira do cartão
- Disponibilidade do gateway
- Taxa de sucesso histórica
- Custo de processamento
- Região geográfica
- Horário da transação

**Estratégias:**
- **Round Robin**: Distribuição uniforme
- **Weighted**: Baseado em pesos configurados
- **Cost-Based**: Menor custo
- **Performance-Based**: Melhor taxa de sucesso
- **Failover**: Gateway secundário automático

#### 3.3.5 Eventos Publicados
- `gateway.selected` - Gateway selecionado
- `gateway.unavailable` - Gateway indisponível
- `gateway.failover` - Failover executado
- `routing.rule.updated` - Regra atualizada

#### 3.3.6 Eventos Consumidos
- `gateway.health.changed` - Atualizar status
- `payment.failed` - Ajustar roteamento

#### 3.3.7 Dependências
- Getnet Service
- Stone Service (futuro)
- Redis (cache de regras)
- DocumentDB (logs de roteamento)

---

### 3.4 Getnet Service (Serviço de Integração Getnet)

#### 3.4.1 Responsabilidades
- Integração específica com gateway Getnet
- Tradução de protocolos (interno ↔ Getnet)
- Gerenciamento de credenciais e autenticação
- Implementação de retry e circuit breaker
- Armazenamento de requests/responses para auditoria
- Tratamento de erros específicos do gateway
- Anonimização de dados sensíveis

#### 3.4.2 Domínio
**Bounded Context**: Integração com Gateway Externo (Getnet)

**Entidades Principais:**
- GetnetTransaction (Transação Getnet)
- GetnetRequest (Requisição)
- GetnetResponse (Resposta)
- GetnetCredential (Credenciais)

#### 3.4.3 APIs Principais
```
POST   /api/v1/getnet/authorize         - Autorizar pagamento
POST   /api/v1/getnet/capture           - Capturar pagamento
POST   /api/v1/getnet/cancel            - Cancelar transação
POST   /api/v1/getnet/refund            - Processar estorno
GET    /api/v1/getnet/transaction/{id}  - Consultar transação
POST   /api/v1/getnet/webhook           - Receber notificações
GET    /api/v1/getnet/health            - Health check
```

#### 3.4.4 Operações Getnet
**Fluxo de Autorização:**
1. Receber requisição do Payments Service
2. Validar dados obrigatórios
3. Transformar para formato Getnet
4. Enviar para API Getnet
5. Processar resposta
6. Armazenar raw request/response
7. Publicar evento de resultado

**Tratamento de Erros:**
- Timeout: Retry com exponential backoff
- 5xx: Circuit breaker + fallback
- 4xx: Retornar erro ao cliente
- Network: Dead Letter Queue (DLQ)

#### 3.4.5 Eventos Publicados
- `getnet.authorized` - Autorização aprovada
- `getnet.denied` - Autorização negada
- `getnet.captured` - Captura confirmada
- `getnet.error` - Erro no processamento
- `getnet.timeout` - Timeout na comunicação

#### 3.4.6 Eventos Consumidos
- `payment.initiated` - Processar pagamento
- `payment.cancel.requested` - Cancelar no gateway

#### 3.4.7 Dependências
- Getnet API (externa)
- DocumentDB (auditoria de requests/responses)
- SQS + DLQ (retry e falhas)
- AWS Secrets Manager (credenciais)
- CloudWatch (logs anonimizados)

#### 3.4.8 Segurança e Compliance
- **Anonimização**: PAN masking, PII redaction
- **Criptografia**: TLS 1.3 para comunicação
- **Auditoria**: 100% de requests/responses armazenados
- **Compliance**: PCI-DSS, LGPD

---

### 3.5 Notification Service (Serviço de Notificações)

#### 3.5.1 Responsabilidades
- Envio de notificações multi-canal
- Gerenciamento de templates
- Controle de preferências de notificação
- Retry de envios falhos
- Tracking de entregas
- Rate limiting
- Agendamento de notificações

#### 3.5.2 Domínio
**Bounded Context**: Comunicação com Usuários

**Entidades Principais:**
- Notification (Notificação)
- Template (Template)
- Channel (Canal)
- DeliveryStatus (Status de Entrega)
- UserPreference (Preferências)

#### 3.5.3 APIs Principais
```
POST   /api/v1/notifications             - Enviar notificação
POST   /api/v1/notifications/batch       - Envio em lote
GET    /api/v1/notifications/{id}        - Consultar notificação
GET    /api/v1/notifications/user/{id}   - Histórico do usuário
PUT    /api/v1/notifications/preferences - Atualizar preferências
GET    /api/v1/notifications/templates   - Listar templates
POST   /api/v1/notifications/schedule    - Agendar notificação
```

#### 3.5.4 Canais Suportados
- **Email**: Via AWS SES
- **Push**: Via SNS + Firebase/APNs
- **SMS**: Via SNS (opcional)
- **Webhook**: Para integrações externas
- **In-App**: Notificações na aplicação

#### 3.5.5 Tipos de Notificação
**Transacionais:**
- Confirmação de pagamento
- Falha em transação
- Recebimento de transferência
- Reembolso processado

**Informativos:**
- Extrato mensal
- Lembretes de pagamento
- Atualizações de sistema

**Segurança:**
- Login de novo dispositivo
- Alteração de senha
- Tentativa de fraude
- Bloqueio de conta

#### 3.5.6 Eventos Publicados
- `notification.sent` - Notificação enviada
- `notification.delivered` - Entrega confirmada
- `notification.failed` - Falha no envio
- `notification.opened` - Notificação aberta

#### 3.5.7 Eventos Consumidos
- `payment.completed` - Notificar conclusão
- `payment.failed` - Notificar falha
- `user.created` - Email de boas-vindas
- `transfer.received` - Notificar recebimento
- `security.alert` - Alerta de segurança

#### 3.5.8 Dependências
- AWS SES (email)
- AWS SNS (push/SMS)
- RDS PostgreSQL (histórico)
- Redis (rate limiting)
- S3 (templates)

---

### 3.6 Anti-Fraud Service (Serviço de Antifraude)

#### 3.6.1 Responsabilidades
- Orquestração de análise de fraude
- Agregação de scores de múltiplos provedores
- Decisão final sobre transações suspeitas
- Gerenciamento de regras de negócio antifraude
- Análise de padrões comportamentais
- Blacklist e whitelist de usuários
- Machine Learning para detecção de anomalias
- Gestão de políticas de risco

#### 3.6.2 Domínio
**Bounded Context**: Prevenção e Detecção de Fraudes

**Entidades Principais:**
- FraudAnalysis (Análise de Fraude)
- FraudScore (Score de Fraude)
- RiskPolicy (Política de Risco)
- BlacklistEntry (Entrada de Blacklist)
- FraudPattern (Padrão de Fraude)
- UserBehavior (Comportamento do Usuário)

#### 3.6.3 APIs Principais
```
POST   /api/v1/fraud/analyze            - Analisar transação
GET    /api/v1/fraud/analysis/{id}      - Consultar análise
POST   /api/v1/fraud/blacklist          - Adicionar à blacklist
DELETE /api/v1/fraud/blacklist/{id}     - Remover da blacklist
GET    /api/v1/fraud/blacklist          - Listar blacklist
POST   /api/v1/fraud/whitelist          - Adicionar à whitelist
GET    /api/v1/fraud/policies           - Listar políticas de risco
PUT    /api/v1/fraud/policies/{id}      - Atualizar política
GET    /api/v1/fraud/stats              - Estatísticas de fraude
```

#### 3.6.4 Fluxo de Análise
**Processo de Análise:**
1. Receber requisição de análise (payment.initiated)
2. Verificar blacklist/whitelist
3. Aplicar regras de negócio (valor, frequência, localização)
4. Enviar para provedores externos (Clearsale, Konduto)
5. Agregar scores dos provedores
6. Calcular score final ponderado
7. Aplicar política de risco
8. Tomar decisão (approve, review, deny)
9. Publicar resultado

**Decisões:**
- **Approve**: Score < 30 (baixo risco)
- **Review**: Score 30-70 (risco médio - análise manual)
- **Deny**: Score > 70 (alto risco)

#### 3.6.5 Regras de Negócio
```yaml
Business_Rules:
  Automatic_Deny:
    - Usuário na blacklist
    - Múltiplas transações em curto período
    - Valor acima do limite sem histórico
    - Localização suspeita (VPN, proxy)
    - Device fingerprint desconhecido
  
  Automatic_Approve:
    - Usuário na whitelist
    - Histórico positivo > 6 meses
    - Score < 20 em todos os provedores
    - Padrão comportamental normal
  
  Manual_Review:
    - Primeira transação > R$ 500
    - Score divergente entre provedores
    - Mudança de padrão comportamental
    - Transação internacional
```

#### 3.6.6 Eventos Publicados
- `fraud.analysis.completed` - Análise concluída
- `fraud.approved` - Transação aprovada
- `fraud.denied` - Transação negada
- `fraud.review.required` - Revisão manual necessária
- `fraud.blacklist.added` - Usuário adicionado à blacklist
- `fraud.pattern.detected` - Padrão de fraude detectado

#### 3.6.7 Eventos Consumidos
- `payment.initiated` - Analisar pagamento
- `payment.completed` - Atualizar histórico positivo
- `payment.chargeback` - Adicionar à blacklist
- `user.created` - Criar perfil de risco

#### 3.6.8 Dependências
- Anti-Fraud-Clearsale Service (análise externa)
- Anti-Fraud-Konduto Service (análise externa)
- RDS PostgreSQL (regras e histórico)
- Redis (cache de blacklist/whitelist)
- DocumentDB (logs de análises)
- ML Model (detecção de anomalias)

---

### 3.7 Anti-Fraud-Clearsale Service (Integração Clearsale)

#### 3.7.1 Responsabilidades
- Integração específica com API Clearsale
- Tradução de protocolos (interno ↔ Clearsale)
- Gerenciamento de credenciais Clearsale
- Implementação de retry e circuit breaker
- Armazenamento de requests/responses para auditoria
- Tratamento de erros específicos da Clearsale
- Normalização de scores e respostas

#### 3.7.2 Domínio
**Bounded Context**: Integração com Provedor Antifraude (Clearsale)

**Entidades Principais:**
- ClearsaleAnalysis (Análise Clearsale)
- ClearsaleRequest (Requisição)
- ClearsaleResponse (Resposta)
- ClearsaleCredential (Credenciais)
- ClearsaleScore (Score)

#### 3.7.3 APIs Principais
```
POST   /api/v1/clearsale/analyze        - Enviar para análise
GET    /api/v1/clearsale/analysis/{id}  - Consultar análise
POST   /api/v1/clearsale/webhook        - Receber callback
GET    /api/v1/clearsale/health         - Health check
GET    /api/v1/clearsale/status         - Status da integração
```

#### 3.7.4 Operações Clearsale
**Fluxo de Análise:**
1. Receber requisição do Anti-Fraud Service
2. Validar dados obrigatórios
3. Enriquecer com dados adicionais (IP, device)
4. Transformar para formato Clearsale
5. Enviar para API Clearsale
6. Processar resposta assíncrona
7. Normalizar score (0-100)
8. Armazenar raw request/response
9. Publicar evento de resultado

**Mapeamento de Score:**
- Clearsale Aprovado → Score 10
- Clearsale Análise Manual → Score 50
- Clearsale Reprovado → Score 90

#### 3.7.5 Eventos Publicados
- `clearsale.analysis.completed` - Análise concluída
- `clearsale.approved` - Aprovado pela Clearsale
- `clearsale.denied` - Negado pela Clearsale
- `clearsale.review` - Requer análise manual
- `clearsale.error` - Erro na integração
- `clearsale.timeout` - Timeout na comunicação

#### 3.7.6 Eventos Consumidos
- `fraud.analysis.requested` - Iniciar análise Clearsale
- `payment.chargeback` - Reportar chargeback

#### 3.7.7 Dependências
- Clearsale API (externa)
- DocumentDB (auditoria de requests/responses)
- SQS + DLQ (retry e falhas)
- AWS Secrets Manager (credenciais)
- CloudWatch (logs)

#### 3.7.8 Tratamento de Erros
- Timeout (30s): Retry 3x com backoff
- 5xx: Circuit breaker + fallback (score neutro 50)
- 4xx: Retornar erro ao Anti-Fraud Service
- Network: Dead Letter Queue

---

### 3.8 Anti-Fraud-Konduto Service (Integração Konduto)

#### 3.8.1 Responsabilidades
- Integração específica com API Konduto
- Tradução de protocolos (interno ↔ Konduto)
- Gerenciamento de credenciais Konduto
- Implementação de retry e circuit breaker
- Armazenamento de requests/responses para auditoria
- Tratamento de erros específicos da Konduto
- Normalização de scores e respostas
- Envio de feedback de transações

#### 3.8.2 Domínio
**Bounded Context**: Integração com Provedor Antifraude (Konduto)

**Entidades Principais:**
- KondutoAnalysis (Análise Konduto)
- KondutoRequest (Requisição)
- KondutoResponse (Resposta)
- KondutoCredential (Credenciais)
- KondutoScore (Score)
- KondutoFeedback (Feedback)

#### 3.8.3 APIs Principais
```
POST   /api/v1/konduto/analyze          - Enviar para análise
GET    /api/v1/konduto/analysis/{id}    - Consultar análise
POST   /api/v1/konduto/feedback         - Enviar feedback
POST   /api/v1/konduto/webhook          - Receber callback
GET    /api/v1/konduto/health           - Health check
GET    /api/v1/konduto/status           - Status da integração
```

#### 3.8.4 Operações Konduto
**Fluxo de Análise:**
1. Receber requisição do Anti-Fraud Service
2. Validar dados obrigatórios
3. Enriquecer com dados de navegação
4. Transformar para formato Konduto
5. Enviar para API Konduto
6. Processar resposta em tempo real
7. Normalizar score (0-100)
8. Armazenar raw request/response
9. Publicar evento de resultado

**Mapeamento de Recomendação:**
- Konduto "approve" → Score 15
- Konduto "review" → Score 50
- Konduto "decline" → Score 85

**Feedback Loop:**
- Enviar resultado final para Konduto
- Reportar chargebacks
- Reportar falsos positivos
- Melhorar modelo de ML da Konduto

#### 3.8.5 Eventos Publicados
- `konduto.analysis.completed` - Análise concluída
- `konduto.approved` - Aprovado pela Konduto
- `konduto.denied` - Negado pela Konduto
- `konduto.review` - Requer análise manual
- `konduto.error` - Erro na integração
- `konduto.timeout` - Timeout na comunicação
- `konduto.feedback.sent` - Feedback enviado

#### 3.8.6 Eventos Consumidos
- `fraud.analysis.requested` - Iniciar análise Konduto
- `payment.completed` - Enviar feedback positivo
- `payment.chargeback` - Enviar feedback negativo
- `fraud.false.positive` - Reportar falso positivo

#### 3.8.7 Dependências
- Konduto API (externa)
- DocumentDB (auditoria de requests/responses)
- SQS + DLQ (retry e falhas)
- AWS Secrets Manager (credenciais)
- CloudWatch (logs)
- Redis (cache de análises recentes)

#### 3.8.8 Tratamento de Erros
- Timeout (20s): Retry 3x com backoff
- 5xx: Circuit breaker + fallback (score neutro 50)
- 4xx: Retornar erro ao Anti-Fraud Service
- Network: Dead Letter Queue

---

### 3.9 Ledger Service (Serviço de Contabilidade)


#### 3.6.1 Responsabilidades
- Registro contábil de todas as transações
- Manutenção de double-entry bookkeeping
- Geração de extratos e relatórios
- Conciliação financeira
- Auditoria de movimentações
- Cálculo de saldos
- Garantia de consistência eventual

#### 3.6.2 Domínio
**Bounded Context**: Contabilidade e Livro-Razão

**Entidades Principais:**
- LedgerEntry (Lançamento)
- Account (Conta)
- Balance (Saldo)
- Transaction (Transação)
- Statement (Extrato)
- Reconciliation (Conciliação)

#### 3.6.3 APIs Principais
```
POST   /api/v1/ledger/entries           - Criar lançamento
GET    /api/v1/ledger/entries/{id}      - Consultar lançamento
GET    /api/v1/ledger/accounts/{id}/balance - Consultar saldo
GET    /api/v1/ledger/accounts/{id}/statement - Gerar extrato
POST   /api/v1/ledger/reconcile         - Executar conciliação
GET    /api/v1/ledger/reports           - Gerar relatórios
GET    /api/v1/ledger/audit/{id}        - Trilha de auditoria
```

#### 3.6.4 Princípios Contábeis
**Double-Entry Bookkeeping:**
- Todo débito tem um crédito correspondente
- Soma de débitos = Soma de créditos
- Imutabilidade de lançamentos
- Correções via lançamentos de estorno

**Tipos de Conta:**
- Asset (Ativo): Contas de usuários
- Liability (Passivo): Obrigações
- Revenue (Receita): Taxas cobradas
- Expense (Despesa): Custos operacionais

#### 3.6.5 Eventos Publicados
- `ledger.entry.created` - Lançamento criado
- `ledger.balance.updated` - Saldo atualizado
- `ledger.reconciled` - Conciliação concluída
- `ledger.inconsistency` - Inconsistência detectada

#### 3.6.6 Eventos Consumidos
- `payment.completed` - Registrar pagamento
- `transfer.completed` - Registrar transferência
- `payment.refunded` - Registrar estorno
- `fee.charged` - Registrar taxa

#### 3.6.7 Dependências
- RDS PostgreSQL (ledger principal)
- DocumentDB (eventos e auditoria)
- Redis (cache de saldos)
- S3 (relatórios e extratos)

#### 3.6.8 Garantias
- **ACID**: Transações atômicas
- **Imutabilidade**: Lançamentos não podem ser alterados
- **Auditabilidade**: 100% rastreável
- **Consistência Eventual**: Sincronização garantida

---

## 4. Matriz de Comunicação entre Serviços

### 4.1 Comunicação Síncrona (REST)
```
User Service → Notification Service (envio de email)
Payments Service → Store Service (seleção de gateway)
Payments Service → User Service (validação de usuário)
Store Service → Getnet Service (processamento)
```

### 4.2 Comunicação Assíncrona (Eventos)
```
Payments Service → Anti-Fraud Service (análise de fraude)
Payments Service → Ledger Service (registro contábil)
Payments Service → Notification Service (alertas)
User Service → Payments Service (atualização de limites)
Getnet Service → Payments Service (callback de gateway)
Ledger Service → Notification Service (extratos)
Anti-Fraud Service → Anti-Fraud-Clearsale Service (análise externa)
Anti-Fraud Service → Anti-Fraud-Konduto Service (análise externa)
Anti-Fraud-Clearsale Service → Anti-Fraud Service (resultado da análise)
Anti-Fraud-Konduto Service → Anti-Fraud Service (resultado da análise)
Anti-Fraud Service → Payments Service (decisão de fraude)
Anti-Fraud Service → User Service (blacklist/whitelist)
```

## 5. Estratégia de Dados

### 5.1 Database per Service
Cada serviço possui seu próprio banco de dados, garantindo:
- Isolamento de dados
- Escalabilidade independente
- Tecnologia adequada ao caso de uso
- Redução de acoplamento

### 5.2 Distribuição de Dados
**RDS PostgreSQL:**
- User Service (dados cadastrais)
- Payments Service (transações)
- Ledger Service (lançamentos contábeis)
- Anti-Fraud Service (regras, blacklist, whitelist)

**DocumentDB:**
- Getnet Service (auditoria de requests)
- Ledger Service (eventos)
- Store Service (logs de roteamento)
- Anti-Fraud Service (logs de análises)
- Anti-Fraud-Clearsale Service (auditoria de requests/responses)
- Anti-Fraud-Konduto Service (auditoria de requests/responses)

**Redis:**
- Payments Service (cache de status)
- Store Service (regras de roteamento)
- Notification Service (rate limiting)
- Ledger Service (cache de saldos)
- Anti-Fraud Service (cache de blacklist/whitelist)
- Anti-Fraud-Konduto Service (cache de análises recentes)


## 6. Escalabilidade e Performance

### 6.1 Estratégias por Serviço
**User Service**: Escala horizontal moderada (read-heavy)
**Payments Service**: Escala horizontal agressiva (write-heavy)
**Store Service**: Escala horizontal moderada (stateless)
**Getnet Service**: Escala horizontal + circuit breaker
**Notification Service**: Escala horizontal + queue-based
**Ledger Service**: Escala vertical + read replicas
**Anti-Fraud Service**: Escala horizontal moderada (análise em tempo real)
**Anti-Fraud-Clearsale Service**: Escala horizontal + circuit breaker
**Anti-Fraud-Konduto Service**: Escala horizontal + circuit breaker


### 6.2 Métricas de Performance
- Latência P95 < 200ms (operações síncronas)
- Throughput: 10.000+ TPS (Payments Service)
- Disponibilidade: 99.95% por serviço
- Error rate < 0.1%

## 7. Resiliência e Fault Tolerance

### 7.1 Padrões Implementados
- **Circuit Breaker**: Todos os serviços
- **Retry with Backoff**: Integrações externas
- **Timeout**: Todas as chamadas HTTP
- **Bulkhead**: Isolamento de recursos
- **Fallback**: Gateways alternativos

### 7.2 Health Checks
Cada serviço expõe:
- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe
- `/health/startup` - Startup probe

## 8. Segurança

### 8.1 Autenticação e Autorização
- API Gateway + AWS Cognito
- JWT tokens para comunicação inter-serviços
- mTLS para comunicação sensível
- IAM roles para acesso a recursos AWS

### 8.2 Proteção de Dados
- Criptografia em trânsito (TLS 1.3)
- Criptografia em repouso (AWS KMS)
- Anonimização de logs
- Tokenização de dados sensíveis

## 9. Observabilidade

### 9.1 Logging
- Logs estruturados (JSON)
- Correlation ID em todas as requisições
- Centralização via CloudWatch
- Anonimização automática

### 9.2 Métricas
- Métricas de negócio (transações, valores)
- Métricas técnicas (latência, erros)
- Métricas de infraestrutura (CPU, memória)
- Dashboards no Datadog

### 9.3 Tracing
- Distributed tracing via OpenTelemetry
- Rastreamento end-to-end de transações
- Visualização de dependências
- Análise de bottlenecks

## 10. Evolução Futura

### 10.1 Novos Serviços Planejados
- **Stone Service**: Integração com gateway Stone
- **Analytics Service**: Business intelligence

### 10.2 Melhorias Planejadas
- Migração para EKS (Kubernetes)
- Implementação de Service Mesh (Istio)
- Adoção de Kafka para event streaming
- Infraestrutura PCI para tokenização

## 11. Referências

- Documento de Cenários: `0-scenarios.md`
- Documento de Stack Tecnológica: `2-tech-stack.md`
- Documento de Estratégia de Integração: `3-integration-stratefy.md`
- Documento de Segurança: `4-security.md`
- Documento de Observabilidade: `5-observability.md`
